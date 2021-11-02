//! Code to handle incoming cells on a circuit
//!
//! TODO: I don't have so much confidence in the close-and-cleanup
//! behavior here, or in the error handling behavior.
//!
//! TODO: perhaps this should share code with channel::reactor; perhaps
//! it should just not exist.

use super::streammap::{ShouldSendEnd, StreamEnt};
use crate::circuit::celltypes::ClientCircChanMsg;
use crate::circuit::unique_id::UniqId;
use crate::circuit::{sendme, streammap};
use crate::crypto::cell::{HopNum, InboundClientCrypt, InboundClientLayer};
use crate::util::err::ReactorError;
use crate::{Error, Result};
use tor_cell::chancell::msg::Relay;
use tor_cell::relaycell::msg::{End, RelayMsg, Sendme};
use tor_cell::relaycell::{RelayCell, StreamId};

use futures::channel::{mpsc, oneshot};
use futures::select_biased;
use futures::sink::SinkExt;
use futures::stream::{self, StreamExt};

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use tracing::{debug, trace};

/// A message telling the reactor to do something.
pub(super) enum CtrlMsg {
    /// Shut down the reactor.
    Shutdown,
    /// Register a new one-shot receiver that can send a CtrlMsg to the
    /// reactor.
    /// Tell the reactor that a given stream has gone away.
    CloseStream(HopNum, StreamId, sendme::StreamRecvWindow),
    /// Ask the reactor for a new stream ID, and allocate a circuit for it.
    AddStream(
        HopNum,
        mpsc::Sender<RelayMsg>,
        sendme::StreamSendWindow,
        oneshot::Sender<Result<StreamId>>,
    ),
    /// Tell the reactor to add a new hop to its view of the circuit, and
    /// then tell us when it has done so.
    AddHop(
        InboundHop,
        Box<dyn InboundClientLayer + Send>,
        oneshot::Sender<()>,
    ),
}

impl std::fmt::Debug for CtrlMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CtrlMsg::*;
        match self {
            Shutdown => write!(f, "Shutdown"),
            CloseStream(h, s, _) => write!(f, "CloseStream({:?}, {:?}, _)", h, s),
            AddStream(h, _, _, _) => write!(f, "AddStream({:?}, _, _, _)", h),
            AddHop(_, _, _) => write!(f, "AddHop(_, _, _)"),
        }
    }
}
/// Represents the reactor's view of a single hop.
pub(super) struct InboundHop {
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    map: streammap::StreamMap,
    /// Window used to say how many cells we can receive.
    recvwindow: sendme::CircRecvWindow,
}

impl InboundHop {
    /// Create a new hop.
    pub(super) fn new() -> Self {
        InboundHop {
            map: streammap::StreamMap::new(),
            recvwindow: sendme::CircRecvWindow::new(1000),
        }
    }
}

/// Object to handle incoming cells and background tasks on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// A stream of oneshot receivers that tell this reactor about things it
    /// needs to handle, like closed streams.
    //
    // The actual type here is quite ugly! Is there a better way?
    //
    // See documentation of CtrlMsg and CtrlResult for info about why
    // we're using this ugly type.
    control: mpsc::UnboundedReceiver<CtrlMsg>,

    /// Input Stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    // TODO: could use a SPSC channel here instead.
    input: stream::Fuse<mpsc::Receiver<ClientCircChanMsg>>,

    /// Reference to the circuit.
    circuit: Weak<super::ClientCirc>,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    ///
    /// We keep this separately from the state for outbound cells, since
    /// it is convenient for the reactor to be able to use this without
    /// locking the circuit.
    crypto_in: InboundClientCrypt,
    /// List of hops state objects used by the reactor
    hops: Vec<InboundHop>,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
}

impl Reactor {
    /// Construct a new Reactor.
    pub(super) fn new(
        circuit: &Arc<super::ClientCirc>,
        control: mpsc::UnboundedReceiver<CtrlMsg>,
        input: mpsc::Receiver<ClientCircChanMsg>,
        unique_id: UniqId,
    ) -> Self {
        Reactor {
            input: input.fuse(),
            control,
            circuit: Arc::downgrade(circuit),
            crypto_in: InboundClientCrypt::new(),
            hops: Vec::new(),
            unique_id,
        }
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub async fn run(mut self) -> Result<()> {
        if let Some(circ) = self.circuit.upgrade() {
            if circ.is_closing() {
                return Err(Error::CircuitClosed);
            }
        } else {
            return Err(Error::CircuitClosed);
        }
        debug!("{}: Running circuit reactor", self.unique_id);
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        debug!("{}: Circuit reactor stopped: {:?}", self.unique_id, result);
        self.propagate_close().await;
        result
    }

    /// Tell the circuit that this reactor has been closed.
    pub(super) async fn propagate_close(self) {
        if let Some(circ) = self.circuit.upgrade() {
            // TODO: should this call terminate?
            circ.closed.store(true, Ordering::SeqCst);
            let mut circ = circ.c.lock().await;
            if let Some((_, sender)) = circ.sendmeta.take() {
                let _ignore_err = sender.send(Err(Error::CircuitClosed));
            }
        }
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    pub(super) async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        // What's next to do?
        let item = select_biased! {
            // Got a control message!
            ctrl = self.control.next() => {
                match ctrl {
                    Some(CtrlMsg::Shutdown) | None => return Err(ReactorError::Shutdown),
                    Some(msg) => self.handle_control(msg).await?,
                }
                return Ok(());
            }
            // we got a message on our channel, or it closed.
            item = self.input.next() => item,
        };
        let item = match item {
            // the channel closed; we're done.
            None => return Err(ReactorError::Shutdown),
            // we got a ChanMsg!
            Some(r) => r,
        };

        let exit = self.handle_cell(item).await?;
        if exit {
            return Err(ReactorError::Shutdown);
        }
        Ok(())
    }

    /// Handle a CtrlMsg other than Shutdown.
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        trace!("{}: reactor received {:?}", self.unique_id, msg);
        match msg {
            CtrlMsg::Shutdown => panic!(), // was handled in reactor loop.
            CtrlMsg::CloseStream(hop, id, recvwindow) => {
                self.close_stream(hop, id, recvwindow).await?
            }
            CtrlMsg::AddStream(hop, sink, window, sender) => {
                let hop = self.hop_mut(hop);
                if let Some(hop) = hop {
                    let r = hop.map.add_ent(sink, window);
                    // XXXX not sure if this is right to ignore
                    let _ignore = sender.send(r);
                }
                // If there was no hop with this index, dropping the sender
                // will cancel the attempt to add the stream.
            }
            CtrlMsg::AddHop(hop, layer, sender) => {
                self.hops.push(hop);
                self.crypto_in.add_layer(layer);
                // XXXX not sure if this is right to ignore
                let _ignore = sender.send(());
            }
        }
        Ok(())
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    async fn close_stream(
        &mut self,
        hopnum: HopNum,
        id: StreamId,
        window: sendme::StreamRecvWindow,
    ) -> Result<()> {
        // Mark the stream as closing.
        let hop = self.hop_mut(hopnum).ok_or_else(|| {
            Error::InternalError("Tried to close a stream on a hop that wasn't there?".into())
        })?;

        let should_send_end = hop.map.terminate(id, window)?;
        trace!(
            "{}: Ending stream {}; should_send_end={:?}",
            self.unique_id,
            id,
            should_send_end
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if should_send_end == ShouldSendEnd::Send {
            let end_cell = RelayCell::new(id, End::new_misc().into());
            if let Some(circ) = self.circuit.upgrade() {
                circ.send_relay_cell(hopnum, false, end_cell).await?;
            } else {
                return Err(Error::CircuitClosed);
            }
        }
        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return true if we should exit.
    async fn handle_cell(&mut self, cell: ClientCircChanMsg) -> Result<bool> {
        use ClientCircChanMsg::*;
        match cell {
            Relay(r) => {
                self.handle_relay_cell(r).await?;
                Ok(false)
            }
            Destroy(_) => {
                self.handle_destroy_cell()?;
                Ok(true)
            }
        }
    }

    /// React to a Relay or RelayEarly cell.
    async fn handle_relay_cell(&mut self, cell: Relay) -> Result<()> {
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(&mut body)?;
        // Make a copy of the authentication tag. TODO: I'd rather not
        // copy it, but I don't see a way around it right now.
        let tag = {
            let mut tag_copy = [0_u8; 20];
            // XXXX This could crash if the tag length changes.  We'll
            // have to refactor it then.
            (&mut tag_copy).copy_from_slice(tag);
            tag_copy
        };
        // Decode the cell.
        let msg = RelayCell::decode(body.into())?;

        let c_t_w = sendme::cell_counts_towards_windows(&msg);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            let hop = self
                .hop_mut(hopnum)
                .ok_or_else(|| Error::CircProto("Sendme from nonexistent hop".into()))?;
            hop.recvwindow.take()?
        } else {
            false
        };
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            let sendme = Sendme::new_tag(tag);
            let cell = RelayCell::new(0.into(), sendme.into());
            if let Some(circ) = self.circuit.upgrade() {
                circ.send_relay_cell(hopnum, false, cell).await?;
            } else {
                return Err(Error::CircuitClosed);
            }
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::InternalError("Trying to send SENDME to nonexistent hop".to_string())
                })?
                .recvwindow
                .put();
        }

        // Break the message apart into its streamID and message.
        let (streamid, msg) = msg.into_streamid_and_msg();

        // If this cell wants/refuses to have a Stream ID, does it
        // have/not have one?
        if !msg.cmd().accepts_streamid_val(streamid) {
            return Err(Error::CircProto(format!(
                "Invalid stream ID {} for relay command {}",
                streamid,
                msg.cmd()
            )));
        }

        // If this has a reasonable streamID value of 0, it's a meta cell,
        // not meant for a particular stream.
        if streamid.is_zero() {
            if let Some(circ) = self.circuit.upgrade() {
                let mut circ = circ.c.lock().await;
                return circ.handle_meta_cell(hopnum, msg).await;
            } else {
                return Err(Error::CircuitClosed);
            }
        }

        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto("Cell from nonexistent hop!".into()))?;
        match hop.map.get_mut(streamid) {
            Some(StreamEnt::Open(s, w, ref mut dropped)) => {
                // The stream for this message exists, and is open.

                if let RelayMsg::Sendme(_) = msg {
                    // We need to handle sendmes here, not in the stream's
                    // recv() method, or else we'd never notice them if the
                    // stream isn't reading.
                    w.put(Some(())).await;
                    return Ok(());
                }

                // Remember whether this was an end cell: if so we should
                // close the stream.
                let is_end_cell = matches!(msg, RelayMsg::End(_));

                // TODO: Add a wrapper type here to reject cells that should
                // never go to a client, like BEGIN.
                let result = s.send(msg).await;
                if result.is_err() && c_t_w {
                    // the other side of the stream has gone away; remember
                    // that we received a cell that we couldn't queue for it.
                    //
                    // Later this value will be recorded in a half-stream.
                    *dropped += 1;
                }
                if is_end_cell {
                    hop.map.end_received(streamid)?;
                }
                Ok(())
            }
            Some(StreamEnt::EndSent(halfstream)) => {
                // We sent an end but maybe the other side hasn't heard.

                if matches!(msg, RelayMsg::End(_)) {
                    hop.map.end_received(streamid)
                } else {
                    halfstream.handle_msg(&msg).await
                }
            }
            _ => {
                // No stream wants this message.
                Err(Error::CircProto(
                    "Cell received on nonexistent stream!?".into(),
                ))
            }
        }
    }

    /// Helper: process a destroy cell.
    #[allow(clippy::unnecessary_wraps)]
    fn handle_destroy_cell(&mut self) -> Result<()> {
        // I think there is nothing more to do here.
        Ok(())
    }

    /// Return the hop corresponding to `hopnum`, if there is one.
    fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut InboundHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }
}

#[cfg(test)]
mod test {}
