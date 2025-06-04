//! Module exposing types for representing circuits in the tunnel reactor.

pub(super) mod create;
pub(super) mod extender;

use crate::channel::{Channel, ChannelSender};
use crate::congestion::sendme;
use crate::congestion::{CongestionControl, CongestionSignals};
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    HopNum, InboundClientCrypt, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody,
};
use crate::crypto::handshake::fast::CreateFastClient;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::memquota::{CircuitAccount, SpecificAccount as _, StreamAccount};
use crate::stream::{AnyCmdChecker, StreamSendFlowControl, StreamStatus};
use crate::tunnel::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use crate::tunnel::circuit::handshake::{BoxedClientLayer, HandshakeRole};
use crate::tunnel::circuit::path;
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::{
    CircParameters, CircuitRxReceiver, MutableState, StreamMpscReceiver, StreamMpscSender,
};
use crate::tunnel::handshake::RelayCryptLayerProtocol;
use crate::tunnel::reactor::MetaCellDisposition;
use crate::tunnel::streammap::{
    self, EndSentStreamEnt, OpenStreamEnt, ShouldSendEnd, StreamEntMut,
};
use crate::util::err::ReactorError;
use crate::util::sometimes_unbounded_sink::SometimesUnboundedSink;
use crate::util::SinkExt as _;
use crate::{ClockSkew, Error, Result};

use tor_async_utils::{SinkTrySend as _, SinkTrySendError as _};
use tor_cell::chancell::msg::{AnyChanMsg, HandshakeType, Relay};
use tor_cell::chancell::{AnyChanCell, ChanCmd, CircId};
use tor_cell::chancell::{BoxedCellBody, ChanMsg};
use tor_cell::relaycell::extend::{CcRequest, CircRequestExt};
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme, SendmeTag, Truncated};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellDecoderResult, RelayCellFormat, RelayCmd,
    StreamId, UnparsedRelayMsg,
};
use tor_error::{internal, Bug};
use tor_linkspec::RelayIds;
use tor_llcrypto::pk;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};

use futures::stream::FuturesUnordered;
use futures::{SinkExt as _, Stream};
use oneshot_fused_workaround as oneshot;
use safelog::sensitive as sv;
use tracing::{debug, trace, warn};

#[cfg(feature = "conflux")]
use super::conflux::ConfluxMsgHandler;
use super::{
    CellHandlers, CircuitHandshake, CloseStreamBehavior, LegId, ReactorResultChannel, SendRelayCell,
};

use std::borrow::Borrow;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, SystemTime};

use create::{Create2Wrap, CreateFastWrap, CreateHandshakeWrap};
use extender::HandshakeAuxDataHandler;

#[cfg(feature = "hs-service")]
use {
    crate::stream::{DataCmdChecker, IncomingStreamRequest},
    tor_cell::relaycell::msg::Begin,
};

#[cfg(feature = "conflux")]
use {
    super::conflux::{ConfluxAction, OooRelayMsg},
    crate::tunnel::reactor::RemoveLegReason,
};

/// Initial value for outbound flow-control window on streams.
pub(super) const SEND_WINDOW_INIT: u16 = 500;
/// Initial value for inbound flow-control window on streams.
pub(crate) const RECV_WINDOW_INIT: u16 = 500;
/// Size of the buffer used between the reactor and a `StreamReader`.
///
/// FIXME(eta): We pick 2× the receive window, which is very conservative (we arguably shouldn't
///             get sent more than the receive window anyway!). We might do due to things that
///             don't count towards the window though.
pub(crate) const STREAM_READER_BUFFER: usize = (2 * RECV_WINDOW_INIT) as usize;

/// Represents the reactor's view of a single hop.
pub(super) struct CircHop {
    /// Reactor unique ID. Used for logging.
    unique_id: UniqId,
    /// Hop number in the path.
    hop_num: HopNum,
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    ///
    /// NOTE: this is behind a mutex because the reactor polls the `StreamMap`s
    /// of all hops concurrently, in a [`FuturesUnordered`]. Without the mutex,
    /// this wouldn't be possible, because it would mean holding multiple
    /// mutable references to `self` (the reactor). Note, however,
    /// that there should never be any contention on this mutex:
    /// we never create more than one [`Circuit::ready_streams_iterator`] stream
    /// at a time, and we never clone/lock the hop's `StreamMap` outside of
    /// [`Circuit::ready_streams_iterator`].
    ///
    // TODO: encapsulate the Vec<CircHop> into a separate CircHops structure,
    // and hide its internals from the Reactor. The CircHops implementation
    // should enforce the invariant described in the note above.
    map: Arc<Mutex<streammap::StreamMap>>,
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    ccontrol: CongestionControl,
    /// Decodes relay cells received from this hop.
    inbound: RelayCellDecoder,
    /// Format to use for relay cells.
    //
    // When we have packed/fragmented cells, this may be replaced by a RelayCellEncoder.
    relay_format: RelayCellFormat,
}

/// A circuit "leg" from a tunnel.
///
/// Regular (non-multipath) circuits have a single leg.
/// Conflux (multipath) circuits have `N` (usually, `N = 2`).
pub(crate) struct Circuit {
    /// The channel this circuit is attached to.
    channel: Arc<Channel>,
    /// Sender object used to actually send cells.
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    pub(super) chan_sender: SometimesUnboundedSink<AnyChanCell, ChannelSender>,
    /// Input stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    ///
    // TODO: could use a SPSC channel here instead.
    pub(super) input: CircuitRxReceiver,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    crypto_in: InboundClientCrypt,
    /// The cryptographic state for this circuit for outbound cells.
    crypto_out: OutboundClientCrypt,
    /// List of hops state objects used by the reactor
    hops: Vec<CircHop>,
    /// Mutable information about this circuit,
    /// shared with the reactor's `ConfluxSet`.
    mutable: Arc<MutableState>,
    /// This circuit's identifier on the upstream channel.
    channel_id: CircId,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// A handler for conflux cells.
    ///
    /// Set once the conflux handshake is initiated by the reactor
    /// using [`Reactor::handle_link_circuits`](super::Reactor::handle_link_circuits).
    #[cfg(feature = "conflux")]
    conflux_handler: Option<ConfluxMsgHandler>,
    /// Memory quota account
    #[allow(dead_code)] // Partly here to keep it alive as long as the circuit
    memquota: CircuitAccount,
}

/// A command to run in response to a circuit event.
///
/// Unlike `RunOnceCmdInner`, doesn't know anything about `LegId`s.
/// The user of the `CircuitCmd`s is supposed to know the `LegId`
/// of the circuit the `CircuitCmd` came from.
///
/// This type gets mapped to a `RunOnceCmdInner` in the circuit reactor.
#[derive(Debug)]
pub(super) enum CircuitCmd {
    /// Send a RELAY cell on the circuit leg this command originates from.
    Send(SendRelayCell),
    /// Handle a SENDME message received on the circuit leg this command originates from.
    HandleSendMe {
        /// The hop number.
        hop: HopNum,
        /// The SENDME message to handle.
        sendme: Sendme,
    },
    /// Close the specified stream on the circuit leg this command originates from.
    CloseStream {
        /// The hop number.
        hop: HopNum,
        /// The ID of the stream to close.
        sid: StreamId,
        /// The stream-closing behavior.
        behav: CloseStreamBehavior,
        /// The reason for closing the stream.
        reason: streammap::TerminateReason,
    },
    /// Remove this circuit from the conflux set.
    ///
    /// Returned by `ConfluxMsgHandler::handle_conflux_msg` for invalid messages
    /// (originating from wrong hop), and for messages that are rejected
    /// by its inner `AbstractMsgHandler`.
    #[cfg(feature = "conflux")]
    ConfluxRemove(RemoveLegReason),
    /// This circuit has completed the conflux handshake,
    /// and wants to send the specified cell.
    ///
    /// Returned by an `AbstractMsgHandler` to signal to the reactor that
    /// the conflux handshake is complete.
    #[cfg(feature = "conflux")]
    ConfluxHandshakeComplete(SendRelayCell),
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
    /// Enqueue an out-of-order cell in the reactor.
    #[cfg(feature = "conflux")]
    Enqueue(OooRelayMsg),
}

/// Return a `CircProto` error for the specified unsupported cell.
///
/// This error will shut down the reactor.
///
/// Note: this is a macro to simplify usage (this way the caller doesn't
/// need to .map() the result to the appropriate type)
macro_rules! unsupported_client_cell {
    ($msg:expr) => {{
        unsupported_client_cell!(@ $msg, "")
    }};

    ($msg:expr, $hopnum:expr) => {{
        let hop: HopNum = $hopnum;
        let hop_display = format!(" from hop {}", hop.display());
        unsupported_client_cell!(@ $msg, hop_display)
    }};

    (@ $msg:expr, $hopnum_display:expr) => {
        Err(crate::Error::CircProto(format!(
            "Unexpected {} cell{} on client circuit",
            $msg.cmd(),
            $hopnum_display,
        )))
    };
}

pub(super) use unsupported_client_cell;

impl Circuit {
    /// Create a new non-multipath circuit.
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        memquota: CircuitAccount,
        mutable: Arc<MutableState>,
    ) -> Self {
        let chan_sender = SometimesUnboundedSink::new(channel.sender());

        let crypto_out = OutboundClientCrypt::new();
        Circuit {
            channel,
            chan_sender,
            input,
            crypto_in: InboundClientCrypt::new(),
            hops: vec![],
            unique_id,
            channel_id,
            crypto_out,
            mutable,
            #[cfg(feature = "conflux")]
            conflux_handler: None,
            memquota,
        }
    }

    /// Return the process-unique identifier of this circuit.
    pub(super) fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Return the shared mutable state of this circuit.
    pub(super) fn mutable(&self) -> &Arc<MutableState> {
        &self.mutable
    }

    /// Install a [`ConfluxMsgHandler`] on this circuit,
    ///
    /// Once this is called, the circuit will be able to handle conflux cells.
    #[cfg(feature = "conflux")]
    pub(super) fn install_conflux_handler(&mut self, conflux_handler: ConfluxMsgHandler) {
        self.conflux_handler = Some(conflux_handler);
    }

    /// Send a LINK cell to the specified hop.
    ///
    /// This must be called *after* a [`ConfluxMsgHandler`] is installed
    /// on the circuit with [`install_conflux_handler`](Self::install_conflux_handler).
    #[cfg(feature = "conflux")]
    pub(super) async fn begin_conflux_link(
        &mut self,
        hop: HopNum,
        cell: AnyRelayMsgOuter,
        runtime: &tor_rtcompat::DynTimeProvider,
    ) -> Result<()> {
        use tor_rtcompat::SleepProvider as _;

        if self.conflux_handler.is_none() {
            return Err(internal!(
                "tried to send LINK cell before installing a ConfluxMsgHandler?!"
            )
            .into());
        }

        let cell = SendRelayCell {
            hop,
            early: false,
            cell,
        };
        self.send_relay_cell(cell).await?;

        let Some(conflux_handler) = self.conflux_handler.as_mut() else {
            return Err(internal!("ConfluxMsgHandler disappeared?!").into());
        };

        Ok(conflux_handler.note_link_sent(runtime.wallclock())?)
    }

    /// Get the wallclock time when the handshake on this circuit is supposed to time out.
    ///
    /// Returns `None` if this handler hasn't started the handshake yet.
    pub(super) fn conflux_hs_timeout(&self) -> Option<SystemTime> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                self.conflux_handler.as_ref().map(|handler| handler.handshake_timeout())?
            } else {
                None
            }
        }
    }

    /// Handle a [`CtrlMsg::AddFakeHop`](super::CtrlMsg::AddFakeHop) message.
    #[cfg(test)]
    pub(super) fn handle_add_fake_hop(
        &mut self,
        format: RelayCellFormat,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        params: &CircParameters,
        done: ReactorResultChannel<()>,
    ) {
        use crate::tunnel::circuit::test::DummyCrypto;

        let dummy_peer_id = tor_linkspec::OwnedChanTarget::builder()
            .ed_identity([4; 32].into())
            .rsa_identity([5; 20].into())
            .build()
            .expect("Could not construct fake hop");

        let fwd = Box::new(DummyCrypto::new(fwd_lasthop));
        let rev = Box::new(DummyCrypto::new(rev_lasthop));
        let binding = None;
        self.add_hop(
            format,
            path::HopDetail::Relay(dummy_peer_id),
            fwd,
            rev,
            binding,
            params,
        )
        .expect("could not add hop to circuit");
        let _ = done.send(Ok(()));
    }

    /// Encode `msg` and encrypt it, returning the resulting cell
    /// and tag that should be expected for an authenticated SENDME sent
    /// in response to that cell.
    fn encode_relay_cell(
        crypto_out: &mut OutboundClientCrypt,
        relay_format: RelayCellFormat,
        hop: HopNum,
        early: bool,
        msg: AnyRelayMsgOuter,
    ) -> Result<(AnyChanMsg, SendmeTag)> {
        let mut body: RelayCellBody = msg
            .encode(relay_format, &mut rand::rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();
        let cmd = if early {
            ChanCmd::RELAY_EARLY
        } else {
            ChanCmd::RELAY
        };
        let tag = crypto_out.encrypt(cmd, &mut body, hop)?;
        let msg = Relay::from(BoxedCellBody::from(body));
        let msg = if early {
            AnyChanMsg::RelayEarly(msg.into())
        } else {
            AnyChanMsg::Relay(msg)
        };

        Ok((msg, tag))
    }

    /// Encode `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// If there is insufficient outgoing *circuit-level* or *stream-level*
    /// SENDME window, an error is returned instead.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    pub(super) async fn send_relay_cell(&mut self, msg: SendRelayCell) -> Result<()> {
        if self.is_conflux_pending() {
            // TODO(conflux): is this right? Should we ensure all the legs are linked?
            return Err(internal!("tried to send cell on unlinked circuit").into());
        }

        let SendRelayCell {
            hop,
            early,
            cell: msg,
        } = msg;

        trace!("{}: sending relay cell: {:?}", self.unique_id, msg);

        let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());
        let stream_id = msg.stream_id();
        let hop_num = Into::<usize>::into(hop);
        let circhop = &mut self.hops.get_mut(hop_num).ok_or(Error::NoSuchHop)?;

        // We need to apply stream-level flow control *before* encoding the message.
        if c_t_w {
            if let Some(stream_id) = stream_id {
                let mut hop_map = circhop.map.lock().expect("lock poisoned");
                let Some(StreamEntMut::Open(ent)) = hop_map.get_mut(stream_id) else {
                    warn!(
                        "{}: sending a relay cell for non-existent or non-open stream with ID {}!",
                        self.unique_id, stream_id
                    );
                    return Err(Error::CircProto(format!(
                        "tried to send a relay cell on non-open stream {}",
                        sv(stream_id),
                    )));
                };
                ent.take_capacity_to_send(msg.msg())?;
            }
        }

        // Save the RelayCmd of the message before it gets consumed below.
        // We need this to tell our ConfluxMsgHandler about the cell we've just sent,
        // so that it can update its counters.
        let relay_cmd = msg.cmd();

        // NOTE(eta): Now that we've encrypted the cell, we *must* either send it or abort
        //            the whole circuit (e.g. by returning an error).
        let (msg, tag) =
            Self::encode_relay_cell(&mut self.crypto_out, circhop.relay_format, hop, early, msg)?;
        // The cell counted for congestion control, inform our algorithm of such and pass down the
        // tag for authenticated SENDMEs.
        if c_t_w {
            circhop.ccontrol.note_data_sent(&tag)?;
        }

        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        Pin::new(&mut self.chan_sender).send_unbounded(cell).await?;

        #[cfg(feature = "conflux")]
        if let Some(conflux) = self.conflux_handler.as_mut() {
            conflux.note_cell_sent(relay_cmd);
        }

        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return `CellStatus::CleanShutdown` if we should exit.
    ///
    // TODO(conflux): returning `Vec<CircuitCmd>` means we're unnecessarily
    // allocating a `Vec` here. Generally, the number of commands is going to be small
    // (usually 1, but > 1 when we start supporting packed cells).
    //
    // We should consider using smallvec instead. It might also be a good idea to have a
    // separate higher-level type splitting this out into Single(CircuitCmd),
    // and Multiple(SmallVec<[CircuitCmd; <capacity>]>).
    pub(super) fn handle_cell(
        &mut self,
        handlers: &mut CellHandlers,
        leg: LegId,
        cell: ClientCircChanMsg,
    ) -> Result<Vec<CircuitCmd>> {
        trace!("{}: handling cell: {:?}", self.unique_id, cell);
        use ClientCircChanMsg::*;
        match cell {
            Relay(r) => self.handle_relay_cell(handlers, leg, r),
            Destroy(d) => {
                let reason = d.reason();
                debug!(
                    "{}: Received DESTROY cell. Reason: {} [{}]",
                    self.unique_id,
                    reason.human_str(),
                    reason
                );

                self.handle_destroy_cell().map(|c| vec![c])
            }
        }
    }

    /// Decode `cell`, returning its corresponding hop number, tag,
    /// and decoded body.
    fn decode_relay_cell(
        &mut self,
        cell: Relay,
    ) -> Result<(HopNum, SendmeTag, RelayCellDecoderResult)> {
        // This is always RELAY, not RELAY_EARLY, so long as this code is client-only.
        let cmd = cell.cmd();
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(cmd, &mut body)?;

        // Decode the cell.
        let decode_res = self
            .hop_mut(hopnum)
            .ok_or_else(|| {
                Error::from(internal!(
                    "Trying to decode cell from nonexistent hop {:?}",
                    hopnum
                ))
            })?
            .inbound
            .decode(body.into())
            .map_err(|e| Error::from_bytes_err(e, "relay cell"))?;

        Ok((hopnum, tag, decode_res))
    }

    /// React to a Relay or RelayEarly cell.
    fn handle_relay_cell(
        &mut self,
        handlers: &mut CellHandlers,
        leg: LegId,
        cell: Relay,
    ) -> Result<Vec<CircuitCmd>> {
        let (hopnum, tag, decode_res) = self.decode_relay_cell(cell)?;

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            self.hop_mut(hopnum)
                .ok_or_else(|| Error::CircProto("Sendme from nonexistent hop".into()))?
                .ccontrol
                .note_data_received()?
        } else {
            false
        };

        let mut circ_cmds = vec![];
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let sendme = Sendme::from(tag);
            let cell = AnyRelayMsgOuter::new(None, sendme.into());
            circ_cmds.push(CircuitCmd::Send(SendRelayCell {
                hop: hopnum,
                early: false,
                cell,
            }));

            // Inform congestion control of the SENDME we are sending. This is a circuit level one.
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::from(internal!(
                        "Trying to send SENDME to nonexistent hop {:?}",
                        hopnum
                    ))
                })?
                .ccontrol
                .note_sendme_sent()?;
        }

        let (mut msgs, incomplete) = decode_res.into_parts();
        while let Some(msg) = msgs.next() {
            let msg_status = self.handle_relay_msg(handlers, hopnum, leg, c_t_w, msg)?;

            match msg_status {
                None => continue,
                Some(msg @ CircuitCmd::CleanShutdown) => {
                    for m in msgs {
                        debug!(
                            "{id}: Ignoring relay msg received after triggering shutdown: {m:?}",
                            id = self.unique_id
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!(
                            "{id}: Ignoring partial relay msg received after triggering shutdown: {:?}",
                            incomplete,
                            id=self.unique_id,
                        );
                    }
                    circ_cmds.push(msg);
                    return Ok(circ_cmds);
                }
                Some(msg) => {
                    circ_cmds.push(msg);
                }
            }
        }

        Ok(circ_cmds)
    }

    /// Handle a single incoming relay message.
    fn handle_relay_msg(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        leg: LegId,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(streamid) = streamid else {
            return self.handle_meta_cell(handlers, hopnum, msg);
        };

        #[cfg(feature = "conflux")]
        let msg = if let Some(conflux) = self.conflux_handler.as_mut() {
            match conflux.action_for_msg(hopnum, cell_counts_toward_windows, streamid, msg)? {
                ConfluxAction::Deliver(msg) => {
                    // The message either doesn't count towards the sequence numbers
                    // or is already well-ordered, so we're ready to handle it.

                    // It's possible that some of our buffered messages are now ready to be
                    // handled. We don't check that here, however, because that's handled
                    // by the reactor main loop.
                    msg
                }
                ConfluxAction::Enqueue(msg) => {
                    // Tell the reactor to enqueue this msg
                    return Ok(Some(CircuitCmd::Enqueue(msg)));
                }
            }
        } else {
            // If we don't have a conflux_handler, it means this circuit is not part of
            // a conflux tunnel, so we can just process the message.
            msg
        };

        self.handle_in_order_relay_msg(
            handlers,
            hopnum,
            leg,
            cell_counts_toward_windows,
            streamid,
            msg,
        )
    }

    /// Handle a single incoming relay message that is known to be in order.
    pub(super) fn handle_in_order_relay_msg(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        leg: LegId,
        cell_counts_toward_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        #[cfg(feature = "conflux")]
        if let Some(conflux) = self.conflux_handler.as_mut() {
            conflux.inc_last_seq_delivered(&msg);
        }

        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto("Cell from nonexistent hop!".into()))?;
        let mut hop_map = hop.map.lock().expect("lock poisoned");
        match hop_map.get_mut(streamid) {
            Some(StreamEntMut::Open(ent)) => {
                // Can't have a stream level SENDME when congestion control is enabled.
                let message_closes_stream =
                    Self::deliver_msg_to_stream(streamid, ent, cell_counts_toward_windows, msg)?;

                if message_closes_stream {
                    hop_map.ending_msg_received(streamid)?;
                }
            }
            #[cfg(feature = "hs-service")]
            Some(StreamEntMut::EndSent(_))
                if matches!(
                    msg.cmd(),
                    RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
                ) =>
            {
                // If the other side is sending us a BEGIN but hasn't yet acknowledged our END
                // message, just remove the old stream from the map and stop waiting for a
                // response
                hop_map.ending_msg_received(streamid)?;
                drop(hop_map);
                return self.handle_incoming_stream_request(handlers, msg, streamid, hopnum, leg);
            }
            Some(StreamEntMut::EndSent(EndSentStreamEnt { half_stream, .. })) => {
                // We sent an end but maybe the other side hasn't heard.

                match half_stream.handle_msg(msg)? {
                    StreamStatus::Open => {}
                    StreamStatus::Closed => {
                        hop_map.ending_msg_received(streamid)?;
                    }
                }
            }
            #[cfg(feature = "hs-service")]
            None if matches!(
                msg.cmd(),
                RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
            ) =>
            {
                drop(hop_map);
                return self.handle_incoming_stream_request(handlers, msg, streamid, hopnum, leg);
            }
            _ => {
                // No stream wants this message, or ever did.
                return Err(Error::CircProto(
                    "Cell received on nonexistent stream!?".into(),
                ));
            }
        }
        Ok(None)
    }

    /// Handle a conflux message coming from the specified hop.
    ///
    /// Returns an error if
    ///
    ///   * this is not a conflux circuit (i.e. it doesn't have a [`ConfluxMsgHandler`])
    ///   * this is a client circuit and the conflux message originated an unexpected hop
    ///   * the cell was sent in violation of the handshake protocol
    #[cfg(feature = "conflux")]
    fn handle_conflux_msg(
        &mut self,
        hop: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        let Some(conflux_handler) = self.conflux_handler.as_mut() else {
            // If conflux is not enabled, tear down the circuit
            // (see 4.2.1. Cell Injection Side Channel Mitigations in prop329)
            //
            // TODO(conflux): make sure this is properly implemented
            return Err(Error::CircProto(format!(
                "Received {} cell from hop {} on non-conflux client circuit?!",
                msg.cmd(),
                hop.display(),
            )));
        };

        Ok(conflux_handler.handle_conflux_msg(msg, hop))
    }

    /// For conflux: return the sequence number of the last cell sent on this leg.
    ///
    /// Returns an error if this circuit is not part of a conflux set.
    #[cfg(feature = "conflux")]
    pub(super) fn last_seq_sent(&self) -> Result<u64> {
        let handler = self
            .conflux_handler
            .as_ref()
            .ok_or_else(|| internal!("tried to get last_seq_sent of non-conflux circ"))?;

        Ok(handler.last_seq_sent())
    }

    /// For conflux: return the sequence number of the last cell received on this leg.
    ///
    /// Returns an error if this circuit is not part of a conflux set.
    #[cfg(feature = "conflux")]
    pub(super) fn last_seq_recv(&self) -> Result<u64> {
        let handler = self
            .conflux_handler
            .as_ref()
            .ok_or_else(|| internal!("tried to get last_seq_recv of non-conflux circ"))?;

        Ok(handler.last_seq_recv())
    }

    /// Deliver `msg` to the specified open stream entry `ent`.
    fn deliver_msg_to_stream(
        streamid: StreamId,
        ent: &mut OpenStreamEnt,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<bool> {
        // The stream for this message exists, and is open.

        if msg.cmd() == RelayCmd::SENDME {
            let _sendme = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "Sendme message on stream"))?
                .into_msg();

            // We need to handle sendmes here, not in the stream's
            // recv() method, or else we'd never notice them if the
            // stream isn't reading.
            ent.put_for_incoming_sendme()?;
            return Ok(false);
        }

        let message_closes_stream = ent.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        if let Err(e) = Pin::new(&mut ent.sink).try_send(msg) {
            if e.is_full() {
                // If we get here, we either have a logic bug (!), or an attacker
                // is sending us more cells than we asked for via congestion control.
                return Err(Error::CircProto(format!(
                    "Stream sink would block; received too many cells on stream ID {}",
                    sv(streamid),
                )));
            }
            if e.is_disconnected() && cell_counts_toward_windows {
                // the other side of the stream has gone away; remember
                // that we received a cell that we couldn't queue for it.
                //
                // Later this value will be recorded in a half-stream.
                ent.dropped += 1;
            }
        }

        Ok(message_closes_stream)
    }

    /// A helper for handling incoming stream requests.
    #[cfg(feature = "hs-service")]
    fn handle_incoming_stream_request(
        &mut self,
        handlers: &mut CellHandlers,
        msg: UnparsedRelayMsg,
        stream_id: StreamId,
        hop_num: HopNum,
        leg: LegId,
    ) -> Result<Option<CircuitCmd>> {
        use super::syncview::ClientCircSyncView;
        use tor_cell::relaycell::msg::EndReason;
        use tor_error::into_internal;
        use tor_log_ratelim::log_ratelim;

        use crate::{circuit::CIRCUIT_BUFFER_SIZE, tunnel::reactor::StreamReqInfo};

        // We need to construct this early so that we don't double-borrow &mut self

        let Some(handler) = handlers.incoming_stream_req_handler.as_mut() else {
            return Err(Error::CircProto(
                "Cannot handle BEGIN cells on this circuit".into(),
            ));
        };

        if hop_num != handler.hop_num {
            return Err(Error::CircProto(format!(
                "Expecting incoming streams from {}, but received {} cell from unexpected hop {}",
                handler.hop_num.display(),
                msg.cmd(),
                hop_num.display()
            )));
        }

        let message_closes_stream = handler.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        // TODO: we've already looked up the `hop` in handle_relay_cell, so we shouldn't
        // have to look it up again! However, we can't pass the `&mut hop` reference from
        // `handle_relay_cell` to this function, because that makes Rust angry (we'd be
        // borrowing self as mutable more than once).
        //
        // TODO: we _could_ use self.hops.get_mut(..) instead self.hop_mut(..) inside
        // handle_relay_cell to work around the problem described above
        let hop = self
            .hops
            .get_mut(Into::<usize>::into(hop_num))
            .ok_or(Error::CircuitClosed)?;

        if message_closes_stream {
            hop.map
                .lock()
                .expect("lock poisoned")
                .ending_msg_received(stream_id)?;

            return Ok(None);
        }

        let begin = msg
            .decode::<Begin>()
            .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
            .into_msg();

        let req = IncomingStreamRequest::Begin(begin);

        {
            use crate::stream::IncomingStreamRequestDisposition::*;

            let ctx = crate::stream::IncomingStreamRequestContext { request: &req };
            // IMPORTANT: ClientCircSyncView::n_open_streams() (called via disposition() below)
            // accesses the stream map mutexes!
            //
            // This means it's very important not to call this function while any of the hop's
            // stream map mutex is held.
            let view = ClientCircSyncView::new(&self.hops);

            match handler.filter.as_mut().disposition(&ctx, &view)? {
                Accept => {}
                CloseCircuit => return Ok(Some(CircuitCmd::CleanShutdown)),
                RejectRequest(end) => {
                    let end_msg = AnyRelayMsgOuter::new(Some(stream_id), end.into());
                    let cell = SendRelayCell {
                        hop: hop_num,
                        early: false,
                        cell: end_msg,
                    };
                    return Ok(Some(CircuitCmd::Send(cell)));
                }
            }
        }

        // TODO: Sadly, we need to look up `&mut hop` yet again,
        // since we needed to pass `&self.hops` by reference to our filter above. :(
        let hop = self
            .hops
            .get_mut(Into::<usize>::into(hop_num))
            .ok_or(Error::CircuitClosed)?;
        let relay_cell_format = hop.relay_format;

        let memquota = StreamAccount::new(&self.memquota)?;

        let (sender, receiver) = MpscSpec::new(STREAM_READER_BUFFER).new_mq(
            self.chan_sender.as_inner().time_provider().clone(),
            memquota.as_raw_account(),
        )?;
        let (msg_tx, msg_rx) = MpscSpec::new(CIRCUIT_BUFFER_SIZE).new_mq(
            self.chan_sender.as_inner().time_provider().clone(),
            memquota.as_raw_account(),
        )?;

        let cmd_checker = DataCmdChecker::new_connected();
        hop.map.lock().expect("lock poisoned").add_ent_with_id(
            sender,
            msg_rx,
            hop.build_send_flow_ctrl(),
            stream_id,
            cmd_checker,
        )?;

        let outcome = Pin::new(&mut handler.incoming_sender).try_send(StreamReqInfo {
            req,
            stream_id,
            hop_num,
            leg,
            msg_tx,
            receiver,
            memquota,
            relay_cell_format,
        });

        log_ratelim!("Delivering message to incoming stream handler"; outcome);

        if let Err(e) = outcome {
            if e.is_full() {
                // The IncomingStreamRequestHandler's stream is full; it isn't
                // handling requests fast enough. So instead, we reply with an
                // END cell.
                let end_msg = AnyRelayMsgOuter::new(
                    Some(stream_id),
                    End::new_with_reason(EndReason::RESOURCELIMIT).into(),
                );

                let cell = SendRelayCell {
                    hop: hop_num,
                    early: false,
                    cell: end_msg,
                };
                return Ok(Some(CircuitCmd::Send(cell)));
            } else if e.is_disconnected() {
                // The IncomingStreamRequestHandler's stream has been dropped.
                // In the Tor protocol as it stands, this always means that the
                // circuit itself is out-of-use and should be closed. (See notes
                // on `allow_stream_requests.`)
                //
                // Note that we will _not_ reach this point immediately after
                // the IncomingStreamRequestHandler is dropped; we won't hit it
                // until we next get an incoming request.  Thus, if we do later
                // want to add early detection for a dropped
                // IncomingStreamRequestHandler, we need to do it elsewhere, in
                // a different way.
                debug!(
                    "{}: Incoming stream request receiver dropped",
                    self.unique_id
                );
                // This will _cause_ the circuit to get closed.
                return Err(Error::CircuitClosed);
            } else {
                // There are no errors like this with the current design of
                // futures::mpsc, but we shouldn't just ignore the possibility
                // that they'll be added later.
                return Err(Error::from((into_internal!(
                    "try_send failed unexpectedly"
                ))(e)));
            }
        }

        Ok(None)
    }

    /// Helper: process a destroy cell.
    #[allow(clippy::unnecessary_wraps)]
    fn handle_destroy_cell(&mut self) -> Result<CircuitCmd> {
        // I think there is nothing more to do here.
        Ok(CircuitCmd::CleanShutdown)
    }

    /// Handle a [`CtrlMsg::Create`](super::CtrlMsg::Create) message.
    pub(super) async fn handle_create(
        &mut self,
        recv_created: oneshot::Receiver<CreateResponse>,
        handshake: CircuitHandshake,
        params: &mut CircParameters,
        done: ReactorResultChannel<()>,
    ) -> StdResult<(), ReactorError> {
        let ret = match handshake {
            CircuitHandshake::CreateFast => self.create_firsthop_fast(recv_created, params).await,
            CircuitHandshake::Ntor {
                public_key,
                ed_identity,
            } => {
                self.create_firsthop_ntor(recv_created, ed_identity, public_key, params)
                    .await
            }
            CircuitHandshake::NtorV3 { public_key } => {
                self.create_firsthop_ntor_v3(recv_created, public_key, params)
                    .await
            }
        };
        let _ = done.send(ret); // don't care if sender goes away

        // TODO: maybe we don't need to flush here?
        // (we could let run_once() handle all the flushing)
        self.chan_sender.flush().await?;

        Ok(())
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, and a handshake object to perform
    /// the cryptographic handshake.
    async fn create_impl<H, W, M>(
        &mut self,
        cell_protocol: RelayCryptLayerProtocol,
        recvcreated: oneshot::Receiver<CreateResponse>,
        wrap: &W,
        key: &H::KeyType,
        params: &mut CircParameters,
        msg: &M,
    ) -> Result<()>
    where
        H: ClientHandshake + HandshakeAuxDataHandler,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
        M: Borrow<H::ClientAuxData>,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let (state, msg) = {
            // done like this because holding the RNG across an await boundary makes the future
            // non-Send
            let mut rng = rand::rng();
            H::client1(&mut rng, key, msg)?
        };
        let create_cell = wrap.to_chanmsg(msg);
        trace!(
            "{}: Extending to hop 1 with {}",
            self.unique_id,
            create_cell.cmd()
        );
        self.send_msg(create_cell).await?;

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let relay_handshake = wrap.decode_chanmsg(reply)?;
        let (server_msg, keygen) = H::client2(state, relay_handshake)?;

        H::handle_server_aux_data(params, &server_msg)?;

        let relay_cell_format = cell_protocol.relay_cell_format();
        let BoxedClientLayer { fwd, back, binding } =
            cell_protocol.construct_client_layers(HandshakeRole::Initiator, keygen)?;

        trace!("{}: Handshake complete; circuit created.", self.unique_id);

        let peer_id = self.channel.target().clone();

        self.add_hop(
            relay_cell_format,
            path::HopDetail::Relay(peer_id),
            fwd,
            back,
            binding,
            params,
        )?;
        Ok(())
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CREATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    async fn create_firsthop_fast(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        params: &mut CircParameters,
    ) -> Result<()> {
        // In a CREATE_FAST handshake, we can't negotiate a format other than this.
        let protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);
        let wrap = CreateFastWrap;
        self.create_impl::<CreateFastClient, _, _>(protocol, recvcreated, &wrap, &(), params, &())
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided keys must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        ed_identity: pk::ed25519::Ed25519Identity,
        pubkey: NtorPublicKey,
        params: &mut CircParameters,
    ) -> Result<()> {
        // In an ntor handshake, we can't negotiate a format other than this.
        let relay_cell_protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);

        // Exit now if we have an Ed25519 or RSA identity mismatch.
        let target = RelayIds::builder()
            .ed_identity(ed_identity)
            .rsa_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR,
        };
        self.create_impl::<NtorClient, _, _>(
            relay_cell_protocol,
            recvcreated,
            &wrap,
            &pubkey,
            params,
            &(),
        )
        .await
    }

    /// Use the ntor-v3 handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided key must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor_v3(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        pubkey: NtorV3PublicKey,
        params: &mut CircParameters,
    ) -> Result<()> {
        // Exit now if we have a mismatched key.
        let target = RelayIds::builder()
            .ed_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        // TODO #1947: Add support for negotiating other formats.
        let relay_cell_protocol = RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0);

        // Set the client extensions.
        let client_extensions = circ_extensions_from_params(params)?;
        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR_V3,
        };

        self.create_impl::<NtorV3Client, _, _>(
            relay_cell_protocol,
            recvcreated,
            &wrap,
            &pubkey,
            params,
            &client_extensions,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    ///
    /// Will return an error if the circuit already has [`u8::MAX`] hops.
    pub(super) fn add_hop(
        &mut self,
        format: RelayCellFormat,
        peer_id: path::HopDetail,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        binding: Option<CircuitBinding>,
        params: &CircParameters,
    ) -> StdResult<(), Bug> {
        let hop_num = self.hops.len();
        debug_assert_eq!(hop_num, usize::from(self.num_hops()));

        // There are several places in the code that assume that a `usize` hop number
        // can be cast or converted to a `u8` hop number,
        // so this check is important to prevent panics or incorrect behaviour.
        if hop_num == usize::from(u8::MAX) {
            return Err(internal!(
                "cannot add more hops to a circuit with `u8::MAX` hops"
            ));
        }

        let hop_num = (hop_num as u8).into();

        let hop = CircHop::new(self.unique_id, hop_num, format, params);
        self.hops.push(hop);
        self.crypto_in.add_layer(rev);
        self.crypto_out.add_layer(fwd);
        self.mutable.add_hop(peer_id, binding);

        Ok(())
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    #[allow(clippy::cognitive_complexity)]
    fn handle_meta_cell(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.

        // TODO: This pattern (Check command, try to decode, map error) occurs
        // several times, and would be good to extract simplify. Such
        // simplification is obstructed by a couple of factors: First, that
        // there is not currently a good way to get the RelayCmd from _type_ of
        // a RelayMsg.  Second, that decode() [correctly] consumes the
        // UnparsedRelayMsg.  I tried a macro-based approach, and didn't care
        // for it. -nickm
        if msg.cmd() == RelayCmd::SENDME {
            let sendme = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "sendme message"))?
                .into_msg();

            return Ok(Some(CircuitCmd::HandleSendMe {
                hop: hopnum,
                sendme,
            }));
        }
        if msg.cmd() == RelayCmd::TRUNCATED {
            let truncated = msg
                .decode::<Truncated>()
                .map_err(|e| Error::from_bytes_err(e, "truncated message"))?
                .into_msg();
            let reason = truncated.reason();
            debug!(
                "{}: Truncated from hop {}. Reason: {} [{}]",
                self.unique_id,
                hopnum.display(),
                reason.human_str(),
                reason
            );

            return Ok(Some(CircuitCmd::CleanShutdown));
        }

        trace!("{}: Received meta-cell {:?}", self.unique_id, msg);

        #[cfg(feature = "conflux")]
        if matches!(
            msg.cmd(),
            RelayCmd::CONFLUX_LINK
                | RelayCmd::CONFLUX_LINKED
                | RelayCmd::CONFLUX_LINKED_ACK
                | RelayCmd::CONFLUX_SWITCH
        ) {
            return self.handle_conflux_msg(hopnum, msg);
        }

        if self.is_conflux_pending() {
            warn!(
                "{}: received unexpected cell {msg:?} on unlinked conflux circuit",
                self.unique_id,
            );
            return Err(Error::CircProto(
                "Received unexpected cell on unlinked circuit".into(),
            ));
        }

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO:(conflux): should the conflux state machine be a meta cell handler?
        // We'd need to add support for multiple meta handlers, and change the
        // MetaCellHandler API to support returning Option<RunOnceCmdInner>
        // (because some cells will require sending a response)
        if let Some(mut handler) = handlers.meta_handler.take() {
            if handler.expected_hop() == hopnum {
                // Somebody was waiting for a message -- maybe this message
                let ret = handler.handle_msg(msg, self);
                trace!(
                    "{}: meta handler completed with result: {:?}",
                    self.unique_id,
                    ret
                );
                match ret {
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::Consumed) => {
                        handlers.meta_handler = Some(handler);
                        Ok(None)
                    }
                    Ok(MetaCellDisposition::ConversationFinished) => Ok(None),
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::CloseCirc) => Ok(Some(CircuitCmd::CleanShutdown)),
                    Err(e) => Err(e),
                }
            } else {
                // Somebody wanted a message from a different hop!  Put this
                // one back.
                handlers.meta_handler = Some(handler);

                unsupported_client_cell!(msg, hopnum)
            }
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            unsupported_client_cell!(msg)
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    pub(super) fn handle_sendme(
        &mut self,
        hopnum: HopNum,
        msg: Sendme,
        signals: CongestionSignals,
    ) -> Result<Option<CircuitCmd>> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find hop {}", hopnum.display())))?;

        let tag = msg.into_sendme_tag().ok_or_else(||
                // Versions of Tor <=0.3.5 would omit a SENDME tag in this case;
                // but we don't support those any longer.
                 Error::CircProto("missing tag on circuit sendme".into()))?;
        // Update the CC object that we received a SENDME along with possible congestion signals.
        hop.ccontrol.note_sendme_received(tag, signals)?;
        Ok(None)
    }

    /// Send a message onto the circuit's channel.
    ///
    /// If the channel is ready to accept messages, it will be sent immediately. If not, the message
    /// will be enqueued for sending at a later iteration of the reactor loop.
    ///
    /// # Note
    ///
    /// Making use of the enqueuing capabilities of this function is discouraged! You should first
    /// check whether the channel is ready to receive messages (`self.channel.poll_ready`), and
    /// ideally use this to implement backpressure (such that you do not read from other sources
    /// that would send here while you know you're unable to forward the messages on).
    async fn send_msg(&mut self, msg: AnyChanMsg) -> Result<()> {
        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        // Note: this future is always `Ready`, so await won't block.
        Pin::new(&mut self.chan_sender).send_unbounded(cell).await?;
        Ok(())
    }

    /// Returns a [`Stream`] of [`CircuitCmd`] to poll from the main loop.
    ///
    /// The iterator contains at most one [`CircuitCmd`] for each hop,
    /// representing the instructions for handling the ready-item, if any,
    /// of its highest priority stream.
    ///
    /// IMPORTANT: this stream locks the stream map mutexes of each `CircHop`!
    /// To avoid contention, never create more than one [`Circuit::ready_streams_iterator`]
    /// stream at a time!
    ///
    /// This is cancellation-safe.
    pub(super) fn ready_streams_iterator(&self) -> impl Stream<Item = Result<CircuitCmd>> {
        self.hops
            .iter()
            .enumerate()
            .filter_map(|(i, hop)| {
                if !hop.ccontrol.can_send() {
                    // We can't send anything on this hop that counts towards SENDME windows.
                    //
                    // In theory we could send messages that don't count towards
                    // windows (like `RESOLVE`), and process end-of-stream
                    // events (to send an `END`), but it's probably not worth
                    // doing an O(N) iteration over flow-control-ready streams
                    // to see if that's the case.
                    //
                    // This *doesn't* block outgoing flow-control messages (e.g.
                    // SENDME), which are initiated via the control-message
                    // channel, handled above.
                    //
                    // TODO: Consider revisiting. OTOH some extra throttling when circuit-level
                    // congestion control has "bottomed out" might not be so bad, and the
                    // alternatives have complexity and/or performance costs.
                    return None;
                }

                let hop_num = HopNum::from(i as u8);
                let hop_map = Arc::clone(&self.hops[i].map);
                Some(futures::future::poll_fn(move |cx| {
                    // Process an outbound message from the first ready stream on
                    // this hop. The stream map implements round robin scheduling to
                    // ensure fairness across streams.
                    // TODO: Consider looping here to process multiple ready
                    // streams. Need to be careful though to balance that with
                    // continuing to service incoming and control messages.
                    let mut hop_map = hop_map.lock().expect("lock poisoned");
                    let Some((sid, msg)) = hop_map.poll_ready_streams_iter(cx).next() else {
                        // No ready streams for this hop.
                        return Poll::Pending;
                    };

                    if msg.is_none() {
                        return Poll::Ready(Ok(CircuitCmd::CloseStream {
                            hop: hop_num,
                            sid,
                            behav: CloseStreamBehavior::default(),
                            reason: streammap::TerminateReason::StreamTargetClosed,
                        }));
                    };
                    let msg = hop_map.take_ready_msg(sid).expect("msg disappeared");

                    #[allow(unused)] // unused in non-debug builds
                    let Some(StreamEntMut::Open(s)) = hop_map.get_mut(sid) else {
                        panic!("Stream {sid} disappeared");
                    };

                    debug_assert!(
                        s.can_send(&msg),
                        "Stream {sid} produced a message it can't send: {msg:?}"
                    );

                    let cell = SendRelayCell {
                        hop: hop_num,
                        early: false,
                        cell: AnyRelayMsgOuter::new(Some(sid), msg),
                    };
                    Poll::Ready(Ok(CircuitCmd::Send(cell)))
                }))
            })
            .collect::<FuturesUnordered<_>>()
    }

    /// Return the congestion signals for this reactor. This is used by congestion control module.
    ///
    /// Note: This is only async because we need a Context to check the sink for readiness.
    pub(super) async fn congestion_signals(&mut self) -> CongestionSignals {
        futures::future::poll_fn(|cx| -> Poll<CongestionSignals> {
            Poll::Ready(CongestionSignals::new(
                self.chan_sender.poll_ready_unpin_bool(cx).unwrap_or(false),
                self.chan_sender.n_queued(),
            ))
        })
        .await
    }

    /// Return a reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn hop(&self, hopnum: HopNum) -> Option<&CircHop> {
        self.hops.get(Into::<usize>::into(hopnum))
    }

    /// Return a mutable reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Begin a stream with the provided hop in this circuit.
    pub(super) fn begin_stream(
        &mut self,
        hop_num: HopNum,
        message: AnyRelayMsg,
        sender: StreamMpscSender<UnparsedRelayMsg>,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> StdResult<Result<(SendRelayCell, StreamId)>, Bug> {
        let Some(hop) = self.hop_mut(hop_num) else {
            return Err(internal!(
                "{}: Attempting to send a BEGIN cell to an unknown hop {hop_num:?}",
                self.unique_id,
            ));
        };

        Ok(hop.begin_stream(message, sender, rx, cmd_checker))
    }

    /// Close the specified stream
    pub(super) async fn close_stream(
        &mut self,
        hop_num: HopNum,
        sid: StreamId,
        behav: CloseStreamBehavior,
        reason: streammap::TerminateReason,
    ) -> Result<()> {
        if let Some(hop) = self.hop_mut(hop_num) {
            let res = hop.close_stream(sid, behav, reason)?;
            if let Some(cell) = res {
                self.send_relay_cell(cell).await?;
            }
        }
        Ok(())
    }

    /// Returns true if there are any streams on this circuit
    ///
    /// Important: this function locks the stream map of its each of the [`CircHop`]s
    /// in this circuit, so it must **not** be called from any function where the
    /// stream map lock is held (such as [`ready_streams_iterator`](Self::ready_streams_iterator).
    pub(super) fn has_streams(&self) -> bool {
        self.hops
            .iter()
            .any(|hop| hop.map.lock().expect("lock poisoned").n_open_streams() > 0)
    }

    /// The number of hops in this circuit.
    pub(super) fn num_hops(&self) -> u8 {
        // `Circuit::add_hop` checks to make sure that we never have more than `u8::MAX` hops,
        // so `self.hops.len()` should be safe to cast to a `u8`.
        // If that assumption is violated,
        // we choose to panic rather than silently use the wrong hop due to an `as` cast.
        self.hops
            .len()
            .try_into()
            .expect("`hops.len()` has more than `u8::MAX` hops")
    }

    /// Check whether this circuit has any hops.
    pub(super) fn has_hops(&self) -> bool {
        !self.hops.is_empty()
    }

    /// Get the `HopNum` of the last hop, if this circuit is non-empty.
    ///
    /// Returns `None` if the circuit has no hops.
    pub(super) fn last_hop_num(&self) -> Option<HopNum> {
        let num_hops = self.num_hops();
        if num_hops == 0 {
            // asked for the last hop, but there are no hops
            return None;
        }
        Some(HopNum::from(num_hops - 1))
    }

    /// Get the path of the circuit.
    ///
    /// **Warning:** Do not call while already holding the [`Self::mutable`] lock.
    pub(super) fn path(&self) -> Arc<path::Path> {
        self.mutable.path()
    }

    /// Return a ClockSkew declaring how much clock skew the other side of this channel
    /// claimed that we had when we negotiated the connection.
    pub(super) fn clock_skew(&self) -> ClockSkew {
        self.channel.clock_skew()
    }

    /// Does congestion control use stream SENDMEs for the given `hop`?
    ///
    /// Returns `None` if `hop` doesn't exist.
    pub(super) fn uses_stream_sendme(&self, hop: HopNum) -> Option<bool> {
        let hop = self.hop(hop)?;
        Some(hop.ccontrol.uses_stream_sendme())
    }

    /// Returns whether this is a conflux circuit that is not linked yet.
    pub(super) fn is_conflux_pending(&self) -> bool {
        let Some(status) = self.conflux_status() else {
            return false;
        };

        status != ConfluxStatus::Linked
    }

    /// Returns the conflux status of this circuit.
    ///
    /// Returns `None` if this is not a conflux circuit.
    pub(super) fn conflux_status(&self) -> Option<ConfluxStatus> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                self.conflux_handler
                    .as_ref()
                    .map(|handler| handler.status())
            } else {
                None
            }
        }
    }

    /// Returns initial RTT on this leg, measured in the conflux handshake.
    #[cfg(feature = "conflux")]
    pub(super) fn init_rtt(&self) -> Option<Duration> {
        self.conflux_handler
            .as_ref()
            .map(|handler| handler.init_rtt())?
    }
}

/// The conflux status of a conflux [`Circuit`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum ConfluxStatus {
    /// Circuit has not begun the conflux handshake yet.
    Unlinked,
    /// Conflux handshake is in progress.
    Pending,
    /// A linked conflux circuit.
    Linked,
}

/// Return the stream ID of `msg`, if it has one.
///
/// Returns `Ok(None)` if `msg` is a meta cell.
fn msg_streamid(msg: &UnparsedRelayMsg) -> Result<Option<StreamId>> {
    let cmd = msg.cmd();
    let streamid = msg.stream_id();
    if !cmd.accepts_streamid_val(streamid) {
        return Err(Error::CircProto(format!(
            "Invalid stream ID {} for relay command {}",
            sv(StreamId::get_or_zero(streamid)),
            msg.cmd()
        )));
    }

    Ok(streamid)
}

impl Drop for Circuit {
    fn drop(&mut self) {
        let _ = self.channel.close_circuit(self.channel_id);
    }
}

impl CircHop {
    /// Create a new hop.
    pub(super) fn new(
        unique_id: UniqId,
        hop_num: HopNum,
        relay_format: RelayCellFormat,
        params: &CircParameters,
    ) -> Self {
        CircHop {
            unique_id,
            hop_num,
            map: Arc::new(Mutex::new(streammap::StreamMap::new())),
            ccontrol: CongestionControl::new(&params.ccontrol),
            inbound: RelayCellDecoder::new(relay_format),
            relay_format,
        }
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    pub(crate) fn begin_stream(
        &mut self,
        message: AnyRelayMsg,
        sender: StreamMpscSender<UnparsedRelayMsg>,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(SendRelayCell, StreamId)> {
        let flow_ctrl = self.build_send_flow_ctrl();
        let r =
            self.map
                .lock()
                .expect("lock poisoned")
                .add_ent(sender, rx, flow_ctrl, cmd_checker)?;
        let cell = AnyRelayMsgOuter::new(Some(r), message);
        Ok((
            SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell,
            },
            r,
        ))
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    /// If no END cell is specified, an END cell with the reason byte set to
    /// REASON_MISC will be sent.
    fn close_stream(
        &mut self,
        id: StreamId,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
    ) -> Result<Option<SendRelayCell>> {
        let should_send_end = self.map.lock().expect("lock poisoned").terminate(id, why)?;
        trace!(
            "{}: Ending stream {}; should_send_end={:?}",
            self.unique_id,
            id,
            should_send_end
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if let (ShouldSendEnd::Send, CloseStreamBehavior::SendEnd(end_message)) =
            (should_send_end, message)
        {
            let end_cell = AnyRelayMsgOuter::new(Some(id), end_message.into());
            let cell = SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell: end_cell,
            };

            return Ok(Some(cell));
        }
        Ok(None)
    }

    /// Return the format that is used for relay cells sent to this hop.
    ///
    /// For the most part, this format isn't necessary to interact with a CircHop;
    /// it becomes relevant when we are deciding _what_ we can encode for the hop.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.relay_format
    }

    /// Builds the (sending) flow control handler for a new stream.
    fn build_send_flow_ctrl(&self) -> StreamSendFlowControl {
        if self.ccontrol.uses_stream_sendme() {
            let window = sendme::StreamSendWindow::new(SEND_WINDOW_INIT);
            StreamSendFlowControl::new_window_based(window)
        } else {
            StreamSendFlowControl::new_xon_xoff_based()
        }
    }

    /// Delegate to CongestionControl, for testing purposes
    #[cfg(test)]
    pub(crate) fn send_window_and_expected_tags(&self) -> (u32, Vec<SendmeTag>) {
        self.ccontrol.send_window_and_expected_tags()
    }

    /// Return the number of open streams on this hop.
    ///
    /// WARNING: because this locks the stream map mutex,
    /// it should never be called from a context where that mutex is already locked.
    pub(super) fn n_open_streams(&self) -> usize {
        self.map.lock().expect("lock poisoned").n_open_streams()
    }

    /// Return a reference to our CongestionControl object.
    pub(crate) fn ccontrol(&self) -> &CongestionControl {
        &self.ccontrol
    }
}

/// Return the client circuit-creation extensions that we should use in order to negotiate
/// a given set of circuit hop parameters.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn circ_extensions_from_params(params: &CircParameters) -> Result<Vec<CircRequestExt>> {
    // allow 'unused_mut' because of the combinations of `cfg` conditions below
    #[allow(unused_mut)]
    let mut client_extensions = Vec::new();

    if params.ccontrol.is_enabled() {
        cfg_if::cfg_if! {
            if #[cfg(feature = "flowctl-cc")] {
                // TODO(arti#88): We have an `if false` in `exit_circparams_from_netparams`
                // which should prevent the above `is_enabled()` from ever being true,
                // even with the "flowctl-cc" feature enabled:
                // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2932#note_3191196
                // The panic here is so that CI tests will hopefully catch if congestion
                // control is unexpectedly enabled.
                // We should remove this panic once xon/xoff flow is supported.
                #[cfg(not(test))]
                panic!("Congestion control is enabled on this circuit, but we don't yet support congestion control");

                #[allow(unreachable_code)]
                client_extensions.push(CircRequestExt::CcRequest(CcRequest::default()));
            } else {
                return Err(
                    tor_error::internal!(
                        "Congestion control is enabled on this circuit, but 'flowctl-cc' feature is not enabled"
                    )
                    .into()
                );
            }
        }
    }

    Ok(client_extensions)
}
