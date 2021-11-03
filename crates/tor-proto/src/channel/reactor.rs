//! Code to handle incoming cells on a channel.
//!
//! The role of this code is to run in a separate asynchronous task,
//! and routes cells to the right circuits.
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.

use super::circmap::{CircEnt, CircMap};
use super::UniqId;
use crate::circuit::halfcirc::HalfCirc;
use crate::util::err::ReactorError;
use crate::{Error, Result};
use tor_cell::chancell::msg::{Destroy, DestroyReason};
use tor_cell::chancell::{msg::ChanMsg, ChanCell, CircId};

use futures::channel::{mpsc, oneshot};

use futures::sink::SinkExt;
use futures::stream::Stream;
use futures::Sink;

use std::convert::TryInto;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;

use crate::channel::unique_id;
use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use tracing::{debug, trace};

/// A boxed trait object that can provide `ChanCell`s.
pub(super) type BoxedChannelStream =
    Box<dyn Stream<Item = std::result::Result<ChanCell, tor_cell::Error>> + Send + Unpin + 'static>;
/// A boxed trait object that can sink `ChanCell`s.
pub(super) type BoxedChannelSink =
    Box<dyn Sink<ChanCell, Error = tor_cell::Error> + Send + Unpin + 'static>;
/// The type of a oneshot channel used to inform reactor users of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

/// A message telling the channel reactor to do something.
#[derive(Debug)]
pub(super) enum CtrlMsg {
    /// Shut down the reactor.
    Shutdown,
    /// Tell the reactor that a given circuit has gone away.
    CloseCircuit(CircId),
    /// Allocate a new circuit in this channel's circuit map, generating an ID for it
    /// and registering senders for messages received for the circuit.
    AllocateCircuit {
        /// Channel to send the circuit's `CreateResponse` down.
        created_sender: oneshot::Sender<CreateResponse>,
        /// Channel to send other messages from this circuit down.
        sender: mpsc::Sender<ClientCircChanMsg>,
        /// Oneshot channel to send the new circuit's identifiers down.
        tx: ReactorResultChannel<(CircId, crate::circuit::UniqId)>,
    },
}

/// Object to handle incoming cells and background tasks on a channel.
///
/// This type is returned when you finish a channel; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the channel won't work."]
pub struct Reactor {
    /// A receiver for control messages from `Channel` objects.
    pub(super) control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// A receiver for cells to be sent on this reactor's sink.
    ///
    /// `Channel` objects have a sender that can send cells here.
    pub(super) cells: mpsc::Receiver<ChanCell>,
    /// A Stream from which we can read `ChanCell`s.
    ///
    /// This should be backed by a TLS connection if you want it to be secure.
    pub(super) input: futures::stream::Fuse<BoxedChannelStream>,
    /// A Sink to which we can write `ChanCell`s.
    ///
    /// This should also be backed by a TLS connection if you want it to be secure.
    pub(super) output: BoxedChannelSink,
    /// A map from circuit ID to Sinks on which we can deliver cells.
    pub(super) circs: CircMap,
    /// Logging identifier for this channel
    pub(super) unique_id: UniqId,
    /// If true, this channel is closing.
    pub(super) closed: Arc<AtomicBool>,
    /// Context for allocating unique circuit log identifiers.
    pub(super) circ_unique_id_ctx: unique_id::CircUniqIdContext,
    /// What link protocol is the channel using?
    #[allow(dead_code)] // We don't support protocols where this would matter
    pub(super) link_protocol: u16,
}

impl Reactor {
    /// Launch the reactor, and run until the channel closes or we
    /// encounter an error.
    ///
    /// Once this function returns, the channel is dead, and can't be
    /// used again.
    pub async fn run(mut self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::ChannelClosed);
        }
        debug!("{}: Running reactor", self.unique_id);
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        debug!("{}: Reactor stopped: {:?}", self.unique_id, result);
        self.closed.store(true, Ordering::SeqCst);
        result
    }

    /// Helper for run(): handles only one action, and doesn't mark
    /// the channel closed on finish.
    async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        // This is written this way (manually calling poll) for a bunch of reasons:
        //
        // - We can only send things onto self.output if poll_ready has returned Ready, so
        //   we need some custom logic to implement that.
        // - We probably want to call poll_flush on every reactor iteration, to ensure it continues
        //   to make progress flushing.
        // - We also need to do the equivalent of select! between self.cells, self.control, and
        //   self.input, but with the extra logic bits added above.
        //
        // In Rust 2021, it would theoretically be possible to do this with a hybrid mix of select!
        // and manually implemented poll_fn, but we aren't using that yet. (also, arguably doing
        // it this way is both less confusing and more flexible).
        let fut = futures::future::poll_fn(|cx| -> Poll<std::result::Result<_, ReactorError>> {
            // We've potentially got three types of thing to deal with in this reactor iteration:
            let mut cell_to_send = None;
            let mut control_message = None;
            let mut input = None;

            // See if the output sink can have cells written to it yet.
            if let Poll::Ready(ret) = Pin::new(&mut self.output).poll_ready(cx) {
                let _ = ret.map_err(Error::CellErr)?;
                // If it can, check whether we have any cells to send it from `Channel` senders.
                if let Poll::Ready(msg) = Pin::new(&mut self.cells).poll_next(cx) {
                    match msg {
                        x @ Some(..) => cell_to_send = x,
                        None => {
                            // cells sender dropped, shut down the reactor!
                            return Poll::Ready(Err(ReactorError::Shutdown));
                        }
                    }
                }
            }

            // Check whether we've got a control message pending.
            if let Poll::Ready(ret) = Pin::new(&mut self.control).poll_next(cx) {
                match ret {
                    None | Some(CtrlMsg::Shutdown) => {
                        return Poll::Ready(Err(ReactorError::Shutdown))
                    }
                    x @ Some(..) => control_message = x,
                }
            }

            // Check whether we've got any incoming cells.
            if let Poll::Ready(ret) = Pin::new(&mut self.input).poll_next(cx) {
                match ret {
                    None => return Poll::Ready(Err(ReactorError::Shutdown)),
                    Some(r) => input = Some(r.map_err(Error::CellErr)?),
                }
            }

            // Flush the output sink. We don't actually care about whether it's ready or not;
            // we just want to keep flushing it (hence the _).
            let _ = Pin::new(&mut self.output)
                .poll_flush(cx)
                .map_err(Error::CellErr)?;

            // If all three values aren't present, return Pending and wait to get polled again
            // so that one of them is present.
            if cell_to_send.is_none() && control_message.is_none() && input.is_none() {
                return Poll::Pending;
            }
            // Otherwise, return the three Options, one of which is going to be Some.
            Poll::Ready(Ok((cell_to_send, control_message, input)))
        });
        let (cell_to_send, control_message, input) = fut.await?;
        if let Some(ctrl) = control_message {
            self.handle_control(ctrl).await?;
        }
        if let Some(item) = input {
            crate::note_incoming_traffic();
            self.handle_cell(item).await?;
        }
        if let Some(cts) = cell_to_send {
            Pin::new(&mut self.output)
                .start_send(cts)
                .map_err(Error::CellErr)?;
            // Give the sink a little flush, to make sure it actually starts doing things.
            futures::future::poll_fn(|cx| Pin::new(&mut self.output).poll_flush(cx))
                .await
                .map_err(Error::CellErr)?;
        }
        Ok(()) // Run again.
    }

    /// Handle a CtrlMsg other than Shutdown.
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        trace!("{}: reactor received {:?}", self.unique_id, msg);
        match msg {
            CtrlMsg::Shutdown => panic!(), // was handled in reactor loop.
            CtrlMsg::CloseCircuit(id) => self.outbound_destroy_circ(id).await?,
            CtrlMsg::AllocateCircuit {
                created_sender,
                sender,
                tx,
            } => {
                let mut rng = rand::thread_rng();
                let my_unique_id = self.unique_id;
                let circ_unique_id = self.circ_unique_id_ctx.next(my_unique_id);
                let ret: Result<_> = self
                    .circs
                    .add_ent(&mut rng, created_sender, sender)
                    .map(|id| (id, circ_unique_id));
                let _ = tx.send(ret); // don't care about other side going away
            }
        }
        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cell types get ignored
    /// or rejected; a few get delivered to circuits.
    async fn handle_cell(&mut self, cell: ChanCell) -> Result<()> {
        let (circid, msg) = cell.into_circid_and_msg();
        use ChanMsg::*;

        match msg {
            Relay(_) | Padding(_) | VPadding(_) => {} // too frequent to log.
            _ => trace!("{}: received {} for {}", self.unique_id, msg.cmd(), circid),
        }

        match msg {
            // These aren't allowed on clients.
            Create(_) | CreateFast(_) | Create2(_) | RelayEarly(_) | PaddingNegotiate(_) => Err(
                Error::ChanProto(format!("{} cell on client channel", msg.cmd())),
            ),

            // In theory this is allowed in clients, but we should never get
            // one, since we don't use TAP.
            Created(_) => Err(Error::ChanProto(format!(
                "{} cell received, but we never send CREATEs",
                msg.cmd()
            ))),

            // These aren't allowed after handshaking is done.
            Versions(_) | Certs(_) | Authorize(_) | Authenticate(_) | AuthChallenge(_)
            | Netinfo(_) => Err(Error::ChanProto(format!(
                "{} cell after handshake is done",
                msg.cmd()
            ))),

            // These are allowed, and need to be handled.
            Relay(_) => self.deliver_relay(circid, msg).await,

            Destroy(_) => self.deliver_destroy(circid, msg).await,

            CreatedFast(_) | Created2(_) => self.deliver_created(circid, msg).await,

            // These are always ignored.
            Padding(_) | VPadding(_) => Ok(()),

            // Unrecognized cell types should be safe to allow _on channels_,
            // since they can't propagate.
            Unrecognized(_) => Ok(()),

            // tor_cells knows about this type, but we don't.
            _ => Ok(()),
        }
    }

    /// Give the RELAY cell `msg` to the appropriate circuit.
    async fn deliver_relay(&mut self, circid: CircId, msg: ChanMsg) -> Result<()> {
        match self.circs.get_mut(circid) {
            Some(CircEnt::Open(s)) => {
                // There's an open circuit; we can give it the RELAY cell.
                // XXXX I think that this one actually means the other side
                // is closed. If we see it IRL we should maybe ignore it.
                s.send(msg.try_into()?).await.map_err(|_| {
                    Error::InternalError("Circuit queue rejected message. Is it closing?".into())
                })
            }
            Some(CircEnt::Opening(_, _)) => Err(Error::ChanProto(
                "Relay cell on pending circuit before CREATED* received".into(),
            )),
            Some(CircEnt::DestroySent(hs)) => hs.receive_cell(),
            None => Err(Error::ChanProto("Relay cell on nonexistent circuit".into())),
        }
    }

    /// Handle a CREATED{,_FAST,2} cell by passing it on to the appropriate
    /// circuit, if that circuit is waiting for one.
    async fn deliver_created(&mut self, circid: CircId, msg: ChanMsg) -> Result<()> {
        let target = self.circs.advance_from_opening(circid)?;
        let created = msg.try_into()?;
        // XXXX I think that this one actually means the other side
        // is closed
        target.send(created).map_err(|_| {
            Error::InternalError(
                "Circuit queue rejected created message. Is it closing? XXX".into(),
            )
        })
    }

    /// Handle a DESTROY cell by removing the corresponding circuit
    /// from the map, and passing the destroy cell onward to the circuit.
    async fn deliver_destroy(&mut self, circid: CircId, msg: ChanMsg) -> Result<()> {
        // Remove the circuit from the map: nothing more can be done with it.
        let entry = self.circs.remove(circid);
        match entry {
            // If the circuit is waiting for CREATED, tell it that it
            // won't get one.
            Some(CircEnt::Opening(oneshot, _)) => {
                trace!(
                    "{}: Passing destroy to pending circuit {}",
                    self.unique_id,
                    circid
                );
                oneshot
                    .send(msg.try_into()?)
                    // XXXX I think that this one actually means the other side
                    // is closed
                    .map_err(|_| {
                        Error::InternalError(
                            "pending circuit wasn't interested in Destroy cell?".into(),
                        )
                    })
            }
            // It's an open circuit: tell it that it got a DESTROY cell.
            Some(CircEnt::Open(mut sink)) => {
                trace!(
                    "{}: Passing destroy to open circuit {}",
                    self.unique_id,
                    circid
                );
                sink.send(msg.try_into()?)
                    .await
                    // XXXX I think that this one actually means the other side
                    // is closed
                    .map_err(|_| {
                        Error::InternalError("circuit wasn't interested in destroy cell?".into())
                    })
            }
            // We've sent a destroy; we can leave this circuit removed.
            Some(CircEnt::DestroySent(_)) => Ok(()),
            // Got a DESTROY cell for a circuit we don't have.
            None => {
                trace!(
                    "{}: Destroy for nonexistent circuit {}",
                    self.unique_id,
                    circid
                );
                Err(Error::ChanProto("Destroy for nonexistent circuit".into()))
            }
        }
    }

    /// Helper: send a cell on the outbound sink.
    async fn send_cell(&mut self, cell: ChanCell) -> Result<()> {
        self.output.send(cell).await?;
        Ok(())
    }

    /// Called when a circuit goes away: sends a DESTROY cell and removes
    /// the circuit.
    async fn outbound_destroy_circ(&mut self, id: CircId) -> Result<()> {
        trace!(
            "{}: Circuit {} is gone; sending DESTROY",
            self.unique_id,
            id
        );
        // Remove the circuit's entry from the map: nothing more
        // can be done with it.
        // TODO: It would be great to have a tighter upper bound for
        // the number of relay cells we'll receive.
        self.circs.destroy_sent(id, HalfCirc::new(3000));
        let destroy = Destroy::new(DestroyReason::NONE).into();
        let cell = ChanCell::new(id, destroy);
        self.send_cell(cell).await?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use tokio::test as async_test;
    use tokio_crate as tokio;

    use crate::circuit::CircParameters;

    type CodecResult = std::result::Result<ChanCell, tor_cell::Error>;

    pub(crate) fn new_reactor() -> (
        crate::channel::Channel,
        Reactor,
        mpsc::Receiver<ChanCell>,
        mpsc::Sender<CodecResult>,
    ) {
        let link_protocol = 4;
        let (send1, recv1) = mpsc::channel(32);
        let (send2, recv2) = mpsc::channel(32);
        let unique_id = UniqId::new();
        let ed_id = [6; 32].into();
        let rsa_id = [10; 20].into();
        let send1 = send1.sink_map_err(|e| {
            eprintln!("got sink error: {}", e);
            tor_cell::Error::ChanProto("dummy message".into())
        });
        let (chan, reactor) = crate::channel::Channel::new(
            link_protocol,
            Box::new(send1),
            Box::new(recv2),
            unique_id,
            ed_id,
            rsa_id,
        );
        (chan, reactor, recv1, send2)
    }

    // Try shutdown from inside run_once..
    #[async_test]
    async fn shutdown() {
        let (chan, mut reactor, _output, _input) = new_reactor();

        chan.terminate();
        let r = reactor.run_once().await;
        assert!(matches!(r, Err(ReactorError::Shutdown)));
    }

    // Try shutdown while reactor is running.
    #[async_test]
    async fn shutdown2() {
        // TODO: Ask a rust person if this is how to do this.
        use futures::future::FutureExt;
        use futures::join;

        let (chan, reactor, _output, _input) = new_reactor();
        // Let's get the reactor running...
        let run_reactor = reactor.run().map(|x| x.is_ok()).shared();

        let rr = run_reactor.clone();

        let exit_then_check = async {
            assert!(rr.peek().is_none());
            // ... and terminate the channel while that's happening.
            chan.terminate();
        };

        let (rr_s, _) = join!(run_reactor, exit_then_check);

        // Now let's see. The reactor should not _still_ be running.
        assert!(rr_s);
    }

    #[async_test]
    async fn new_circ_closed() {
        let (chan, mut reactor, mut output, _input) = new_reactor();

        let (ret, reac) = futures::join!(chan.new_circ(), reactor.run_once());
        let (pending, _circr) = ret.unwrap();
        assert!(reac.is_ok());

        let id = pending.peek_circid().await;

        let ent = reactor.circs.get_mut(id);
        assert!(matches!(ent, Some(CircEnt::Opening(_, _))));
        // Now drop the circuit; this should tell the reactor to remove
        // the circuit from the map.
        drop(pending);

        reactor.run_once().await.unwrap();
        let ent = reactor.circs.get_mut(id);
        assert!(matches!(ent, Some(CircEnt::DestroySent(_))));
        let cell = output.next().await.unwrap();
        assert_eq!(cell.circid(), id);
        assert!(matches!(cell.msg(), ChanMsg::Destroy(_)));
    }

    // Test proper delivery of a created cell that doesn't make a channel
    #[async_test]
    async fn new_circ_create_failure() {
        use tor_cell::chancell::msg;
        let mut rng = rand::thread_rng();
        let (chan, mut reactor, mut output, mut input) = new_reactor();

        let (ret, reac) = futures::join!(chan.new_circ(), reactor.run_once());
        let (pending, _circr) = ret.unwrap();
        assert!(reac.is_ok());

        let circparams = CircParameters::default();

        let id = pending.peek_circid().await;

        let ent = reactor.circs.get_mut(id);
        assert!(matches!(ent, Some(CircEnt::Opening(_, _))));
        // We'll get a bad handshake result from this createdfast cell.
        let created_cell = ChanCell::new(id, msg::CreatedFast::new(*b"x").into());
        input.send(Ok(created_cell)).await.unwrap();

        let (circ, reac) = futures::join!(
            pending.create_firsthop_fast(&mut rng, &circparams),
            reactor.run_once()
        );
        // Make sure statuses are as expected.
        assert!(matches!(circ.err().unwrap(), Error::BadHandshake));
        assert!(reac.is_ok());

        // Make sure that the createfast cell got sent
        let cell_sent = output.next().await.unwrap();
        assert!(matches!(cell_sent.msg(), msg::ChanMsg::CreateFast(_)));

        // The circid now counts as open, since as far as the reactor knows,
        // it was accepted.  (TODO: is this a bug?)
        let ent = reactor.circs.get_mut(id);
        assert!(matches!(ent, Some(CircEnt::Open(_))));

        // But the next run if the reactor will make the circuit get closed.
        reactor.run_once().await.unwrap();
        let ent = reactor.circs.get_mut(id);
        assert!(matches!(ent, Some(CircEnt::DestroySent(_))));
    }

    // Try incoming cells that shouldn't arrive on channels.
    #[async_test]
    async fn bad_cells() {
        use tor_cell::chancell::msg;
        let (_chan, mut reactor, _output, mut input) = new_reactor();

        // We shouldn't get create cells, ever.
        let create_cell = msg::Create2::new(4, *b"hihi").into();
        input
            .send(Ok(ChanCell::new(9.into(), create_cell)))
            .await
            .unwrap();

        // shouldn't get created2 cells for nonexistent circuits
        let created2_cell = msg::Created2::new(*b"hihi").into();
        input
            .send(Ok(ChanCell::new(7.into(), created2_cell)))
            .await
            .unwrap();

        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: CREATE2 cell on client channel"
        );

        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Unexpected CREATED* cell not on opening circuit"
        );

        // Can't get a relay cell on a circuit we've never heard of.
        let relay_cell = msg::Relay::new(b"abc").into();
        input
            .send(Ok(ChanCell::new(4.into(), relay_cell)))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Relay cell on nonexistent circuit"
        );

        // Can't get handshaking cells while channel is open.
        let versions_cell = msg::Versions::new([3]).unwrap().into();
        input
            .send(Ok(ChanCell::new(0.into(), versions_cell)))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: VERSIONS cell after handshake is done"
        );

        // We don't accept CREATED.
        let created_cell = msg::Created::new(&b"xyzzy"[..]).into();
        input
            .send(Ok(ChanCell::new(25.into(), created_cell)))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: CREATED cell received, but we never send CREATEs"
        );
    }

    #[async_test]
    async fn deliver_relay() {
        use crate::circuit::celltypes::ClientCircChanMsg;
        use futures::channel::oneshot;
        use tor_cell::chancell::msg;

        let (_chan, mut reactor, _output, mut input) = new_reactor();

        let (_circ_stream_7, mut circ_stream_13) = {
            let (snd1, _rcv1) = oneshot::channel();
            let (snd2, rcv2) = mpsc::channel(64);
            reactor
                .circs
                .put_unchecked(7.into(), CircEnt::Opening(snd1, snd2));

            let (snd3, rcv3) = mpsc::channel(64);
            reactor.circs.put_unchecked(13.into(), CircEnt::Open(snd3));

            reactor
                .circs
                .put_unchecked(23.into(), CircEnt::DestroySent(HalfCirc::new(25)));
            (rcv2, rcv3)
        };

        // If a relay cell is sent on an open channel, the correct circuit
        // should get it.
        let relaycell: ChanMsg = msg::Relay::new(b"do you suppose").into();
        input
            .send(Ok(ChanCell::new(13.into(), relaycell.clone())))
            .await
            .unwrap();
        reactor.run_once().await.unwrap();
        let got = circ_stream_13.next().await.unwrap();
        assert!(matches!(got, ClientCircChanMsg::Relay(_)));

        // If a relay cell is sent on an opening channel, that's an error.
        input
            .send(Ok(ChanCell::new(7.into(), relaycell.clone())))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Relay cell on pending circuit before CREATED* received"
        );

        // If a relay cell is sent on a non-existent channel, that's an error.
        input
            .send(Ok(ChanCell::new(101.into(), relaycell.clone())))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Relay cell on nonexistent circuit"
        );

        // It's fine to get a relay cell on a DestroySent channel: that happens
        // when the other side hasn't noticed the Destroy yet.

        // We can do this 25 more times according to our setup:
        for _ in 0..25 {
            input
                .send(Ok(ChanCell::new(23.into(), relaycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap(); // should be fine.
        }

        // This one will fail.
        input
            .send(Ok(ChanCell::new(23.into(), relaycell.clone())))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Too many cells received on destroyed circuit"
        );
    }

    #[async_test]
    async fn deliver_destroy() {
        use crate::circuit::celltypes::*;
        use futures::channel::oneshot;
        use tor_cell::chancell::msg;

        let (_chan, mut reactor, _output, mut input) = new_reactor();

        let (circ_oneshot_7, mut circ_stream_13) = {
            let (snd1, rcv1) = oneshot::channel();
            let (snd2, _rcv2) = mpsc::channel(64);
            reactor
                .circs
                .put_unchecked(7.into(), CircEnt::Opening(snd1, snd2));

            let (snd3, rcv3) = mpsc::channel(64);
            reactor.circs.put_unchecked(13.into(), CircEnt::Open(snd3));

            reactor
                .circs
                .put_unchecked(23.into(), CircEnt::DestroySent(HalfCirc::new(25)));
            (rcv1, rcv3)
        };

        // Destroying an opening circuit is fine.
        let destroycell: ChanMsg = msg::Destroy::new(0.into()).into();
        input
            .send(Ok(ChanCell::new(7.into(), destroycell.clone())))
            .await
            .unwrap();
        reactor.run_once().await.unwrap();
        let msg = circ_oneshot_7.await;
        assert!(matches!(msg, Ok(CreateResponse::Destroy(_))));

        // Destroying an open circuit is fine.
        input
            .send(Ok(ChanCell::new(13.into(), destroycell.clone())))
            .await
            .unwrap();
        reactor.run_once().await.unwrap();
        let msg = circ_stream_13.next().await.unwrap();
        assert!(matches!(msg, ClientCircChanMsg::Destroy(_)));

        // Destroying a DestroySent circuit is fine.
        input
            .send(Ok(ChanCell::new(23.into(), destroycell.clone())))
            .await
            .unwrap();
        reactor.run_once().await.unwrap();

        // Destroying a nonexistent circuit is an error.
        input
            .send(Ok(ChanCell::new(101.into(), destroycell.clone())))
            .await
            .unwrap();
        let e = reactor.run_once().await.unwrap_err().unwrap_err();
        assert_eq!(
            format!("{}", e),
            "channel protocol violation: Destroy for nonexistent circuit"
        );
    }
}
