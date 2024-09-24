//! Code to handle incoming cells on a channel.
//!
//! The role of this code is to run in a separate asynchronous task,
//! and routes cells to the right circuits.
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.

use super::circmap::{CircEnt, CircMap};
use super::OpenChanCellS2C;
use crate::channel::OpenChanMsgS2C;
use crate::circuit::halfcirc::HalfCirc;
use crate::util::err::{ChannelClosed, ReactorError};
use crate::{Error, Result};
use tor_async_utils::SinkPrepareExt as _;
use tor_cell::chancell::msg::{Destroy, DestroyReason, PaddingNegotiate};
use tor_cell::chancell::ChanMsg;
use tor_cell::chancell::{msg::AnyChanMsg, AnyChanCell, CircId};
use tor_memquota::mq_queue;
use tor_rtcompat::SleepProvider;

use futures::channel::mpsc;
use oneshot_fused_workaround as oneshot;

use futures::sink::SinkExt;
use futures::stream::Stream;
use futures::Sink;
use futures::StreamExt as _;
use futures::{select, select_biased};
use tor_error::internal;

use std::fmt;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::channel::{codec::CodecError, padding, params::*, unique_id, ChannelDetails};
use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use tracing::{debug, trace};

/// A boxed trait object that can provide `ChanCell`s.
pub(super) type BoxedChannelStream = Box<
    dyn Stream<Item = std::result::Result<OpenChanCellS2C, CodecError>> + Send + Unpin + 'static,
>;
/// A boxed trait object that can sink `ChanCell`s.
pub(super) type BoxedChannelSink =
    Box<dyn Sink<AnyChanCell, Error = CodecError> + Send + Unpin + 'static>;
/// The type of a oneshot channel used to inform reactor users of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

/// Convert `err` to an Error, under the assumption that it's happening on an
/// open channel.
fn codec_err_to_chan(err: CodecError) -> Error {
    match err {
        CodecError::Io(e) => crate::Error::ChanIoErr(Arc::new(e)),
        CodecError::EncCell(err) => Error::from_cell_enc(err, "channel cell"),
        CodecError::DecCell(err) => Error::from_cell_dec(err, "channel cell"),
    }
}

/// A message telling the channel reactor to do something.
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[derive(Debug)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
#[allow(clippy::exhaustive_enums)]
pub enum CtrlMsg {
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
    /// Enable/disable/reconfigure channel padding
    ///
    /// The sender of these messages is responsible for the optimisation of
    /// ensuring that "no-change" messages are elided.
    /// (This is implemented in `ChannelsParamsUpdatesBuilder`.)
    ///
    /// These updates are done via a control message to avoid adding additional branches to the
    /// main reactor `select!`.
    ConfigUpdate(Arc<ChannelPaddingInstructionsUpdates>),
}

/// Object to handle incoming cells and background tasks on a channel.
///
/// This type is returned when you finish a channel; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the channel won't work."]
pub struct Reactor<S: SleepProvider> {
    /// A receiver for control messages from `Channel` objects.
    pub(super) control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    pub(super) reactor_closed_tx: oneshot::Sender<void::Void>,
    /// A receiver for cells to be sent on this reactor's sink.
    ///
    /// `Channel` objects have a sender that can send cells here.
    pub(super) cells: mq_queue::Receiver<AnyChanCell, mq_queue::MpscSpec>,
    /// A Stream from which we can read `ChanCell`s.
    ///
    /// This should be backed by a TLS connection if you want it to be secure.
    pub(super) input: futures::stream::Fuse<BoxedChannelStream>,
    /// A Sink to which we can write `ChanCell`s.
    ///
    /// This should also be backed by a TLS connection if you want it to be secure.
    pub(super) output: BoxedChannelSink,
    /// Timer tracking when to generate channel padding
    pub(super) padding_timer: Pin<Box<padding::Timer<S>>>,
    /// Outgoing cells introduced at the channel reactor
    pub(super) special_outgoing: SpecialOutgoing,
    /// A map from circuit ID to Sinks on which we can deliver cells.
    pub(super) circs: CircMap,
    /// A unique identifier for this channel.
    pub(super) unique_id: super::UniqId,
    /// Information shared with the frontend
    pub(super) details: Arc<ChannelDetails>,
    /// Context for allocating unique circuit log identifiers.
    pub(super) circ_unique_id_ctx: unique_id::CircUniqIdContext,
    /// What link protocol is the channel using?
    #[allow(dead_code)] // We don't support protocols where this would matter
    pub(super) link_protocol: u16,
}

/// Outgoing cells introduced at the channel reactor
#[derive(Default, Debug, Clone)]
pub(super) struct SpecialOutgoing {
    /// If we must send a `PaddingNegotiate`
    pub(super) padding_negotiate: Option<PaddingNegotiate>,
}

impl SpecialOutgoing {
    /// Do we have a special cell to send?
    ///
    /// Called by the reactor before looking for cells from the reactor's clients.
    /// The returned message *must* be sent by the caller, not dropped!
    #[must_use = "SpecialOutgoing::next()'s return value must be actually sent"]
    pub(super) fn next(&mut self) -> Option<AnyChanCell> {
        // If this gets more cases, consider making SpecialOutgoing into a #[repr(C)]
        // enum, so that we can fast-path the usual case of "no special message to send".
        if let Some(p) = self.padding_negotiate.take() {
            return Some(p.into());
        }
        None
    }
}

/// Allows us to just say debug!("{}: Reactor did a thing", &self, ...)
///
/// There is no risk of confusion because no-one would try to print a
/// Reactor for some other reason.
impl<S: SleepProvider> fmt::Display for Reactor<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.unique_id, f)
    }
}

impl<S: SleepProvider> Reactor<S> {
    /// Launch the reactor, and run until the channel closes or we
    /// encounter an error.
    ///
    /// Once this function returns, the channel is dead, and can't be
    /// used again.
    pub async fn run(mut self) -> Result<()> {
        if self.details.closed.load(Ordering::SeqCst) {
            return Err(ChannelClosed.into());
        }
        trace!("{}: Running reactor", &self);
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        debug!("{}: Reactor stopped: {:?}", &self, result);
        self.details.closed.store(true, Ordering::SeqCst);
        result
    }

    /// Helper for run(): handles only one action, and doesn't mark
    /// the channel closed on finish.
    async fn run_once(&mut self) -> std::result::Result<(), ReactorError> {
        select! {

            // See if the output sink can have cells written to it yet.
            // If so, see if we have to-be-transmitted cells.
            ret = self.output.prepare_send_from(async {
                // This runs if we will be able to write, so try to obtain a cell:

                if let Some(l) = self.special_outgoing.next() {
                    // See reasoning below.
                    // eprintln!("PADDING - SENDING NEOGIATION: {:?}", &l);
                    self.padding_timer.as_mut().note_cell_sent();
                    return Some(l)
                }

                select_biased! {
                    n = self.cells.next() => {
                        // Note transmission on *input* to the reactor, not ultimate
                        // transmission.  Ideally we would tap into the TCP stream at the far
                        // end of our TLS or perhaps during encoding on entry to the TLS, but
                        // both of those would involve quite some plumbing.  Doing it here in
                        // the reactor avoids additional inter-task communication, mutexes,
                        // etc.  (And there is no real difference between doing it here on
                        // input, to just below, on enquieing into the `sendable`.)
                        //
                        // Padding is sent when the output channel is idle, and the effect of
                        // buffering is just that we might sent it a little early because we
                        // measure idleness when we last put something into the output layers.
                        //
                        // We can revisit this if measurement shows it to be bad in practice.
                        //
                        // (We in any case need padding that we generate when idle to make it
                        // through to the output promptly, or it will be late and ineffective.)
                        self.padding_timer.as_mut().note_cell_sent();
                        n
                    },
                    p = self.padding_timer.as_mut().next() => {
                        // eprintln!("PADDING - SENDING PADDING: {:?}", &p);
                        Some(p.into())
                    },
                }
            }) => {
                let (msg, sendable) = ret.map_err(codec_err_to_chan)?;
                let msg = msg.ok_or(ReactorError::Shutdown)?;
                sendable.send(msg).map_err(codec_err_to_chan)?;
            }

            ret = self.control.next() => {
                let ctrl = match ret {
                    None | Some(CtrlMsg::Shutdown) => return Err(ReactorError::Shutdown),
                    Some(x) => x,
                };
                self.handle_control(ctrl).await?;
            }

            ret = self.input.next() => {
                let item = ret
                    .ok_or(ReactorError::Shutdown)?
                    .map_err(codec_err_to_chan)?;
                crate::note_incoming_traffic();
                self.handle_cell(item).await?;
            }

        }
        Ok(()) // Run again.
    }

    /// Handle a CtrlMsg other than Shutdown.
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        trace!("{}: reactor received {:?}", &self, msg);
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
                self.update_disused_since();
            }
            CtrlMsg::ConfigUpdate(updates) => {
                if self.link_protocol == 4 {
                    // Link protocol 4 does not permit sending, or negotiating, link padding.
                    // We test for == 4 so that future updates to handshake.rs LINK_PROTOCOLS
                    // keep doing padding things.
                    return Ok(());
                }

                let ChannelPaddingInstructionsUpdates {
                    // List all the fields explicitly; that way the compiler will warn us
                    // if one is added and we fail to handle it here.
                    padding_enable,
                    padding_parameters,
                    padding_negotiate,
                } = &*updates;
                if let Some(parameters) = padding_parameters {
                    self.padding_timer.as_mut().reconfigure(parameters);
                }
                if let Some(enable) = padding_enable {
                    if *enable {
                        self.padding_timer.as_mut().enable();
                    } else {
                        self.padding_timer.as_mut().disable();
                    }
                }
                if let Some(padding_negotiate) = padding_negotiate {
                    // This replaces any previous PADDING_NEGOTIATE cell that we were
                    // told to send, but which we didn't manage to send yet.
                    // It doesn't make sense to queue them up.
                    self.special_outgoing.padding_negotiate = Some(padding_negotiate.clone());
                }
            }
        }
        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cell types get ignored
    /// or rejected; a few get delivered to circuits.
    async fn handle_cell(&mut self, cell: OpenChanCellS2C) -> Result<()> {
        let (circid, msg) = cell.into_circid_and_msg();
        use OpenChanMsgS2C::*;

        match msg {
            Relay(_) | Padding(_) | Vpadding(_) => {} // too frequent to log.
            _ => trace!(
                "{}: received {} for {}",
                &self,
                msg.cmd(),
                CircId::get_or_zero(circid)
            ),
        }

        match msg {
            // These are allowed, and need to be handled.
            Relay(_) => self.deliver_relay(circid, msg.into()).await,

            Destroy(_) => self.deliver_destroy(circid, msg.into()).await,

            CreatedFast(_) | Created2(_) => self.deliver_created(circid, msg.into()).await,

            // These are always ignored.
            Padding(_) | Vpadding(_) => Ok(()),
        }
    }

    /// Give the RELAY cell `msg` to the appropriate circuit.
    async fn deliver_relay(&mut self, circid: Option<CircId>, msg: AnyChanMsg) -> Result<()> {
        let Some(circid) = circid else {
            return Err(Error::ChanProto("Relay cell without circuit ID".into()));
        };

        let mut ent = self
            .circs
            .get_mut(circid)
            .ok_or_else(|| Error::ChanProto("Relay cell on nonexistent circuit".into()))?;

        match &mut *ent {
            CircEnt::Open(s) => {
                // There's an open circuit; we can give it the RELAY cell.
                if s.send(msg.try_into()?).await.is_err() {
                    drop(ent);
                    // The circuit's receiver went away, so we should destroy the circuit.
                    self.outbound_destroy_circ(circid).await?;
                }
                Ok(())
            }
            CircEnt::Opening(_, _) => Err(Error::ChanProto(
                "Relay cell on pending circuit before CREATED* received".into(),
            )),
            CircEnt::DestroySent(hs) => hs.receive_cell(),
        }
    }

    /// Handle a CREATED{,_FAST,2} cell by passing it on to the appropriate
    /// circuit, if that circuit is waiting for one.
    async fn deliver_created(&mut self, circid: Option<CircId>, msg: AnyChanMsg) -> Result<()> {
        let Some(circid) = circid else {
            return Err(Error::ChanProto("'Created' cell without circuit ID".into()));
        };

        let target = self.circs.advance_from_opening(circid)?;
        let created = msg.try_into()?;
        // TODO(nickm) I think that this one actually means the other side
        // is closed. See arti#269.
        target.send(created).map_err(|_| {
            Error::from(internal!(
                "Circuit queue rejected created message. Is it closing?"
            ))
        })
    }

    /// Handle a DESTROY cell by removing the corresponding circuit
    /// from the map, and passing the destroy cell onward to the circuit.
    async fn deliver_destroy(&mut self, circid: Option<CircId>, msg: AnyChanMsg) -> Result<()> {
        let Some(circid) = circid else {
            return Err(Error::ChanProto("'Destroy' cell without circuit ID".into()));
        };

        // Remove the circuit from the map: nothing more can be done with it.
        let entry = self.circs.remove(circid);
        self.update_disused_since();
        match entry {
            // If the circuit is waiting for CREATED, tell it that it
            // won't get one.
            Some(CircEnt::Opening(oneshot, _)) => {
                trace!("{}: Passing destroy to pending circuit {}", &self, circid);
                oneshot
                    .send(msg.try_into()?)
                    // TODO(nickm) I think that this one actually means the other side
                    // is closed. See arti#269.
                    .map_err(|_| {
                        internal!("pending circuit wasn't interested in destroy cell?").into()
                    })
            }
            // It's an open circuit: tell it that it got a DESTROY cell.
            Some(CircEnt::Open(mut sink)) => {
                trace!("{}: Passing destroy to open circuit {}", &self, circid);
                sink.send(msg.try_into()?)
                    .await
                    // TODO(nickm) I think that this one actually means the other side
                    // is closed. See arti#269.
                    .map_err(|_| {
                        internal!("open circuit wasn't interested in destroy cell?").into()
                    })
            }
            // We've sent a destroy; we can leave this circuit removed.
            Some(CircEnt::DestroySent(_)) => Ok(()),
            // Got a DESTROY cell for a circuit we don't have.
            None => {
                trace!("{}: Destroy for nonexistent circuit {}", &self, circid);
                Err(Error::ChanProto("Destroy for nonexistent circuit".into()))
            }
        }
    }

    /// Helper: send a cell on the outbound sink.
    async fn send_cell(&mut self, cell: AnyChanCell) -> Result<()> {
        self.output.send(cell).await.map_err(codec_err_to_chan)?;
        Ok(())
    }

    /// Called when a circuit goes away: sends a DESTROY cell and removes
    /// the circuit.
    async fn outbound_destroy_circ(&mut self, id: CircId) -> Result<()> {
        trace!("{}: Circuit {} is gone; sending DESTROY", &self, id);
        // Remove the circuit's entry from the map: nothing more
        // can be done with it.
        // TODO: It would be great to have a tighter upper bound for
        // the number of relay cells we'll receive.
        self.circs.destroy_sent(id, HalfCirc::new(3000));
        self.update_disused_since();
        let destroy = Destroy::new(DestroyReason::NONE).into();
        let cell = AnyChanCell::new(Some(id), destroy);
        self.send_cell(cell).await?;

        Ok(())
    }

    /// Update disused timestamp with current time if this channel is no longer used
    fn update_disused_since(&self) {
        if self.circs.open_ent_count() == 0 {
            // Update disused_since if it still indicates that the channel is in use
            self.details.unused_since.update_if_none();
        } else {
            // Mark this channel as in use
            self.details.unused_since.clear();
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::channel::UniqId;
    use crate::circuit::CircParameters;
    use crate::util::fake_mq;
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures::task::SpawnExt;
    use tor_linkspec::OwnedChanTarget;
    use tor_rtcompat::Runtime;

    type CodecResult = std::result::Result<OpenChanCellS2C, CodecError>;

    pub(crate) fn new_reactor<R: Runtime>(
        runtime: R,
    ) -> (
        Arc<crate::channel::Channel>,
        Reactor<R>,
        mpsc::Receiver<AnyChanCell>,
        mpsc::Sender<CodecResult>,
    ) {
        let link_protocol = 4;
        let (send1, recv1) = mpsc::channel(32);
        let (send2, recv2) = mpsc::channel(32);
        let unique_id = UniqId::new();
        let dummy_target = OwnedChanTarget::builder()
            .ed_identity([6; 32].into())
            .rsa_identity([10; 20].into())
            .build()
            .unwrap();
        let send1 = send1.sink_map_err(|e| {
            trace!("got sink error: {:?}", e);
            CodecError::DecCell(tor_cell::Error::ChanProto("dummy message".into()))
        });
        let (chan, reactor) = crate::channel::Channel::new(
            link_protocol,
            Box::new(send1),
            Box::new(recv2),
            unique_id,
            dummy_target,
            crate::ClockSkew::None,
            runtime,
            fake_mq(),
        )
        .expect("channel create failed");
        (chan, reactor, recv1, send2)
    }

    // Try shutdown from inside run_once..
    #[test]
    fn shutdown() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut reactor, _output, _input) = new_reactor(rt);

            chan.terminate();
            let r = reactor.run_once().await;
            assert!(matches!(r, Err(ReactorError::Shutdown)));
        });
    }

    // Try shutdown while reactor is running.
    #[test]
    fn shutdown2() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            // TODO: Ask a rust person if this is how to do this.

            use futures::future::FutureExt;
            use futures::join;

            let (chan, reactor, _output, _input) = new_reactor(rt);
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
        });
    }

    #[test]
    fn new_circ_closed() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut reactor, mut output, _input) = new_reactor(rt.clone());
            assert!(chan.duration_unused().is_some()); // unused yet

            let (ret, reac) = futures::join!(chan.new_circ(), reactor.run_once());
            let (pending, circr) = ret.unwrap();
            rt.spawn(async {
                let _ignore = circr.run().await;
            })
            .unwrap();
            assert!(reac.is_ok());

            let id = pending.peek_circid();

            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::Opening(_, _)));
            assert!(chan.duration_unused().is_none()); // in use

            // Now drop the circuit; this should tell the reactor to remove
            // the circuit from the map.
            drop(pending);

            reactor.run_once().await.unwrap();
            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::DestroySent(_)));
            let cell = output.next().await.unwrap();
            assert_eq!(cell.circid(), Some(id));
            assert!(matches!(cell.msg(), AnyChanMsg::Destroy(_)));
            assert!(chan.duration_unused().is_some()); // unused again
        });
    }

    // Test proper delivery of a created cell that doesn't make a channel
    #[test]
    #[ignore] // See bug #244: re-enable this test once it passes reliably.
    fn new_circ_create_failure() {
        use std::time::Duration;
        use tor_rtcompat::SleepProvider;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            use tor_cell::chancell::msg;
            let (chan, mut reactor, mut output, mut input) = new_reactor(rt.clone());

            let (ret, reac) = futures::join!(chan.new_circ(), reactor.run_once());
            let (pending, circr) = ret.unwrap();
            rt.spawn(async {
                let _ignore = circr.run().await;
            })
            .unwrap();
            assert!(reac.is_ok());

            let circparams = CircParameters::default();

            let id = pending.peek_circid();

            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::Opening(_, _)));

            #[allow(clippy::clone_on_copy)]
            let rtc = rt.clone();
            let send_response = async {
                rtc.sleep(Duration::from_millis(100)).await;
                trace!("sending createdfast");
                // We'll get a bad handshake result from this createdfast cell.
                let created_cell =
                    OpenChanCellS2C::new(Some(id), msg::CreatedFast::new(*b"x").into());
                input.send(Ok(created_cell)).await.unwrap();
                reactor.run_once().await.unwrap();
            };

            let (circ, _) =
                futures::join!(pending.create_firsthop_fast(&circparams), send_response);
            // Make sure statuses are as expected.
            assert!(matches!(circ.err().unwrap(), Error::BadCircHandshakeAuth));

            reactor.run_once().await.unwrap();

            // Make sure that the createfast cell got sent
            let cell_sent = output.next().await.unwrap();
            assert!(matches!(cell_sent.msg(), msg::AnyChanMsg::CreateFast(_)));

            // But the next run if the reactor will make the circuit get closed.
            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::DestroySent(_)));
        });
    }

    // Try incoming cells that shouldn't arrive on channels.
    #[test]
    fn bad_cells() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            use tor_cell::chancell::msg;
            let (_chan, mut reactor, _output, mut input) = new_reactor(rt);

            // shouldn't get created2 cells for nonexistent circuits
            let created2_cell = msg::Created2::new(*b"hihi").into();
            input
                .send(Ok(OpenChanCellS2C::new(CircId::new(7), created2_cell)))
                .await
                .unwrap();

            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Unexpected CREATED* cell not on opening circuit"
            );

            // Can't get a relay cell on a circuit we've never heard of.
            let relay_cell = msg::Relay::new(b"abc").into();
            input
                .send(Ok(OpenChanCellS2C::new(CircId::new(4), relay_cell)))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Relay cell on nonexistent circuit"
            );

            // There used to be tests here for other types, but now that we only
            // accept OpenClientChanCell, we know that the codec can't even try
            // to give us e.g. VERSIONS or CREATE.
        });
    }

    #[test]
    fn deliver_relay() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            use crate::circuit::celltypes::ClientCircChanMsg;
            use oneshot_fused_workaround as oneshot;
            use tor_cell::chancell::msg;

            let (_chan, mut reactor, _output, mut input) = new_reactor(rt);

            let (_circ_stream_7, mut circ_stream_13) = {
                let (snd1, _rcv1) = oneshot::channel();
                let (snd2, rcv2) = mpsc::channel(64);
                reactor
                    .circs
                    .put_unchecked(CircId::new(7).unwrap(), CircEnt::Opening(snd1, snd2));

                let (snd3, rcv3) = mpsc::channel(64);
                reactor
                    .circs
                    .put_unchecked(CircId::new(13).unwrap(), CircEnt::Open(snd3));

                reactor.circs.put_unchecked(
                    CircId::new(23).unwrap(),
                    CircEnt::DestroySent(HalfCirc::new(25)),
                );
                (rcv2, rcv3)
            };

            // If a relay cell is sent on an open channel, the correct circuit
            // should get it.
            let relaycell: OpenChanMsgS2C = msg::Relay::new(b"do you suppose").into();
            input
                .send(Ok(OpenChanCellS2C::new(CircId::new(13), relaycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let got = circ_stream_13.next().await.unwrap();
            assert!(matches!(got, ClientCircChanMsg::Relay(_)));

            // If a relay cell is sent on an opening channel, that's an error.
            input
                .send(Ok(OpenChanCellS2C::new(CircId::new(7), relaycell.clone())))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
            format!("{}", e),
            "Channel protocol violation: Relay cell on pending circuit before CREATED* received"
        );

            // If a relay cell is sent on a non-existent channel, that's an error.
            input
                .send(Ok(OpenChanCellS2C::new(
                    CircId::new(101),
                    relaycell.clone(),
                )))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Relay cell on nonexistent circuit"
            );

            // It's fine to get a relay cell on a DestroySent channel: that happens
            // when the other side hasn't noticed the Destroy yet.

            // We can do this 25 more times according to our setup:
            for _ in 0..25 {
                input
                    .send(Ok(OpenChanCellS2C::new(CircId::new(23), relaycell.clone())))
                    .await
                    .unwrap();
                reactor.run_once().await.unwrap(); // should be fine.
            }

            // This one will fail.
            input
                .send(Ok(OpenChanCellS2C::new(CircId::new(23), relaycell.clone())))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Too many cells received on destroyed circuit"
            );
        });
    }

    #[test]
    fn deliver_destroy() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            use crate::circuit::celltypes::*;
            use oneshot_fused_workaround as oneshot;
            use tor_cell::chancell::msg;

            let (_chan, mut reactor, _output, mut input) = new_reactor(rt);

            let (circ_oneshot_7, mut circ_stream_13) = {
                let (snd1, rcv1) = oneshot::channel();
                let (snd2, _rcv2) = mpsc::channel(64);
                reactor
                    .circs
                    .put_unchecked(CircId::new(7).unwrap(), CircEnt::Opening(snd1, snd2));

                let (snd3, rcv3) = mpsc::channel(64);
                reactor
                    .circs
                    .put_unchecked(CircId::new(13).unwrap(), CircEnt::Open(snd3));

                reactor.circs.put_unchecked(
                    CircId::new(23).unwrap(),
                    CircEnt::DestroySent(HalfCirc::new(25)),
                );
                (rcv1, rcv3)
            };

            // Destroying an opening circuit is fine.
            let destroycell: OpenChanMsgS2C = msg::Destroy::new(0.into()).into();
            input
                .send(Ok(OpenChanCellS2C::new(
                    CircId::new(7),
                    destroycell.clone(),
                )))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let msg = circ_oneshot_7.await;
            assert!(matches!(msg, Ok(CreateResponse::Destroy(_))));

            // Destroying an open circuit is fine.
            input
                .send(Ok(OpenChanCellS2C::new(
                    CircId::new(13),
                    destroycell.clone(),
                )))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let msg = circ_stream_13.next().await.unwrap();
            assert!(matches!(msg, ClientCircChanMsg::Destroy(_)));

            // Destroying a DestroySent circuit is fine.
            input
                .send(Ok(OpenChanCellS2C::new(
                    CircId::new(23),
                    destroycell.clone(),
                )))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();

            // Destroying a nonexistent circuit is an error.
            input
                .send(Ok(OpenChanCellS2C::new(
                    CircId::new(101),
                    destroycell.clone(),
                )))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Destroy for nonexistent circuit"
            );
        });
    }
}
