//! Code to handle incoming cells on a channel.
//!
//! The role of this code is to run in a separate asynchronous task,
//! and routes cells to the right circuits.
//!
//! TODO: I have zero confidence in the close-and-cleanup behavior here,
//! or in the error handling behavior.

use super::circmap::{CircEnt, CircMap};
use crate::circuit::CircuitRxSender;
use crate::client::circuit::halfcirc::HalfCirc;
use crate::client::circuit::padding::{
    PaddingController, PaddingEvent, PaddingEventStream, SendPadding, StartBlocking,
};
use crate::util::err::ReactorError;
use crate::util::oneshot_broadcast;
use crate::{Error, HopNum, Result};
use tor_async_utils::SinkPrepareExt as _;
use tor_cell::chancell::ChanMsg;
use tor_cell::chancell::msg::{Destroy, DestroyReason, Padding, PaddingNegotiate};
use tor_cell::chancell::{AnyChanCell, CircId, msg::AnyChanMsg};
use tor_error::debug_report;
use tor_rtcompat::{CoarseTimeProvider, DynTimeProvider, SleepProvider};

#[cfg_attr(not(target_os = "linux"), allow(unused))]
use tor_error::error_report;
#[cfg_attr(not(target_os = "linux"), allow(unused))]
use tor_rtcompat::StreamOps;

use futures::channel::mpsc;
use oneshot_fused_workaround as oneshot;

use futures::Sink;
use futures::StreamExt as _;
use futures::sink::SinkExt;
use futures::stream::Stream;
use futures::{select, select_biased};
use tor_error::internal;

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use crate::channel::{ChannelDetails, CloseInfo, kist::KistParams, padding, params::*, unique_id};
use crate::circuit::celltypes::CreateResponse;
use tracing::{debug, instrument, trace};

/// A boxed trait object that can provide `ChanCell`s.
pub(super) type BoxedChannelStream =
    Box<dyn Stream<Item = std::result::Result<AnyChanCell, Error>> + Send + Unpin + 'static>;
/// A boxed trait object that can sink `ChanCell`s.
pub(super) type BoxedChannelSink =
    Box<dyn Sink<AnyChanCell, Error = Error> + Send + Unpin + 'static>;
/// A boxed trait object that can provide additional `StreamOps` on a `BoxedChannelStream`.
pub(super) type BoxedChannelStreamOps = Box<dyn StreamOps + Send + Unpin + 'static>;
/// The type of a oneshot channel used to inform reactor users of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

cfg_if::cfg_if! {
    if #[cfg(feature = "circ-padding")] {
        use crate::util::sink_blocker::{SinkBlocker, CountingPolicy};
        /// Type used by a channel reactor to send cells to the network.
        pub(super) type ChannelOutputSink = SinkBlocker<BoxedChannelSink, CountingPolicy>;
    } else {
        /// Type used by a channel reactor to send cells to the network.
        pub(super) type ChannelOutputSink = BoxedChannelSink;
    }
}

/// A message telling the channel reactor to do something.
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[derive(Debug)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
#[allow(clippy::exhaustive_enums, private_interfaces)]
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
        sender: CircuitRxSender,
        /// Oneshot channel to send the new circuit's identifiers down.
        tx: ReactorResultChannel<(
            CircId,
            crate::circuit::UniqId,
            PaddingController,
            PaddingEventStream,
        )>,
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
    /// Enable/disable/reconfigure KIST.
    ///
    /// Like in the case of `ConfigUpdate`,
    /// the sender of these messages is responsible for the optimisation of
    /// ensuring that "no-change" messages are elided.
    KistConfigUpdate(KistParams),
    /// Change the current padding implementation to the one provided.
    #[cfg(feature = "circ-padding-manual")]
    SetChannelPadder {
        /// The padder to install, or None to remove any existing padder.
        padder: Option<crate::client::CircuitPadder>,
        /// A oneshot channel to use in reporting the outcome.
        sender: oneshot::Sender<Result<()>>,
    },
}

/// Object to handle incoming cells and background tasks on a channel.
///
/// This type is returned when you finish a channel; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the channel won't work."]
pub struct Reactor<S: SleepProvider + CoarseTimeProvider> {
    /// Underlying runtime we use for generating sleep futures and telling time.
    pub(super) runtime: S,
    /// A receiver for control messages from `Channel` objects.
    pub(super) control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    pub(super) reactor_closed_tx: oneshot_broadcast::Sender<Result<CloseInfo>>,
    /// A receiver for cells to be sent on this reactor's sink.
    ///
    /// `Channel` objects have a sender that can send cells here.
    pub(super) cells: super::CellRx,
    /// A Stream from which we can read `ChanCell`s.
    ///
    /// This should be backed by a TLS connection if you want it to be secure.
    pub(super) input: futures::stream::Fuse<BoxedChannelStream>,
    /// A Sink to which we can write `ChanCell`s.
    ///
    /// This should also be backed by a TLS connection if you want it to be secure.
    pub(super) output: ChannelOutputSink,
    /// A handler for setting stream options on the underlying stream.
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    pub(super) streamops: BoxedChannelStreamOps,
    /// Timer tracking when to generate channel padding.
    ///
    /// Note that this is _distinct_ from the experimental maybenot-based padding
    /// implemented with padding_ctrl and padding_stream.
    /// This is the existing per-channel padding
    /// in the tor protocol used to resist netflow attacks.
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
    /// A padding controller to which padding-related events should be reported.
    ///
    /// (This is used for experimental maybenot-based padding.)
    //
    // TODO: It would be good to use S here instead of DynTimeProvider,
    // but we still need the latter for the clones of padding_ctrl that we hand out
    // inside ChannelSender.
    pub(super) padding_ctrl: PaddingController<DynTimeProvider>,
    /// An event stream telling us about padding-related events.
    ///
    /// (This is used for experimental maybenot-based padding.)
    pub(super) padding_event_stream: PaddingEventStream<DynTimeProvider>,
    /// If present, the current rules for blocking the output based on the padding framework.
    pub(super) padding_blocker: Option<StartBlocking>,
    /// What link protocol is the channel using?
    #[allow(dead_code)] // We don't support protocols where this would matter
    pub(super) link_protocol: u16,
}

/// Outgoing cells introduced at the channel reactor
#[derive(Default, Debug, Clone)]
pub(super) struct SpecialOutgoing {
    /// If we must send a `PaddingNegotiate`, this is present.
    padding_negotiate: Option<PaddingNegotiate>,
    /// A number of pending PADDING cells that we have to send, once there is space.
    n_padding: u16,
}

impl SpecialOutgoing {
    /// Do we have a special cell to send?
    ///
    /// Called by the reactor before looking for cells from the reactor's clients.
    /// The returned message *must* be sent by the caller, not dropped!
    #[must_use = "SpecialOutgoing::next()'s return value must be actually sent"]
    fn next(&mut self) -> Option<AnyChanCell> {
        // If this gets more cases, consider making SpecialOutgoing into a #[repr(C)]
        // enum, so that we can fast-path the usual case of "no special message to send".
        if let Some(p) = self.padding_negotiate.take() {
            return Some(p.into());
        }
        if self.n_padding > 0 {
            self.n_padding -= 1;
            return Some(Padding::new().into());
        }
        None
    }

    /// Try to queue a padding cell to be sent.
    fn queue_padding_cell(&mut self) {
        self.n_padding = self.n_padding.saturating_add(1);
    }
}

/// Allows us to just say debug!("{}: Reactor did a thing", &self, ...)
///
/// There is no risk of confusion because no-one would try to print a
/// Reactor for some other reason.
impl<S: SleepProvider + CoarseTimeProvider> fmt::Display for Reactor<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.unique_id, f)
    }
}

impl<S: SleepProvider + CoarseTimeProvider> Reactor<S> {
    /// Launch the reactor, and run until the channel closes or we
    /// encounter an error.
    ///
    /// Once this function returns, the channel is dead, and can't be
    /// used again.
    #[instrument(level = "trace", skip_all)]
    pub async fn run(mut self) -> Result<()> {
        trace!(channel_id = %self, "Running reactor");
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };

        // Log that the reactor stopped, possibly with the associated error as a report.
        // May log at a higher level depending on the error kind.
        const MSG: &str = "Reactor stopped";
        match &result {
            Ok(()) => debug!(channel_id = %self, "{MSG}"),
            Err(e) => debug_report!(e, channel_id = %self, "{MSG}"),
        }

        // Inform any waiters that the channel has closed.
        let close_msg = result.as_ref().map_err(Clone::clone).map(|()| CloseInfo);
        self.reactor_closed_tx.send(close_msg);
        result
    }

    /// Helper for run(): handles only one action.
    #[instrument(level = "trace", skip_all)]
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
                    return Some((l, None));
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

                        // Note that we treat padding from the padding_timer as a normal cell,
                        // since it doesn't have a padding machine.
                        self.padding_ctrl.queued_data(HopNum::from(0));

                        self.padding_timer.as_mut().note_cell_sent();
                        Some((p.into(), None))
                    },
                }
            }) => {
                self.padding_ctrl.flushed_channel_cell();
                let (queued, sendable) = ret?;
                let (msg, cell_padding_info) = queued.ok_or(ReactorError::Shutdown)?;
                // Tell the relevant circuit padder that this cell is getting flushed.
                // Note that, technically, it won't go onto the network for a while longer:
                // it has to go through the TLS buffer, and the kernel TCP buffer.
                // We've got to live with that.
                // TODO: conceivably we could defer this even longer, but it would take
                // some tricky hacking!
                if let (Some(cell_padding_info), Some(circid)) = (cell_padding_info, msg.circid()) {
                    self.circs.note_cell_flushed(circid, cell_padding_info);
                }
                sendable.send(msg)?;
            }

            ret = self.control.next() => {
                let ctrl = match ret {
                    None | Some(CtrlMsg::Shutdown) => return Err(ReactorError::Shutdown),
                    Some(x) => x,
                };
                self.handle_control(ctrl).await?;
            }

            ret = self.padding_event_stream.next() => {
                let event = ret.ok_or_else(|| Error::from(internal!("Padding event stream was exhausted")))?;
                self.handle_padding_event(event).await?;
            }

            ret = self.input.next() => {
                let item = ret
                    .ok_or(ReactorError::Shutdown)??;
                crate::note_incoming_traffic();
                self.handle_cell(item).await?;
            }

        }
        Ok(()) // Run again.
    }

    /// Handle a CtrlMsg other than Shutdown.
    #[instrument(level = "trace", skip(self))] // Intentionally omitting skip_all, msg is useful and not sensitive
    async fn handle_control(&mut self, msg: CtrlMsg) -> Result<()> {
        trace!(
            channel_id = %self,
            msg = ?msg,
            "reactor received control message"
        );

        match msg {
            CtrlMsg::Shutdown => panic!(), // was handled in reactor loop.
            CtrlMsg::CloseCircuit(id) => self.outbound_destroy_circ(id).await?,
            CtrlMsg::AllocateCircuit {
                created_sender,
                sender,
                tx,
            } => {
                let mut rng = rand::rng();
                let my_unique_id = self.unique_id;
                let circ_unique_id = self.circ_unique_id_ctx.next(my_unique_id);
                // NOTE: This is a very weird place to be calling new_padding, but:
                //  - we need to do it here or earlier, so we can add it as part of the CircEnt to
                //    our map.
                //  - We need to do it at some point where we have a runtime, which implies in a
                //    reactor.
                //
                // TODO circpad: We might want to lazy-allocate this somehow, or try harder to make
                // it a no-op when we aren't padding on a particular circuit.
                let (padding_ctrl, padding_stream) = crate::client::circuit::padding::new_padding(
                    // TODO: avoid using DynTimeProvider at some point, and re-parameterize for efficiency.
                    DynTimeProvider::new(self.runtime.clone()),
                );
                let ret: Result<_> = self
                    .circs
                    .add_ent(&mut rng, created_sender, sender, padding_ctrl.clone())
                    .map(|id| (id, circ_unique_id, padding_ctrl, padding_stream));
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
                    self.padding_timer.as_mut().reconfigure(parameters)?;
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
            CtrlMsg::KistConfigUpdate(kist) => self.apply_kist_params(&kist),
            #[cfg(feature = "circ-padding-manual")]
            CtrlMsg::SetChannelPadder { padder, sender } => {
                self.padding_ctrl
                    .install_padder_padding_at_hop(HopNum::from(0), padder);
                let _ignore = sender.send(Ok(()));
            }
        }
        Ok(())
    }

    /// Take the padding action described in `action`.
    ///
    /// (With circuit padding disabled, PaddingEvent can't be constructed.)
    #[cfg(not(feature = "circ-padding"))]
    async fn handle_padding_event(&mut self, action: PaddingEvent) -> Result<()> {
        void::unreachable(action.0)
    }

    /// Take the padding action described in `action`.
    #[cfg(feature = "circ-padding")]
    async fn handle_padding_event(&mut self, action: PaddingEvent) -> Result<()> {
        use PaddingEvent as PE;
        match action {
            PE::SendPadding(send_padding) => {
                self.handle_send_padding(send_padding).await?;
            }
            PE::StartBlocking(start_blocking) => {
                if self.output.is_unlimited() {
                    self.output.set_blocked();
                }
                self.padding_blocker = Some(start_blocking);
            }
            PE::StopBlocking => {
                self.output.set_unlimited();
            }
        }
        Ok(())
    }

    /// Send the padding described in `padding`.
    #[cfg(feature = "circ-padding")]
    async fn handle_send_padding(&mut self, padding: SendPadding) -> Result<()> {
        // TODO circpad: This is somewhat duplicative of the logic in `Circuit::send_padding` and
        // `Circuit::padding_disposition`.  It might be good to unify them at some point.
        // For now (Oct 2025), though, they have slightly different inputs and behaviors.

        use crate::client::circuit::padding::{Bypass::*, Replace::*};
        // multihop padding belongs in circuit padders, not here.
        let hop = HopNum::from(0);
        assert_eq!(padding.hop, hop);

        // If true, there is blocking, but we are allowed to bypass it.
        let blocking_bypassed = matches!(
            (&self.padding_blocker, padding.may_bypass_block()),
            (
                Some(StartBlocking {
                    is_bypassable: true
                }),
                BypassBlocking
            )
        );
        // If true, there is blocking, and we can't bypass it.
        let this_padding_blocked = self.padding_blocker.is_some() && !blocking_bypassed;

        if padding.may_replace_with_data() == Replaceable {
            if self.output_is_full().await? {
                // When the output buffer is full,
                // we _always_ treat it as satisfying our replaceable padding.
                //
                // TODO circpad: It would be better to check whether
                // the output has any bytes at all, but futures_codec doesn't seem to give us a
                // way to check that.  If we manage to do so in the future, we should change the
                // logic in this function.
                self.padding_ctrl
                    .replaceable_padding_already_queued(hop, padding);
                return Ok(());
            } else if self.cells.approx_count() > 0 {
                // We can replace the padding with outbound cells!
                if this_padding_blocked {
                    // In the blocked case, we just declare that the pending data _is_ the queued padding.
                    self.padding_ctrl
                        .replaceable_padding_already_queued(hop, padding);
                } else {
                    // Otherwise we report that queued data _became_ padding,
                    // and we allow it to pass any blocking that's present.
                    self.padding_ctrl.queued_data_as_padding(hop, padding);
                    if blocking_bypassed {
                        self.output.allow_n_additional_items(1);
                    }
                }
                return Ok(());
            } else {
                // There's nothing to replace this with, so fall through.
            }
        }

        // There's no replacement, so we queue unconditionally.
        self.special_outgoing.queue_padding_cell();
        self.padding_ctrl.queued_padding(hop, padding);
        if blocking_bypassed {
            self.output.allow_n_additional_items(1);
        }

        Ok(())
    }

    /// Return true if the output stream is full.
    ///
    /// We use this in circuit padding to implement replaceable padding.
    //
    // TODO circpad: We'd rather check whether there is any data at all queued in self.output,
    // but futures_codec doesn't give us a way to do that.
    #[cfg(feature = "circ-padding")]
    async fn output_is_full(&mut self) -> Result<bool> {
        use futures::future::poll_fn;
        use std::task::Poll;
        // We use poll_fn to get a cx that we can pass to poll_ready_unpin.
        poll_fn(|cx| {
            Poll::Ready(match self.output.poll_ready_unpin(cx) {
                // If if's ready to send, it isn't full.
                Poll::Ready(Ok(())) => Ok(false),
                // If it isn't ready to send, it's full.
                Poll::Pending => Ok(true),
                // Propagate errors:
                Poll::Ready(Err(e)) => Err(e),
            })
        })
        .await
    }

    /// Helper: process a cell on a channel.  Most cell types get ignored
    /// or rejected; a few get delivered to circuits.
    #[instrument(level = "trace", skip_all)]
    async fn handle_cell(&mut self, cell: AnyChanCell) -> Result<()> {
        let (circid, msg) = cell.into_circid_and_msg();
        use AnyChanMsg::*;

        match msg {
            Relay(_) | Padding(_) | Vpadding(_) => {} // too frequent to log.
            _ => trace!(
                channel_id = %self,
                "received {} for {}",
                msg.cmd(),
                CircId::get_or_zero(circid)
            ),
        }

        // Report the message to the padding controller.
        match msg {
            Padding(_) | Vpadding(_) => {
                // We always accept channel padding, even if we haven't negotiated any.
                let _always_acceptable = self.padding_ctrl.decrypted_padding(HopNum::from(0));
            }
            _ => self.padding_ctrl.decrypted_data(HopNum::from(0)),
        }

        match msg {
            // These are allowed, and need to be handled.
            Relay(_) => self.deliver_relay(circid, msg).await,

            Destroy(_) => self.deliver_destroy(circid, msg).await,

            CreatedFast(_) | Created2(_) => self.deliver_created(circid, msg).await,

            // These are always ignored.
            Padding(_) | Vpadding(_) => Ok(()),
            _ => Err(Error::ChanProto(format!("Unexpected cell: {msg:?}"))),
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
            CircEnt::Open { cell_sender: s, .. } => {
                // There's an open circuit; we can give it the RELAY cell.
                if s.send(msg).await.is_err() {
                    drop(ent);
                    // The circuit's receiver went away, so we should destroy the circuit.
                    self.outbound_destroy_circ(circid).await?;
                }
                Ok(())
            }
            CircEnt::Opening { .. } => Err(Error::ChanProto(
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
            Some(CircEnt::Opening {
                create_response_sender,
                ..
            }) => {
                trace!(channel_id = %self, "Passing destroy to pending circuit {}", circid);
                create_response_sender
                    .send(msg.try_into()?)
                    // TODO(nickm) I think that this one actually means the other side
                    // is closed. See arti#269.
                    .map_err(|_| {
                        internal!("pending circuit wasn't interested in destroy cell?").into()
                    })
            }
            // It's an open circuit: tell it that it got a DESTROY cell.
            Some(CircEnt::Open {
                mut cell_sender, ..
            }) => {
                trace!(channel_id = %self, "Passing destroy to open circuit {}", circid);
                cell_sender
                    .send(msg)
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
                trace!(channel_id = %self, "Destroy for nonexistent circuit {}", circid);
                Err(Error::ChanProto("Destroy for nonexistent circuit".into()))
            }
        }
    }

    /// Helper: send a cell on the outbound sink.
    async fn send_cell(&mut self, cell: AnyChanCell) -> Result<()> {
        self.output.send(cell).await?;
        Ok(())
    }

    /// Called when a circuit goes away: sends a DESTROY cell and removes
    /// the circuit.
    async fn outbound_destroy_circ(&mut self, id: CircId) -> Result<()> {
        trace!(channel_id = %self, "Circuit {} is gone; sending DESTROY", id);
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

    /// Use the new KIST parameters.
    #[cfg(target_os = "linux")]
    fn apply_kist_params(&self, params: &KistParams) {
        use super::kist::KistMode;

        let set_tcp_notsent_lowat = |v: u32| {
            if let Err(e) = self.streamops.set_tcp_notsent_lowat(v) {
                // This is bad, but not fatal: not setting the KIST options
                // comes with a performance penalty, but we don't have to crash.
                error_report!(e, "Failed to set KIST socket options");
            }
        };

        match params.kist_enabled() {
            KistMode::TcpNotSentLowat => set_tcp_notsent_lowat(params.tcp_notsent_lowat()),
            KistMode::Disabled => set_tcp_notsent_lowat(u32::MAX),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_kist_params(&self, params: &KistParams) {
        use super::kist::KistMode;

        if params.kist_enabled() != KistMode::Disabled {
            tracing::warn!("KIST not currently supported on non-linux platforms");
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::channel::{ChannelType, ClosedUnexpectedly, UniqId};
    use crate::client::circuit::CircParameters;
    use crate::client::circuit::padding::new_padding;
    use crate::fake_mpsc;
    use crate::util::{DummyTimeoutEstimator, fake_mq};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use tor_cell::chancell::msg;
    use tor_linkspec::OwnedChanTarget;
    use tor_rtcompat::SpawnExt;
    use tor_rtcompat::{DynTimeProvider, NoOpStreamOpsHandle, Runtime};

    pub(crate) type CodecResult = std::result::Result<AnyChanCell, Error>;

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
            Error::CellDecodeErr {
                object: "reactor test",
                err: tor_cell::Error::ChanProto("dummy message".into()),
            }
        });
        let stream_ops = NoOpStreamOpsHandle::default();
        let (chan, reactor) = crate::channel::Channel::new(
            ChannelType::ClientInitiator,
            link_protocol,
            Box::new(send1),
            Box::new(recv2),
            Box::new(stream_ops),
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

            let (ret, reac) = futures::join!(
                chan.new_tunnel(Arc::new(DummyTimeoutEstimator)),
                reactor.run_once()
            );
            let (pending, circr) = ret.unwrap();
            rt.spawn(async {
                let _ignore = circr.run().await;
            })
            .unwrap();
            assert!(reac.is_ok());

            let id = pending.peek_circid();

            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::Opening { .. }));
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
            let (chan, mut reactor, mut output, mut input) = new_reactor(rt.clone());

            let (ret, reac) = futures::join!(
                chan.new_tunnel(Arc::new(DummyTimeoutEstimator)),
                reactor.run_once()
            );
            let (pending, circr) = ret.unwrap();
            rt.spawn(async {
                let _ignore = circr.run().await;
            })
            .unwrap();
            assert!(reac.is_ok());

            let circparams = CircParameters::default();

            let id = pending.peek_circid();

            let ent = reactor.circs.get_mut(id);
            assert!(matches!(*ent.unwrap(), CircEnt::Opening { .. }));

            #[allow(clippy::clone_on_copy)]
            let rtc = rt.clone();
            let send_response = async {
                rtc.sleep(Duration::from_millis(100)).await;
                trace!("sending createdfast");
                // We'll get a bad handshake result from this createdfast cell.
                let created_cell = AnyChanCell::new(Some(id), msg::CreatedFast::new(*b"x").into());
                input.send(Ok(created_cell)).await.unwrap();
                reactor.run_once().await.unwrap();
            };

            let (circ, _) = futures::join!(pending.create_firsthop_fast(circparams), send_response);
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
            let (_chan, mut reactor, _output, mut input) = new_reactor(rt);

            // shouldn't get created2 cells for nonexistent circuits
            let created2_cell = msg::Created2::new(*b"hihi").into();
            input
                .send(Ok(AnyChanCell::new(CircId::new(7), created2_cell)))
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
                .send(Ok(AnyChanCell::new(CircId::new(4), relay_cell)))
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
            use oneshot_fused_workaround as oneshot;

            let (_chan, mut reactor, _output, mut input) = new_reactor(rt.clone());

            let (padding_ctrl, _padding_stream) = new_padding(DynTimeProvider::new(rt));

            let (_circ_stream_7, mut circ_stream_13) = {
                let (snd1, _rcv1) = oneshot::channel();
                let (snd2, rcv2) = fake_mpsc(64);
                reactor.circs.put_unchecked(
                    CircId::new(7).unwrap(),
                    CircEnt::Opening {
                        create_response_sender: snd1,
                        cell_sender: snd2,
                        padding_ctrl: padding_ctrl.clone(),
                    },
                );

                let (snd3, rcv3) = fake_mpsc(64);
                reactor.circs.put_unchecked(
                    CircId::new(13).unwrap(),
                    CircEnt::Open {
                        cell_sender: snd3,
                        padding_ctrl,
                    },
                );

                reactor.circs.put_unchecked(
                    CircId::new(23).unwrap(),
                    CircEnt::DestroySent(HalfCirc::new(25)),
                );
                (rcv2, rcv3)
            };

            // If a relay cell is sent on an open channel, the correct circuit
            // should get it.
            let relaycell: AnyChanMsg = msg::Relay::new(b"do you suppose").into();
            input
                .send(Ok(AnyChanCell::new(CircId::new(13), relaycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let got = circ_stream_13.next().await.unwrap();
            assert!(matches!(got, AnyChanMsg::Relay(_)));

            // If a relay cell is sent on an opening channel, that's an error.
            input
                .send(Ok(AnyChanCell::new(CircId::new(7), relaycell.clone())))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Relay cell on pending circuit before CREATED* received"
            );

            // If a relay cell is sent on a non-existent channel, that's an error.
            input
                .send(Ok(AnyChanCell::new(CircId::new(101), relaycell.clone())))
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
                    .send(Ok(AnyChanCell::new(CircId::new(23), relaycell.clone())))
                    .await
                    .unwrap();
                reactor.run_once().await.unwrap(); // should be fine.
            }

            // This one will fail.
            input
                .send(Ok(AnyChanCell::new(CircId::new(23), relaycell.clone())))
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

            let (_chan, mut reactor, _output, mut input) = new_reactor(rt.clone());

            let (padding_ctrl, _padding_stream) = new_padding(DynTimeProvider::new(rt));

            let (circ_oneshot_7, mut circ_stream_13) = {
                let (snd1, rcv1) = oneshot::channel();
                let (snd2, _rcv2) = fake_mpsc(64);
                reactor.circs.put_unchecked(
                    CircId::new(7).unwrap(),
                    CircEnt::Opening {
                        create_response_sender: snd1,
                        cell_sender: snd2,
                        padding_ctrl: padding_ctrl.clone(),
                    },
                );

                let (snd3, rcv3) = fake_mpsc(64);
                reactor.circs.put_unchecked(
                    CircId::new(13).unwrap(),
                    CircEnt::Open {
                        cell_sender: snd3,
                        padding_ctrl: padding_ctrl.clone(),
                    },
                );

                reactor.circs.put_unchecked(
                    CircId::new(23).unwrap(),
                    CircEnt::DestroySent(HalfCirc::new(25)),
                );
                (rcv1, rcv3)
            };

            // Destroying an opening circuit is fine.
            let destroycell: AnyChanMsg = msg::Destroy::new(0.into()).into();
            input
                .send(Ok(AnyChanCell::new(CircId::new(7), destroycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let msg = circ_oneshot_7.await;
            assert!(matches!(msg, Ok(CreateResponse::Destroy(_))));

            // Destroying an open circuit is fine.
            input
                .send(Ok(AnyChanCell::new(CircId::new(13), destroycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();
            let msg = circ_stream_13.next().await.unwrap();
            assert!(matches!(msg, AnyChanMsg::Destroy(_)));

            // Destroying a DestroySent circuit is fine.
            input
                .send(Ok(AnyChanCell::new(CircId::new(23), destroycell.clone())))
                .await
                .unwrap();
            reactor.run_once().await.unwrap();

            // Destroying a nonexistent circuit is an error.
            input
                .send(Ok(AnyChanCell::new(CircId::new(101), destroycell.clone())))
                .await
                .unwrap();
            let e = reactor.run_once().await.unwrap_err().unwrap_err();
            assert_eq!(
                format!("{}", e),
                "Channel protocol violation: Destroy for nonexistent circuit"
            );
        });
    }

    #[test]
    fn closing_if_reactor_dropped() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, reactor, _output, _input) = new_reactor(rt);

            assert!(!chan.is_closing());
            drop(reactor);
            assert!(chan.is_closing());

            assert!(matches!(
                chan.wait_for_close().await,
                Err(ClosedUnexpectedly::ReactorDropped),
            ));
        });
    }

    #[test]
    fn closing_if_reactor_shutdown() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, reactor, _output, _input) = new_reactor(rt);

            assert!(!chan.is_closing());
            chan.terminate();
            assert!(!chan.is_closing());

            let r = reactor.run().await;
            assert!(r.is_ok());
            assert!(chan.is_closing());

            assert!(chan.wait_for_close().await.is_ok());
        });
    }

    #[test]
    fn reactor_error_wait_for_close() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, reactor, _output, mut input) = new_reactor(rt);

            // force an error by sending created2 cell for nonexistent circuit
            let created2_cell = msg::Created2::new(*b"hihi").into();
            input
                .send(Ok(AnyChanCell::new(CircId::new(7), created2_cell)))
                .await
                .unwrap();

            // `reactor.run()` should return an error
            let run_error = reactor.run().await.unwrap_err();

            // `chan.wait_for_close()` should return the same error
            let Err(ClosedUnexpectedly::ReactorError(wait_error)) = chan.wait_for_close().await
            else {
                panic!("Expected a 'ReactorError'");
            };

            // `Error` doesn't implement `PartialEq`, so best we can do is to compare the strings
            assert_eq!(run_error.to_string(), wait_error.to_string());
        });
    }
}
