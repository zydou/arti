//! Module exposing the relay circuit reactor subsystem.
//!
//! The entry point of the reactor is [`RelayReactor::run`], which launches the
//! reactor background tasks, and begins listening for inbound cells on the provided
//! inbound Tor channel.
//!
//! ### Architecture
//!
//! Internally, the circuit reactor consists of two reactors, that run in separate tasks:
//!
//!   * [`ForwardReactor`]: handles exit-bound cells, by moving cells in the
//!     forward direction (from the client to the exit)
//!   * [`BackwardReactor`]: handles client-bound cells, by moving cells in the
//!     backward direction (from the exit to the client), and by packaging
//!     and sending application stream data towards the client
//!
//! The read and write ends of the inbound and outbound Tor channels are "split",
//! such that each reactor holds an `input` stream (for reading)
//! and a `chan_sender` sink (for writing):
//!
//!  * `ForwardReactor` holds the reading end of the inbound (coming from the client) Tor channel,
//!    and the writing end of the outbound (towards the exit) Tor channel, if there is one
//!  * `BackwardReactor` holds the reading end of the outbound channel, if there is one,
//!    and the writing end of the inbound channel, if there is one
//!
//! Upon receiving an unrecognized cell, the `ForwardReactor` forwards it towards the exit.
//! However, upon receiving a *recognized* cell, the `ForwardReactor` might need to
//! send that cell to the `BackwardReactor` for handling (for example, a cell
//! containing stream data needs to be delivered to the appropriate stream
//! in the `StreamMap`). For this, it uses the `cell_tx` MPSC channel.
//! This is needed because the read and write sides of `StreamMap` are not "splittable",
//! so we are stuck having to reroute all stream data to the reactor that owns the `StreamMap`
//! (i.e. to `BackwardReactor`). In the future, we'd like to redesign the `StreamMap`
//! to split the read ends of the streams from the write ones, which will enable us
//! to pass the read side to the `ForwardReactor` and the write side to the `BackwardReactor`.
//
// TODO(relay): the above is underspecified, because it's not implemented yet,
// but the plan is to iron out these details soon
//
//! This dual reactor architecture should, in theory, have better performance than
//! a single reactor system, because it enables us to parallelize some of the work:
//! the forward and backward directions share little state,
//! because they read from, and write to, different sinks/streams,
//! so they can be run in parallel (as separate tasks).
//! With a single reactor architecture, the reactor would need to drive
//! both the forward and the backward direction, and on each iteration
//! would need to decide which to prioritize, which might prove tricky
//! (though prioritizing one of them at random would've probably been good enough).
//!
//! The monolithic single reactor alternative would also have been significantly
//! more convoluted, and so more difficult to maintain in the long run.
//!
//
// Note: if we address the TODO below, the dual reactor architecture might even
// have some performance benefits:
//
// TODO: the part about sharing little state is not entirely accurate.
// Right now, they share the congestion control state, which is behind a mutex,
// and, indirectly, the `StreamMap` (via the `cell_tx` construction).
// In the future, we'd like to switch to a lock-less architecture,
// but that will involve redesign `CongestionControl`
// (to be mutable without &mut, for example by using atomics under the hood).

mod backward;
mod forward;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt as _, select_biased};
use postage::broadcast;
use tracing::{debug, trace};

use tor_cell::chancell::CircId;
use tor_cell::relaycell::RelayCellDecoder;
use tor_error::internal;
use tor_linkspec::HasRelayIds;
use tor_memquota::mq_queue::{self, MpscSpec};

use crate::channel::Channel;
use crate::circuit::UniqId;
use crate::circuit::celltypes::RelayCircChanMsg;
use crate::circuit::circhop::{CircHopInbound, CircHopOutbound, HopSettings};
use crate::congestion::CongestionControl;
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::CircuitAccount;
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::util::err::ReactorError;

use backward::BackwardReactor;
use forward::ForwardReactor;

/// A message telling the reactor to do something.
///
/// For each `RelayCtrlMsg`, the reactor will send a cell on the underlying Tor channel.
///
/// The difference between this and [`RelayCtrlCmd`] is that `RelayCtrlMsg`s
/// cause the reactor to send cells on the reactor's `chan_sender`,
/// whereas `RelayCtrlCmd` do not.
///
// TODO(relay): we may not need this
#[allow(unused)] // TODO(relay)
#[derive(Debug)]
pub(crate) enum RelayCtrlMsg {}

/// A message telling the reactor to do something.
///
/// The difference between this and [`RelayCtrlMsg`] is that `RelayCtrlCmd`s
/// never cause cells to sent on the Tor channel,
/// while `RelayCtrlMsg`s potentially do.
//
// TODO(relay): we may not need this
#[derive(educe::Educe)]
#[educe(Debug)]
#[allow(unused)] // TODO(relay)
pub(crate) enum RelayCtrlCmd {
    /// Shut down the reactor.
    Shutdown,
}

/// The entry point of the circuit reactor subsystem.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct RelayReactor<T: HasRelayIds> {
    /// The process-unique identifier of this circuit.
    ///
    /// Used for logging;
    unique_id: UniqId,
    /// The reactor for handling the forward direction (client to exit).
    ///
    /// Optional so we can move it out of self in run().
    forward: Option<ForwardReactor<T>>,
    /// The reactor for handling the backward direction (exit to client).
    ///
    /// Optional so we can move it out of self in run().
    backward: Option<BackwardReactor>,
    /// Receiver for control messages for this reactor, sent by reactor handle objects.
    control: mpsc::UnboundedReceiver<RelayCtrlMsg>,
    /// Receiver for command messages for this reactor, sent by reactor handle objects.
    ///
    /// This MPSC channel is polled in [`run`](Self::run).
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<RelayCtrlCmd>,
    /// A sender that is used to alert the [`ForwardReactor`] and [`BackwardReactor`]
    /// when this reactor is finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: broadcast::Sender<void::Void>,
}

/// MPSC queue for inbound data on its way from channel to circuit, sender
#[allow(unused)] // TODO(relay)
pub(crate) type CircuitRxSender = mq_queue::Sender<RelayCircChanMsg, MpscSpec>;

/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<RelayCircChanMsg, MpscSpec>;

#[allow(unused)] // TODO(relay)
impl<T: HasRelayIds> RelayReactor<T> {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        channel: Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        settings: &HopSettings,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
        memquota: CircuitAccount,
    ) -> (Self, RelayCirc) {
        let (outgoing_chan_tx, outgoing_chan_rx) = mpsc::unbounded();
        let (reactor_closed_tx, reactor_closed_rx) = broadcast::channel(0);
        let (cell_tx, cell_rx) = mpsc::unbounded();
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();

        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));
        let inbound = CircHopInbound::new(
            Arc::clone(&ccontrol),
            RelayCellDecoder::new(relay_format),
            settings,
        );

        let forward = ForwardReactor::new(
            inbound,
            unique_id,
            input,
            outgoing_chan_rx,
            crypto_out,
            chan_provider,
            cell_tx,
            reactor_closed_rx.clone(),
        );

        let outbound = CircHopOutbound::new(
            ccontrol,
            relay_format,
            Arc::new(settings.flow_ctrl_params.clone()),
            settings,
        );

        let backward = BackwardReactor::new(
            channel,
            outbound,
            circ_id,
            unique_id,
            crypto_in,
            settings,
            cell_rx,
            outgoing_chan_tx,
            reactor_closed_rx.clone(),
        );

        let handle = RelayCirc {
            control: control_tx,
            command: command_tx,
        };

        let reactor = RelayReactor {
            unique_id,
            forward: Some(forward),
            backward: Some(backward),
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
        };

        (reactor, handle)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> StdResult<(), ReactorError> {
        let unique_id = self.unique_id;
        debug!(
            circ_id = %unique_id,
            "Running relay circuit reactor",
        );

        let res = self.run_inner().await;

        debug!(
            circ_id = %unique_id,
            "Relay circuit reactor shutting down",
        );

        res
    }

    /// Helper for [`run`](Self::run).
    pub(crate) async fn run_inner(mut self) -> StdResult<(), ReactorError> {
        let (forward, backward) = (|| Some((self.forward.take()?, self.backward.take()?)))()
            .expect("relay reactor spawned twice?!");

        let mut forward = Box::pin(forward.run()).fuse();
        let mut backward = Box::pin(backward.run()).fuse();
        loop {
            // If either of these completes, this function returns,
            // dropping reactor_closed_tx, which will, in turn,
            // cause the remaining reactor, if there is one, to shut down too
            select_biased! {
                res = self.command.next() => {
                    let Some(cmd) = res else {
                        trace!(
                            circ_id = %self.unique_id,
                            reason = "command channel drop",
                            "reactor shutdown",
                        );

                        return Err(ReactorError::Shutdown);
                    };

                    self.handle_command(&cmd)?;
                },
                res = self.control.next() => {
                    let Some(msg) = res else {
                        trace!(
                            circ_id = %self.unique_id,
                            reason = "control channel drop",
                            "reactor shutdown",
                        );

                        return Err(ReactorError::Shutdown);
                    };

                    self.handle_control(&msg)?;
                },
                // No need to log the error here, because it was already logged
                // by the reactor that shut down
                res = forward => return Ok(res?),
                res = backward => return Ok(res?),
            }
        }
    }

    /// Handle a [`RelayCtrlCmd`].
    fn handle_command(&self, cmd: &RelayCtrlCmd) -> StdResult<(), ReactorError> {
        match cmd {
            RelayCtrlCmd::Shutdown => self.handle_shutdown(),
        }
    }

    /// Handle a [`RelayCtrlMsg`].
    #[allow(clippy::unnecessary_wraps)]
    fn handle_control(&self, cmd: &RelayCtrlMsg) -> StdResult<(), ReactorError> {
        Err(internal!("not implemented: {cmd:?}").into())
    }

    /// Handle a shutdown request.
    fn handle_shutdown(&self) -> StdResult<(), ReactorError> {
        trace!(
            tunnel_id = %self.unique_id,
            "reactor shutdown due to explicit request",
        );

        Err(ReactorError::Shutdown)
    }
}
