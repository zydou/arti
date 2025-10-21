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
//! > Note: the `BackwardReactor` is also the component that handles [`RelayCtrlMsg`]s
//! > and [`RelayCtrlCmd`]s. This is okay for now, but if we ever add a new control message type
//! > that needs to be handled by `ForwardReactor` (or that needs information from `ForwardReactor`),
//! > we will need to rethink the control message handling
//! > (depending on what that redesign entails, we might want to replace the mpsc control
//! > channels with broadcast channels, or simply have `BackwardReactor` relay control commands
//! > to the `ForwardReactor`).
//!
//! > But we can cross that bridge when we come to it.
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

use std::sync::{Arc, Mutex};

use futures::FutureExt as _;
use futures::channel::mpsc;
use postage::broadcast;
use tracing::debug;

use tor_cell::chancell::CircId;
use tor_cell::relaycell::RelayCellDecoder;
use tor_linkspec::HasRelayIds;
use tor_memquota::mq_queue::{self, MpscSpec};

use crate::Result;
use crate::channel::Channel;
use crate::circuit::UniqId;
use crate::circuit::celltypes::RelayCircChanMsg;
use crate::circuit::circhop::HopSettings;
use crate::congestion::CongestionControl;
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::CircuitAccount;
use crate::relay::channel_provider::ChannelProvider;

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
    forward: ForwardReactor<T>,
    /// The reactor for handling the backward direction (exit to client).
    backward: BackwardReactor,

    // TODO(relay): consider moving control message handling
    // from BackwardReactor to here
}

/// MPSC queue for inbound data on its way from channel to circuit, sender
#[allow(unused)] // TODO(relay)
pub(crate) type CircuitRxSender = mq_queue::Sender<RelayCircChanMsg, MpscSpec>;

/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<RelayCircChanMsg, MpscSpec>;

/// A handle for interacting with a [`BackwardReactor`].
#[allow(unused)] // TODO(relay)
pub(crate) struct RelayReactorHandle {
    /// Sender for reactor control messages.
    control: mpsc::UnboundedSender<RelayCtrlMsg>,
    /// Sender for reactor control commands.
    command: mpsc::UnboundedSender<RelayCtrlCmd>,
    /// A broadcast receiver used to detect when the reactor is dropped.
    reactor_closed_rx: broadcast::Receiver<void::Void>,
}

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
    ) -> (Self, RelayReactorHandle) {
        let (outgoing_chan_tx, outgoing_chan_rx) = mpsc::unbounded();
        let (reactor_closed_tx, reactor_closed_rx) = broadcast::channel(0);
        let (cell_tx, cell_rx) = mpsc::unbounded();

        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));

        let forward = ForwardReactor::new(
            unique_id,
            RelayCellDecoder::new(relay_format),
            input,
            Arc::clone(&ccontrol),
            outgoing_chan_rx,
            crypto_out,
            chan_provider,
            cell_tx,
            reactor_closed_rx.clone(),
        );

        let (backward, control, command) = BackwardReactor::new(
            channel,
            circ_id,
            unique_id,
            crypto_in,
            ccontrol,
            settings,
            relay_format,
            cell_rx,
            outgoing_chan_tx,
            reactor_closed_tx,
        );

        let handle = RelayReactorHandle {
            control,
            command,
            reactor_closed_rx,
        };

        let reactor = RelayReactor {
            unique_id,
            forward,
            backward,
        };

        (reactor, handle)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> Result<()> {
        let Self {
            forward,
            backward,
            unique_id,
        } = self;

        debug!(
            circ_id = %unique_id,
            "Running relay circuit reactor",
        );

        futures::select! {
            res = forward.run().fuse() => res,
            res = backward.run().fuse() => res,
        }
    }
}
