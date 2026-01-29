//! Module exposing the circuit reactor subsystem.
//!
//! This module implements the new [multi-reactor circuit subsystem].
//!
// Note: this is currently only used for the relay side,
// but we plan to eventually rewrite client circuit implementation
// to use these new reactor types as well.
//!
//! The entry point of the reactor is [`Reactor::run`], which launches the
//! reactor background tasks, and begins listening for inbound cells on the provided
//! inbound Tor channel.
//!
//! ### Architecture
//!
//! Internally, the circuit reactor consists of multiple reactors,
//! each running in a separate task:
//!
//!   * [`StreamReactor`] (one per hop): handles all messages arriving to,
//!     and coming from the streams of a given hop. The ready stream messages
//!     are sent to the [`BackwardReactor`]
//!   * [`ForwardReactor`]: handles incoming cells arriving on the
//!     "inbound" Tor channel (towards the guard, if we are a client, or towards
//!     the client, if we are a relay). If we are a client, it moves stream messages
//!     towards the corresponding [`StreamReactor`]. If we are a relay,
//!     in addition to sending any stream messages to the `StreamReactor`,
//!     this reactor also moves cells in the forward direction
//!     (from the client towards the exit)
//!   * [`BackwardReactor`]: writes cells to the "inbound" Tor channel:
//!     towards the client if we are a relay, or the towards the exit
//!     if we are a client.
//!
// TODO: the forward/backward terminology no longer makes sense! Come up with better terms...
//!
//! If we are an exit relay, the cell flow looks roughly like this:
//!
//! ```text
//!                             <stream_tx
//!                              MPSC (0)>
//!   +--------------> FWD -------------------------+
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           v
//! relay      BackwardReactorCmd            StreamReactor
//!   ^             <MPSC (0)>                      |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 v                           |
//!   +--------------- BWD <------------------------+
//!     application stream data    <stream_rx
//!                                 MPSC (0)>
//!
//! For a middle relay (the `StreamReactor` is omitted for brevity,
//! but middle relays can have one too, if leaky pipe is in use):
//!
//! ```text                   unrecognized cell
//!   +--------------> FWD -------------------------+
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           v
//! client      BackwardReactorCmd                relay
//! or relay        <MPSC (0)>                      |
//!   ^                 |                           |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 |                           |
//!   |                 v                           |
//!   +--------------- BWD <------------------------+
//! ```
//!
//! On the client-side the `ForwardReactor` reads cells from the Tor channel to the guard,
//! and the `BackwardReactor` writes to it.
//!
//! ```text
//!   +--------------- FWD <--------------------+
//!   |                 |                       |
//!   |                 |                       |
//!   |                 |                       |
//!   v                 |                       |
//! StreamReactor  BackwardReactorCmd         guard
//!   |               <MPSC (0)>                ^
//!   |                 |                       |
//!   |                 |                       |
//!   |                 |                       |
//!   |                 v                       |
//!   +--------------> BWD ---------------------+
//! ```
//!
//! Client with leaky pipe (`SR` = `StreamReactor`):
//!
//! ```text
//!   +------------------------------+
//!   |       +--------------------+ | (1 MPSC TX per SR)
//!   |       |                    | |
//!   |       |       +----------- FWD <------------------+
//!   |       |       |             |                     |
//!   |       |       |             |                     |
//!   |       |       |             |                     |
//!   v       v       v             |                     |
//!  SR      SR      SR           BackwardReactorCmd    guard
//! (hop 4) (hop 3)  (hop 2)      <MPSC (0)>              ^
//!   |       |       |             |                     |
//!   |       |       |             |                     |
//!   |       |       |             |                     |
//!   |       |       |             v                     |
//!   |       |       |            BWD -------------------+
//!   |       |       |             ^
//!   |       |       |             |
//!   |       |       |             | <stream_rx
//!   |       |       |             |  MPSC (0)>
//!   +-------+-------+-------------+
//! ```
//!
// TODO(tuning): The inter-reactor MPSC channels have no buffering,
// which is likely going to be bad for performance,
// so we will need to tune the sizes of these MPSC buffers.
//!
//! The read and write ends of the inbound and outbound Tor channels are "split",
//! such that each reactor holds an `inbound_chan_rx` stream (for reading)
//! and a `inbound_chan_tx` sink (for writing):
//!
//!  * `ForwardReactor` holds the reading end of the inbound
//!    (coming from the client, if we are a relay, or coming from the guard, if we are a client)
//!    Tor channel, and the writing end of the outbound (towards the exit, if we are a middle relay)
//!    Tor channel, if there is one
//!  * `BackwardReactor` holds the reading end of the outbound channel, if there is one,
//!    and the writing end of the inbound channel, if there is one
//!
//! #### `ForwardReactor`
//!
//! It handles
//!
//!  * unrecognized RELAY cells, by delegating to the implementation-dependent
//!    [`ForwardHandler::handle_unrecognized_cell`]
//!  * recognized RELAY cells, by splitting each cell into individual messages, and handling
//!    each message individually as described in the table below
//!    (Note: since prop340 is not yet implemented, in practice there is only 1 message per cell).
//!
//! ```text
//!
//! Legend: `F` = "forward reactor", `B` = "backward reactor", `S` = "stream reactor"
//!
//! | RELAY cmd         | Received in | Handled in | Description                            |
//! |-------------------|-------------|------------|----------------------------------------|
//! | SENDME            | F           | B          | Sent to BackwardReactor for handling   |
//! |                   |             |            | (BackwardReactorCmd::HandleSendme)     |
//! |                   |             |            | because the forward reactor doesn't    |
//! |                   |             |            | have access to the inbound_chan_tx part|
//! |                   |             |            | of the inbound (towards the client)    |
//! |                   |             |            | Tor channel, and so cannot obtain the  |
//! |                   |             |            | congestion signals needed for SENDME   |
//! |                   |             |            | handling                               |
//! |-------------------|-------------|------------|----------------------------------------|
//! | Other             | F           | F          | Passed to impl-dependent handler       |
//! | (StreamId = 0)    |             |            |  `ForwardHandler::handle_meta_msg()`   |
//! |-------------------|-------------|------------|----------------------------------------|
//! | Other             | F           | S          | All messages with a non-zero stream ID |
//! | (StreamId != 0)   |             |            | are forwarded to the stream reactor    |
//! |-------------------|-------------|------------|----------------------------------------|
//! ```
//!
//! #### `BackwardReactor`
//!
//! It handles
//!
//!  * the packaging and delivery of all cells that need to be written to the "inbound" Tor channel
//!    (it writes them to the towards-the-client Tor channel sink) (**partially implemented**)
//!  * incoming cells coming over the "outbound" Tor channel. This channel only exists
//!    if we are a middle relay. These cells are relayed to the "inbound" Tor channel (**not implemented**).
//!  * the sending of padding cells, according to the PaddingController's instructions
//!
//! This multi-reactor architecture should, in theory, have better performance than
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
// NOTE: The FWD and BWD currently share the hop list containing the per-hop state,
// (including the congestion control object, which is behind a mutex).
//
//! [multi-reactor circuit subsystem]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/notes/relay-conflux.md
//! [`StreamReactor`]: stream::StreamReactor

// TODO(DEDUP): this will replace CircHopList when we rewrite the client reactor
// to use the new reactor architecture
pub(crate) mod circhop;

pub(crate) mod backward;
pub(crate) mod forward;
pub(crate) mod hop_mgr;
pub(crate) mod macros;
pub(crate) mod stream;

use std::result::Result as StdResult;
use std::sync::Arc;

use derive_deftly::Deftly;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt as _, select_biased};
use oneshot_fused_workaround as oneshot;
use tracing::trace;

use tor_cell::chancell::CircId;
use tor_rtcompat::{DynTimeProvider, Runtime};

use crate::channel::Channel;
use crate::circuit::reactor::backward::BackwardHandler;
use crate::circuit::reactor::forward::ForwardHandler;
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::circuit::reactor::stream::ReadyStreamMsg;
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::memquota::CircuitAccount;
use crate::util::err::ReactorError;

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, PaddingEventStream};

use backward::BackwardReactor;
use forward::ForwardReactor;
use macros::derive_deftly_template_CircuitReactor;

/// The type of a oneshot channel used to inform reactor of the result of an operation.
pub(crate) type ReactorResultChannel<T> = oneshot::Sender<crate::Result<T>>;

// TODO(relay): avoid relay-specific types here, in the generic impl!
#[cfg(feature = "relay")]
use crate::relay::channel_provider::ChannelProvider;

/// A handle for interacting with a circuit reactor.
#[derive(derive_more::Debug)]
pub(crate) struct CircReactorHandle<F: ForwardHandler, B: BackwardHandler> {
    /// Sender for reactor control messages.
    #[debug(skip)]
    pub(crate) control: mpsc::UnboundedSender<CtrlMsg<F::CtrlMsg, B::CtrlMsg>>,
    /// Sender for reactor control commands.
    #[debug(skip)]
    pub(crate) command: mpsc::UnboundedSender<CtrlCmd<F::CtrlCmd, B::CtrlCmd>>,
    /// The time provider.
    pub(crate) time_provider: DynTimeProvider,
    /// Memory quota account
    pub(crate) memquota: CircuitAccount,
}

/// A control command.
///
/// The difference between this and [`CtrlMsg`] is that `CtrlCmd`s
/// never cause cells to sent on the Tor channel,
/// while `CtrlMsg`s potentially do.
#[allow(unused)] // TODO(relay)
pub(crate) enum CtrlCmd<F, B> {
    /// A control command for the forward reactor.
    Forward(forward::CtrlCmd<F>),
    /// A control command for the backward reactor.
    Backward(backward::CtrlCmd<B>),
    /// Shut down the reactor.
    Shutdown,
}

/// A control message.
#[allow(unused)] // TODO(relay)
pub(crate) enum CtrlMsg<F, B> {
    /// A control message for the forward reactor.
    Forward(forward::CtrlMsg<F>),
    /// A control message for the backward reactor.
    Backward(backward::CtrlMsg<B>),
}

/// The entry point of the circuit reactor subsystem.
#[derive(Deftly)]
#[derive_deftly(CircuitReactor)]
#[deftly(reactor_name = "circuit reactor")]
#[deftly(only_run_once)]
#[deftly(run_inner_fn = "Self::run_inner")]
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct Reactor<R: Runtime, F: ForwardHandler, B: BackwardHandler> {
    /// The process-unique identifier of this circuit.
    ///
    /// Used for logging.
    unique_id: UniqId,
    /// The reactor for handling
    ///
    ///   * cells moving in the forward direction (from the client towards exit), if we are a relay
    ///   * incoming cells (coming from the guard), if we are a client
    ///
    /// Optional so we can move it out of self in run().
    forward: Option<ForwardReactor<R, F>>,
    /// The reactor for handling
    ///
    ///   * cells moving in the backward direction (from the exit towards client), if we are a relay
    ///   * outgoing cells (moving towards the guard), if we are a client
    ///
    /// Optional so we can move it out of self in run().
    backward: Option<BackwardReactor<B>>,
    /// Receiver for control messages for this reactor, sent by reactor handle objects.
    control: mpsc::UnboundedReceiver<CtrlMsg<F::CtrlMsg, B::CtrlMsg>>,
    /// Receiver for command messages for this reactor, sent by reactor handle objects.
    ///
    /// This MPSC channel is polled in [`run`](Self::run).
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `inbound_chan_tx` is not
    /// ready (whereas `control` messages are not read until the `inbound_chan_tx` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<CtrlCmd<F::CtrlCmd, B::CtrlCmd>>,
    /// Control channels for the [`ForwardReactor`].
    ///
    /// Handles [`CtrlCmd::Forward`] and [`CtrlMsg::Forward`] messages.
    fwd_ctrl: ReactorCtrl<forward::CtrlCmd<F::CtrlCmd>, forward::CtrlMsg<F::CtrlMsg>>,
    /// Control channels for the [`BackwardReactor`].
    ///
    /// Handles [`CtrlCmd::Backward`] and [`CtrlMsg::Backward`] messages.
    bwd_ctrl: ReactorCtrl<backward::CtrlCmd<B::CtrlCmd>, backward::CtrlMsg<B::CtrlMsg>>,
}

/// A handle for sending control/command messages to a FWD or BWD.
struct ReactorCtrl<C, M> {
    /// Sender for control commands.
    command_tx: mpsc::UnboundedSender<C>,
    /// Sender for control messages.
    control_tx: mpsc::UnboundedSender<M>,
}

impl<C, M> ReactorCtrl<C, M> {
    /// Create a new sender handle.
    fn new(command_tx: mpsc::UnboundedSender<C>, control_tx: mpsc::UnboundedSender<M>) -> Self {
        Self {
            command_tx,
            control_tx,
        }
    }

    /// Send a control command.
    fn send_cmd(&mut self, cmd: C) -> Result<(), ReactorError> {
        self.command_tx
            .unbounded_send(cmd)
            .map_err(|_| ReactorError::Shutdown)
    }

    /// Send a control message.
    fn send_msg(&mut self, msg: M) -> Result<(), ReactorError> {
        self.control_tx
            .unbounded_send(msg)
            .map_err(|_| ReactorError::Shutdown)
    }
}

/// Trait implemented by types that can handle control messages and commands.
pub(crate) trait ControlHandler {
    /// The type of control message expected by the forward reactor.
    type CtrlMsg;

    /// The type of control command expected by the forward reactor.
    type CtrlCmd;

    // TODO(DEDUP): do these APIs make sense?
    // What should we return here, maybe some instructions for the base reactor
    // to do something?

    /// Handle a control command.
    fn handle_cmd(&mut self, cmd: Self::CtrlCmd) -> StdResult<(), ReactorError>;

    /// Handle a control message.
    fn handle_msg(&mut self, msg: Self::CtrlMsg) -> StdResult<(), ReactorError>;
}

#[allow(unused)] // TODO(relay)
impl<R: Runtime, F: ForwardHandler + ControlHandler, B: BackwardHandler + ControlHandler>
    Reactor<R, F, B>
{
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `inbound_chan_rx`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::too_many_arguments)] // TODO
    pub(crate) fn new(
        runtime: R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        inbound_chan_rx: CircuitRxReceiver,
        forward_impl: F,
        backward_impl: B,
        hop_mgr: HopMgr<R>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        // The sending end of this channel should be in HopMgr
        bwd_rx: mpsc::Receiver<ReadyStreamMsg>,
        memquota: &CircuitAccount,
        #[cfg(feature = "relay")] chan_provider: Box<
            dyn ChannelProvider<BuildSpec = F::BuildSpec> + Send,
        >,
    ) -> (Self, CircReactorHandle<F, B>) {
        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        #[allow(clippy::disallowed_methods)]
        let (backward_reactor_tx, forward_reactor_rx) = mpsc::channel(0);

        // TODO: channels galore
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();

        let (fwd_control_tx, fwd_control_rx) = mpsc::unbounded();
        let (fwd_command_tx, fwd_command_rx) = mpsc::unbounded();
        let (bwd_control_tx, bwd_control_rx) = mpsc::unbounded();
        let (bwd_command_tx, bwd_command_rx) = mpsc::unbounded();

        let fwd_ctrl = ReactorCtrl::new(fwd_command_tx, fwd_control_tx);
        let bwd_ctrl = ReactorCtrl::new(bwd_command_tx, bwd_control_tx);

        let handle = CircReactorHandle {
            control: control_tx,
            command: command_tx,
            time_provider: DynTimeProvider::new(runtime.clone()),
            memquota: memquota.clone(),
        };

        /// Grab a handle to the hop list (it's needed by the BWD)
        let hops = Arc::clone(hop_mgr.hops());
        let forward = ForwardReactor::new(
            unique_id,
            forward_impl,
            hop_mgr,
            inbound_chan_rx,
            fwd_control_rx,
            fwd_command_rx,
            backward_reactor_tx,
            padding_ctrl.clone(),
            #[cfg(feature = "relay")]
            chan_provider,
        );

        let backward = BackwardReactor::new(
            runtime,
            channel,
            circ_id,
            unique_id,
            backward_impl,
            hops,
            forward_reactor_rx,
            bwd_control_rx,
            bwd_command_rx,
            padding_ctrl,
            padding_event_stream,
            bwd_rx,
        );

        let reactor = Reactor {
            unique_id,
            forward: Some(forward),
            backward: Some(backward),
            control: control_rx,
            command: command_rx,
            fwd_ctrl,
            bwd_ctrl,
        };

        (reactor, handle)
    }

    /// Helper for [`run`](Self::run).
    pub(crate) async fn run_inner(&mut self) -> StdResult<(), ReactorError> {
        let (forward, backward) = (|| Some((self.forward.take()?, self.backward.take()?)))()
            .expect("relay reactor spawned twice?!");

        let mut forward = Box::pin(forward.run()).fuse();
        let mut backward = Box::pin(backward.run()).fuse();
        loop {
            // If either of these completes, this function returns,
            // dropping fwd_ctrl/bwd_ctrl channels, which will, in turn,
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

                    self.handle_command(cmd)?;
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

                    self.handle_control(msg)?;
                },
                // No need to log the error here, because it was already logged
                // by the reactor that shut down
                res = forward => return Ok(res?),
                res = backward => return Ok(res?),
            }
        }
    }

    /// Handle a shutdown request.
    fn handle_shutdown(&self) -> StdResult<(), ReactorError> {
        trace!(
            tunnel_id = %self.unique_id,
            "reactor shutdown due to explicit request",
        );

        Err(ReactorError::Shutdown)
    }

    /// Handle a [`CtrlCmd`].
    fn handle_command(
        &mut self,
        cmd: CtrlCmd<F::CtrlCmd, B::CtrlCmd>,
    ) -> StdResult<(), ReactorError> {
        match cmd {
            CtrlCmd::Forward(c) => self.fwd_ctrl.send_cmd(c),
            CtrlCmd::Backward(c) => self.bwd_ctrl.send_cmd(c),
            CtrlCmd::Shutdown => self.handle_shutdown(),
        }
    }

    /// Handle a [`CtrlMsg`].
    fn handle_control(
        &mut self,
        cmd: CtrlMsg<F::CtrlMsg, B::CtrlMsg>,
    ) -> StdResult<(), ReactorError> {
        match cmd {
            CtrlMsg::Forward(c) => self.fwd_ctrl.send_msg(c),
            CtrlMsg::Backward(c) => self.bwd_ctrl.send_msg(c),
        }
    }
}
