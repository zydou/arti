//! Module exposing the relay circuit reactor subsystem.
//!
//! The entry point of the reactor is [`Reactor::run`], which launches the
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
//! #### `ForwardReactor`
//!
//! It handles
//!
//!  * unrecognized RELAY cells, by moving them in the forward direction (towards the exit)
//!  * recognized RELAY cells, by splitting each cell into messages, and handling
//!    each message individually as described in the table below
//!    (Note: since prop340 is not yet implemented, in practice there is only 1 message per cell).
//!  * RELAY_EARLY cells (**not yet implemented**)
//!  * DESTROY cells (**not yet implemented**)
//!  * PADDING_NEGOTIATE cells (**not yet implemented**)
//!
//! ```text
//!
//! Legend: `F` = "forward reactor", `B` = "backward reactor"
//!
//! | RELAY cmd         | Received in | Handled in | Description                            |
//! |-------------------|-------------|------------|----------------------------------------|
//! | SENDME            | F           | B          | Sent to BackwardReactor for handling   |
//! |                   |             |            | (BackwardReactorCmd::HandleSendme)     |
//! |                   |             |            | because the forward reactor doesn't    |
//! |                   |             |            | have access to the chan_sender part    |
//! |                   |             |            | of the inbound (towards the client)    |
//! |                   |             |            | Tor channel, and so cannot obtain the  |
//! |                   |             |            | congestion signals needed for SENDME   |
//! |                   |             |            | handling                               |
//! |-------------------|-------------|------------|----------------------------------------|
//! | DROP              | F           | F          | Passed to PaddingController for        |
//! |                   |             |            | validation                             |
//! |-------------------|-------------|------------|----------------------------------------|
//! | EXTEND2           | F           |            | Handled by instructing the channel     |
//! |                   |             |            | provider to launch a new channel, and  |
//! |                   |             |            | waiting for the new channel on its     |
//! |                   |             |            | outgoing_chan_rx receiver              |
//! |                   |             |            | (**not yet implemented**)              |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TRUNCATE          | F           | F          | (**not yet implemented**)              |
//! |                   |             |            |                                        |
//! |-------------------|-------------|------------|----------------------------------------|
//! | Any command where | F           | B          | All messages with a non-zero stream ID |
//! | stream Id != 0    |             |            | are forwarded to the Backward reactor  |
//! |                   |             |            | (BackwardReactorCmd::HandleMsg)        |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TODO              |             |            |                                        |
//! |                   |             |            |                                        |
//! ```
//!
//! The `ForwardReactor` uses the `cell_tx` MPSC channel to forward cells to the `BackwardReactor`.
//! The cells are wrapped in a `BackwardReactorCmd`, which specified how the cell should be
//! handled.
//!
//! > **Note**: in addition to forwarding cells received from the client, the `ForwardReactor`
//! > also passes any circuit-level SENDME cells that need to be delivered to the client
//! > to the `BackwardReactor` (see [`BackwardReactorCmd::SendSendme`](backward::BackwardReactorCmd).
//!
//! The reason we need this cross-reactor forwarding is because the read and write sides
//! of `StreamMap` are not "splittable", so we are stuck having to reroute all stream data
//! to the reactor that owns the `StreamMap` (i.e. to `BackwardReactor`).
//! In the future, we'd like to redesign the `StreamMap`
//! to split the read ends of the streams from the write ones, which will enable us
//! to pass the read side to the `ForwardReactor` and the write side to the `BackwardReactor`.
//!
//! > **Note**: the `cell_tx` MPSC channel has no buffering, so if the `BackwardReactor`
//! > is not reading from it quickly enough (for example if its client-facing Tor channel
//! > sink is not ready to accept any more cells), the `ForwardReactor` will block,
//! > and therefore cease reading from its input channel, providing backpressure
//!
//! #### `BackwardReactor`
//!
//! It handles
//!
//!  * the delivery of all client-bound cells (it writes them to the towards-the-client
//!    Tor channel sink) (**partially implemented**)
//!  * all stream management operations (the opening/closing of streams, and the delivery
//!    of DATA cells to their corresponding streams) (**partially implemented**)
//!  * the sending of padding cells, according to the PaddingController's instructions
//!    (**not yet implemented**)
//
// TODO(relay): the above is underspecified, because it's not implemented yet,
// but the plan is to iron out these details soon
//
//!
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
use futures::{FutureExt as _, Stream, StreamExt as _, select_biased};
use postage::broadcast;
use tracing::{debug, trace};

use tor_cell::chancell::CircId;
use tor_cell::relaycell::{RelayCellDecoder, RelayCmd};
use tor_error::{debug_report, internal};
use tor_linkspec::HasRelayIds;
use tor_memquota::mq_queue::{ChannelSpec, MpscSpec};
use tor_rtcompat::{DynTimeProvider, Runtime};

use crate::channel::Channel;
use crate::circuit::circhop::{CircHopInbound, CircHopOutbound, HopSettings};
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::congestion::CongestionControl;
use crate::congestion::sendme::StreamRecvWindow;
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::{CircuitAccount, SpecificAccount};
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::stream::flow_ctrl::xon_xoff::reader::XonXoffReaderCtrl;
use crate::stream::incoming::IncomingStreamRequestFilter;
use crate::stream::incoming::{
    IncomingCmdChecker, IncomingStream, IncomingStreamRequestHandler, StreamReqInfo,
};
use crate::stream::{RECV_WINDOW_INIT, StreamComponents, StreamTarget, Tunnel};
use crate::util::err::ReactorError;

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, PaddingEventStream};

use crate::client::stream::StreamReceiver;

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
pub(crate) struct Reactor<R: Runtime, T: HasRelayIds> {
    /// The runtime.
    ///
    /// Used for spawning the two reactors.
    runtime: R,
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

/// Configuration for incoming stream requests.
pub(super) struct IncomingStreamConfig<'a> {
    /// The stream-initiating commands (BEGIN, RESOLVE, etc.) allowed on this circuit.
    allow_commands: &'a [RelayCmd],
    /// A filter applied to all incoming stream requests
    filter: Box<dyn IncomingStreamRequestFilter>,
}

#[allow(unused)] // TODO(relay)
impl<R: Runtime, T: HasRelayIds> Reactor<R, T> {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new<'a>(
        runtime: R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        settings: &HopSettings,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
        incoming: IncomingStreamConfig<'a>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        memquota: &CircuitAccount,
    ) -> crate::Result<(Self, Arc<RelayCirc>, impl Stream<Item = IncomingStream>)> {
        let (outgoing_chan_tx, outgoing_chan_rx) = mpsc::unbounded();
        let (reactor_closed_tx, reactor_closed_rx) = broadcast::channel(0);

        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        #[allow(clippy::disallowed_methods)]
        let (cell_tx, cell_rx) = mpsc::channel(0);

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
            padding_ctrl.clone(),
            reactor_closed_rx.clone(),
        );

        let outbound = CircHopOutbound::new(
            ccontrol,
            relay_format,
            Arc::new(settings.flow_ctrl_params.clone()),
            settings,
        );

        let handle = Arc::new(RelayCirc {
            control: control_tx,
            command: command_tx,
            time_provider: DynTimeProvider::new(runtime.clone()),
        });

        let (incoming, stream) =
            prepare_incoming_stream(runtime.clone(), Arc::clone(&handle), incoming, memquota)?;

        let backward = BackwardReactor::new(
            runtime.clone(),
            channel,
            outbound,
            circ_id,
            unique_id,
            crypto_in,
            settings,
            cell_rx,
            outgoing_chan_tx,
            padding_ctrl,
            padding_event_stream,
            incoming,
            reactor_closed_rx.clone(),
        );

        let reactor = Reactor {
            runtime,
            unique_id,
            forward: Some(forward),
            backward: Some(backward),
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
        };

        Ok((reactor, handle, stream))
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> crate::Result<()> {
        let unique_id = self.unique_id;

        debug!(
            circ_id = %unique_id,
            "Running relay circuit reactor",
        );

        let result = match self.run_inner().await {
            Ok(()) => return Err(internal!("reactor shut down without an error?!").into()),
            Err(ReactorError::Shutdown) => Ok(()),
            Err(ReactorError::Err(e)) => Err(e),
        };

        // Log that the reactor stopped, possibly with the associated error as a report.
        // May log at a higher level depending on the error kind.
        const MSG: &str = "Relay circuit reactor shut down";
        match &result {
            Ok(()) => trace!(circ_id = %unique_id, "{MSG}"),
            Err(e) => debug_report!(e, circ_id = %unique_id, "{MSG}"),
        }

        result
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

/// Prepare the [`Stream`] of [`IncomingStream`]s and corresponding handler.
///
/// Needed for exits. Middle relays should reject every incoming stream,
/// either through the `filter` provided in the [`IncomingStreamConfig`],
/// or by explicitly calling .reject() on each received stream.
///
// TODO(relay): I think we will prefer using the .reject() approach
// for this, because the filter is only meant for inexpensive quick
// checks that are done immediately in the reactor (any blocking
// in the filter will block the relay reactor main loop!).
///
/// The user of the reactor **must** handle this stream
/// (either by .accept()ing and opening and proxying the corresponding
/// streams as appropriate, or by .reject()ing).
///
// TODO: declare a type-alias for the return type when support for
// impl in type aliases gets stabilized.
//
// See issue #63063 <https://github.com/rust-lang/rust/issues/63063>
fn prepare_incoming_stream<'a, R: Runtime>(
    runtime: R,
    tunnel: Arc<RelayCirc>,
    incoming: IncomingStreamConfig<'a>,
    memquota: &CircuitAccount,
) -> crate::Result<(
    IncomingStreamRequestHandler,
    impl Stream<Item = IncomingStream>,
)> {
    /// The size of the channel receiving IncomingStreamRequestContexts.
    ///
    // TODO(relay-tuning): buffer size
    const INCOMING_BUFFER: usize = crate::stream::STREAM_READER_BUFFER;

    let time_prov = DynTimeProvider::new(runtime);

    let (incoming_sender, incoming_receiver) =
        MpscSpec::new(INCOMING_BUFFER).new_mq(time_prov.clone(), memquota.as_raw_account())?;

    let IncomingStreamConfig {
        allow_commands,
        filter,
    } = incoming;

    let cmd_checker = IncomingCmdChecker::new_any(allow_commands);
    let incoming = IncomingStreamRequestHandler {
        incoming_sender,
        cmd_checker,
        hop_num: None,
        filter,
    };

    // TODO(relay): this is more or less copy-pasta from client code
    let stream = incoming_receiver.map(move |req_ctx| {
        let StreamReqInfo {
            req,
            stream_id,
            hop,
            receiver,
            msg_tx,
            rate_limit_stream,
            drain_rate_request_stream,
            memquota,
            relay_cell_format,
        } = req_ctx;

        // There is no originating hop if we're a relay
        debug_assert!(hop.is_none());

        let target = StreamTarget {
            tunnel: Tunnel::Relay(Arc::clone(&tunnel)),
            tx: msg_tx,
            hop: None,
            stream_id,
            relay_cell_format,
            rate_limit_stream,
        };

        // can be used to build a reader that supports XON/XOFF flow control
        let xon_xoff_reader_ctrl =
            XonXoffReaderCtrl::new(drain_rate_request_stream, target.clone());

        let reader = StreamReceiver {
            target: target.clone(),
            receiver,
            recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
            ended: false,
        };

        let components = StreamComponents {
            stream_receiver: reader,
            target,
            memquota,
            xon_xoff_reader_ctrl,
        };

        IncomingStream::new(time_prov.clone(), req, components)
    });

    Ok((incoming, stream))
}
