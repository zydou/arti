//! Module exposing the relay circuit reactor subsystem.
//!
//! The entry point of the reactor is [`RelayReactor::run`], which launches the
//! reactor background tasks, and begins listening for inbound cells on the provided
//! inbound channel.
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
//! The `BackwardReactor` can also be viewed as the "primary" reactor here:
//! its `.run()` function starts the `BackwardReactor` **and** spawns [`ForwardReactor::run`],
//! so you can view this function as the entry point of the circuit reactor subsystem.
//!
//! > Note: the "primary"/`BackwardReactor` is also the component that handles [`RelayCtrlMsg`]s
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
//!  * `ForwardReactor` holds the reading end of the inbound (coming from the client) channel,
//!    and the writing end of the outbound (towards the exit) channel, if there is one
//!  * `BackwardReactor` holds the reading end of the outbound channel, if there is one,
//!    and the writing end of the inbound channel, if there is one
//!
//! Upon receiving an unrecognized cell, the `ForwardReactor` forwards it towards the exit.
//! However, upon receiving a *recognized* cell, the `ForwardReactor` might need to
//! send that cell to the `BackwardReactor` for handling (for example, if the cell
//! contains stream data). For this, it uses the `cell_tx` channel.
//
// TODO(relay): the above is underspecified, because it's not implemented yet,
// but the plan is to iron out these details soon

mod forward;

use crate::channel::{Channel, ChannelSender};
use crate::circuit::UniqId;
use crate::circuit::celltypes::RelayCircChanMsg;
use crate::circuit::circhop::HopSettings;
use crate::congestion::CongestionControl;
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer, RelayCellBody};
use crate::memquota::CircuitAccount;
use crate::relay::channel_provider::{ChannelProvider, ChannelResult};
use crate::stream::flow_ctrl::params::FlowCtrlParameters;
use crate::streammap::{self, StreamMap};
use crate::util::err::ReactorError;
use crate::{Error, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;
use crate::client::reactor::CloseStreamBehavior;

use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanCmd, CircId};
use tor_cell::relaycell::msg::{AnyRelayMsg, SendmeTag};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellDecoder, RelayCellFormat, StreamId};
use tor_error::{internal, trace_report};
use tor_linkspec::HasRelayIds;
use tor_memquota::mq_queue::{self, MpscSpec};
use tor_rtcompat::Runtime;

use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, future, select_biased};
use oneshot_fused_workaround as oneshot;
use postage::broadcast;
use tracing::trace;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use forward::ForwardReactor;

/// A message telling the reactor to do something.
///
/// For each `RelayCtrlMsg`, the reactor will send a cell on the underlying channel.
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
/// never cause cells to sent on the channel,
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
pub(crate) struct RelayReactor<R: Runtime, T: HasRelayIds> {
    /// The reactor for handling the forward direction (client to exit).
    forward: ForwardReactor,
    /// The reactor for handling the backward direction (exit to client).
    backward: BackwardReactor<R, T>,
}

/// MPSC queue for inbound data on its way from channel to circuit, sender
#[allow(unused)] // TODO(relay)
pub(crate) type CircuitRxSender = mq_queue::Sender<RelayCircChanMsg, MpscSpec>;

/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<RelayCircChanMsg, MpscSpec>;

/// The "backward" circuit reactor of a relay.
///
/// Handles the "backward direction": moves cells towards the client,
/// and drives the application streams.
///
/// Shuts down on explicit shutdown requests ([`RelayCtrlCmd::Shutdown`]),
/// if an error occurs, or if the [`ForwardReactor`] shuts down.
///
// TODO(relay): docs
//
// NOTE: the reactor is currently a bit awkward, because it's generic over
// the target relay `BuildSpec`. This will become slightly less awkward when
// we refactor this and the client circuit reactor to be based on an abstract
// reactor type.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct BackwardReactor<R: Runtime, T: HasRelayIds> {
    /// Format to use for relay cells.
    //
    // When we have packed/fragmented cells, this may be replaced by a RelayCellEncoder.
    relay_format: RelayCellFormat,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The circuit identifier on the incoming channel.
    circ_id: CircId,
    /// The reading end of the outbound channel, if we are not the last hop.
    ///
    /// Yields cells moving from the exit towards the client.
    input: Option<CircuitRxReceiver>,
    /// The sending end of the inbound channel.
    ///
    /// Delivers cells towards the client.
    chan_sender: ChannelSender,
    /// The cryptographic state for this circuit for inbound cells.
    crypto_in: Box<dyn InboundRelayLayer + Send>,
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    ccontrol: Arc<Mutex<CongestionControl>>,
    /// Flow control parameters for new streams.
    flow_ctrl_params: Arc<FlowCtrlParameters>,
    /// Receiver for control messages for this reactor, sent by reactor handle objects.
    control: mpsc::UnboundedReceiver<RelayCtrlMsg>,
    /// Receiver for command messages for this reactor, sent by reactor handle objects.
    ///
    /// This channel is polled in [`BackwardReactor::run_once`].
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<RelayCtrlCmd>,
    /// Receiver for stream data that need to be delivered to a stream.
    ///
    /// The sender is in [`ForwardReactor`], which will forward all cells
    /// carrying stream data to us.
    ///
    /// This serves a dual purpose:
    ///   * it enables the `ForwardReactor` to deliver stream data received from the client
    ///   * it lets the `BackwardReactor` know if the `ForwardReactor` has shut down:
    ///     we select! on this channel in the main loop, so if the `ForwardReactor`
    ///     shuts down, we will get EOS upon calling `.next()`)
    cell_rx: mpsc::UnboundedReceiver<()>,
    /// A handle to a [`ChannelProvider`], used for initiating outgoing channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying channel provider (`ChanMgr`),
    /// to enable the reuse of existing channels where possible.
    chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
    /// A sender for sending newly opened outgoing [`Channel`]`s to the reactor.
    ///
    /// This is passed to the [`ChannelProvider`] for each channel request.
    outgoing_chan_tx: mpsc::UnboundedSender<ChannelResult>,
    /// A mapping from stream IDs to stream entries.
    /// TODO: can we use a CircHop instead??
    /// Otherwise we'll duplicate much of it here.
    streams: Arc<Mutex<StreamMap>>,
    /// A sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: broadcast::Sender<void::Void>,
    /// The runtime.
    ///
    /// Used for spawning the [`BackwardReactor`].
    runtime: R,
}

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
impl<R: Runtime, T: HasRelayIds> RelayReactor<R, T> {
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
        inbound_rx: CircuitRxReceiver,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        settings: &HopSettings,
        runtime: R,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
        memquota: CircuitAccount,
    ) -> (Self, RelayReactorHandle) {
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let (outgoing_chan_tx, outgoing_chan_rx) = mpsc::unbounded();
        let (reactor_closed_tx, reactor_closed_rx) = broadcast::channel(0);
        let (cell_tx, cell_rx) = mpsc::unbounded();

        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));

        let forward = ForwardReactor::new(
            unique_id,
            RelayCellDecoder::new(relay_format),
            inbound_rx,
            Arc::clone(&ccontrol),
            outgoing_chan_rx,
            crypto_out,
            cell_tx,
            reactor_closed_rx.clone(),
        );

        let backward = BackwardReactor {
            relay_format,
            input: None,
            chan_sender: channel.sender(),
            crypto_in,
            ccontrol,
            flow_ctrl_params: Arc::new(settings.flow_ctrl_params.clone()),
            unique_id,
            circ_id,
            control: control_rx,
            command: command_rx,
            chan_provider,
            outgoing_chan_tx,
            streams: Arc::new(Mutex::new(StreamMap::new())),
            reactor_closed_tx,
            cell_rx,
            // XXX BackwardReactor no longer needs a handle to the runtime
            runtime: runtime.clone(),
        };

        let handle = RelayReactorHandle {
            control: control_tx,
            command: command_tx,
            reactor_closed_rx,
        };

        let reactor = RelayReactor { forward, backward };

        (reactor, handle)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> Result<()> {
        let Self { forward, backward } = self;

        let (forward_res, backward_res) = futures::join!(forward.run(), backward.run());

        let () = forward_res?;
        backward_res
    }
}

#[allow(unused)] // TODO(relay)
impl<R: Runtime, T: HasRelayIds> BackwardReactor<R, T> {
    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> Result<()> {
        trace!(
            circ_id = %self.unique_id,
            "Running relay circuit reactor",
        );

        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };

        // Log that the reactor stopped, possibly with the associated error as a report.
        // May log at a higher level depending on the error kind.
        const MSG: &str = "Relay circuit reactor stopped";
        match &result {
            Ok(()) => trace!("{}: {MSG}", self.unique_id),
            Err(e) => trace_report!(e, "{}: {}", self.unique_id, MSG),
        }

        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        // Flush the inbound sink, and check it for readiness
        //
        // TODO(flushing): here and everywhere else we need to flush:
        //
        // Currently, we try to flush every time we want to write to the sink,
        // but may be suboptimal.
        //
        // However, we don't actually *wait* for the flush to complete
        // (we just make a bit of progress by calling poll_flush),
        // so it's possible that this is actually tolerable.
        // We should run some tests, and if this turns out to be a performance bottleneck,
        // we'll have to rethink our flushing approach.
        let inbound_chan_ready = future::poll_fn(|cx| {
            // The flush outcome doesn't matter,
            // so we simply move on to the readiness check.
            // The reason we don't wait on the flush is because we don't
            // want to flush on *every* reactor loop, but we do want to make
            // a bit of progress each time.
            //
            // (TODO: do we want to handle errors here?)
            let _ = self.chan_sender.poll_flush_unpin(cx);

            self.chan_sender.poll_ready_unpin(cx)
        });

        let streams = Arc::clone(&self.streams);
        let ready_streams_fut = future::poll_fn(move |cx| {
            let mut streams = streams.lock().expect("poisoned lock");
            let Some((sid, msg)) = streams.poll_ready_streams_iter(cx).next() else {
                // No ready streams
                //
                // TODO(flushing): if there are no ready streams, we might want to defer
                // flushing until stream data becomes available (or until a timeout elapses).
                // The deferred flushing approach should enable us to send
                // more than one message at a time to the channel reactor.
                return Poll::Pending;
            };

            if msg.is_none() {
                // This means the local sender has been dropped,
                // which presumably can only happen if an error occurs,
                // or if the stream ends. In both cases, we're going to
                // want to send an END to the client to let them know,
                // and to remove the stream from the stream map.
                //
                // TODO(relay): the local sender part is not implemented yet
                return Poll::Ready(StreamEvent::Closed {
                    sid,
                    behav: CloseStreamBehavior::default(),
                    reason: streammap::TerminateReason::StreamTargetClosed,
                });
            };

            let msg = streams.take_ready_msg(sid).expect("msg disappeared");

            Poll::Ready(StreamEvent::ReadyMsg { sid, msg })
        });

        let cc_can_send = self.ccontrol.lock().expect("poisoned lock").can_send();

        let (tx, rx) = oneshot::channel::<()>();

        // In parallel, drive :
        //  1. the application streams stream
        let streams_fut = async move {
            // Avoid polling the application streams if the outgoing sink is blocked
            let _ = inbound_chan_ready.await;

            // Kludge to notify the other future that the inbound chan is ready
            // needed because we can't poll for readiness from two separate tasks
            let _ = tx.send(());

            if !cc_can_send {
                // We can't send anything on this hop that counts towards SENDME windows.
                //
                // TODO: This shouldn't block outgoing flow-control messages (e.g.
                // SENDME), which are initiated via the control-message
                // channel, handled above.
                let () = future::pending().await;
            }

            ready_streams_fut.await
        };

        // 2. Messages moving from the exit towards the client,
        // if we have an outbound channel **iff** the outgoing sink (towards the client)
        // is ready to accept them
        let backwards_cell = async {
            // Avoid reading from the outgoing channel (if there even is one!)
            // if the outgoing sink is blocked.
            let () = rx.await.expect("streams_fut future disappeared?!");

            if let Some(input) = self.input.as_mut() {
                input.next().await
            } else {
                future::pending().await
            }
        };

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

                self.handle_command(&cmd)
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

                self.handle_control(&msg)
            },
            ev = streams_fut.fuse() => self.handle_stream_event(ev),
            cell = backwards_cell.fuse() => {
                let Some(cell) = cell else {
                    // outbound channel closed, we should close too
                    return Err(ReactorError::Shutdown);
                };

                self.handle_backward_cell(cell)
            }
            cell = self.cell_rx.next() => {
                let Some(cell) = cell else {
                    // The outbound reactor has crashed, so we have to shut down.
                    trace!(
                        circ_id = %self.unique_id,
                        "Backward relay reactor shutdown (outbound side has closed)",
                    );

                    return Err(ReactorError::Shutdown);
                };

                todo!()
            }
        }
    }

    /// Encode `msg` and encrypt it, returning the resulting cell
    /// and tag that should be expected for an authenticated SENDME sent
    /// in response to that cell.
    fn encode_clientbound_relay_cell(
        &mut self,
        relay_format: RelayCellFormat,
        msg: AnyRelayMsgOuter,
    ) -> Result<(AnyChanMsg, SendmeTag)> {
        let mut body: RelayCellBody = msg
            .encode(relay_format, &mut rand::rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();

        let tag = self.crypto_in.originate(ChanCmd::RELAY, &mut body);
        let msg = Relay::from(BoxedCellBody::from(body));
        let msg = AnyChanMsg::Relay(msg);

        Ok((msg, tag))
    }

    /// Send a RELAY cell with the specified `msg` to the client.
    fn send_msg_to_client(
        &mut self,
        streamid: Option<StreamId>,
        msg: AnyRelayMsg,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError> {
        let msg = AnyRelayMsgOuter::new(streamid, msg);
        let (msg, tag) = self.encode_clientbound_relay_cell(self.relay_format, msg)?;
        let cell = AnyChanCell::new(Some(self.circ_id), msg);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the streams, so await won't block.
        self.chan_sender.start_send_unpin((cell, info))?;

        Ok(())
    }

    /// Handle a [`StreamEvent`].
    fn handle_stream_event(&mut self, event: StreamEvent) -> StdResult<(), ReactorError> {
        match event {
            StreamEvent::Closed { .. } => todo!(),
            StreamEvent::ReadyMsg { sid, msg } => self.send_msg_to_client(Some(sid), msg, None),
        }
    }

    /// Handle a backward cell (moving from the exit towards the client).
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_backward_cell(&mut self, _cell: RelayCircChanMsg) -> StdResult<(), ReactorError> {
        Err(internal!("Cell relaying is not implemented").into())
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

/// A stream-related event.
#[allow(unused)] // TODO(relay)
enum StreamEvent {
    /// A stream was closed.
    Closed {
        /// The ID of the stream to close.
        sid: StreamId,
        /// The stream-closing behavior.
        behav: CloseStreamBehavior,
        /// The reason for closing the stream.
        reason: streammap::TerminateReason,
    },
    /// A stream has a ready message.
    ReadyMsg {
        /// The ID of the stream to close.
        sid: StreamId,
        /// The message.
        msg: AnyRelayMsg,
    },
}
