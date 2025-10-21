//! A relay's view of the backward (away from the exit, towards the client) state of the circuit.

use crate::channel::{Channel, ChannelSender};
use crate::circuit::UniqId;
use crate::circuit::celltypes::RelayCircChanMsg;
use crate::circuit::circhop::HopSettings;
use crate::congestion::CongestionControl;
use crate::crypto::cell::{InboundRelayLayer, RelayCellBody};
use crate::relay::channel_provider::{ChannelProvider, ChannelResult};
use crate::stream::flow_ctrl::params::FlowCtrlParameters;
use crate::streammap::{self, StreamMap};
use crate::util::err::ReactorError;
use crate::util::poll_all::PollAll;
use crate::{Error, Result};
// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;
use crate::client::reactor::CloseStreamBehavior;

use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanCmd, CircId};
use tor_cell::relaycell::msg::{AnyRelayMsg, SendmeTag};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId};
use tor_error::{internal, trace_report};
use tor_linkspec::HasRelayIds;

use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, future, select_biased};
use oneshot_fused_workaround as oneshot;
use postage::broadcast;
use tracing::trace;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use super::{CircuitRxReceiver, RelayCtrlCmd, RelayCtrlMsg};

/// The "backward" circuit reactor of a relay.
///
/// Handles the "backward direction": moves cells towards the client,
/// and drives the application streams.
///
/// Shuts down on explicit shutdown requests ([`RelayCtrlCmd::Shutdown`]),
/// if an error occurs, or if the [`ForwardReactor`](super::ForwardReactor) shuts down.
///
// TODO(relay): docs
//
// NOTE: the reactor is currently a bit awkward, because it's generic over
// the target relay `BuildSpec`. This will become slightly less awkward when
// we refactor this and the client circuit reactor to be based on an abstract
// reactor type.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(super) struct BackwardReactor<T: HasRelayIds> {
    /// Format to use for relay cells.
    //
    // When we have packed/fragmented cells, this may be replaced by a RelayCellEncoder.
    relay_format: RelayCellFormat,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The circuit identifier on the backward channel.
    circ_id: CircId,
    /// The reading end of the forward channel, if we are not the last hop.
    ///
    /// Yields cells moving from the exit towards the client.
    input: Option<CircuitRxReceiver>,
    /// The sending end of the backward channel.
    ///
    /// Delivers cells towards the client.
    chan_sender: ChannelSender,
    /// The cryptographic state for this circuit for client-bound cells.
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
    /// The sender is in [`ForwardReactor`](super::ForwardReactor), which will forward all cells
    /// carrying stream data to us.
    ///
    /// This serves a dual purpose:
    ///   * it enables the `ForwardReactor` to deliver stream data received from the client
    ///   * it lets the `BackwardReactor` know if the `ForwardReactor` has shut down:
    ///     we select! on this channel in the main loop, so if the `ForwardReactor`
    ///     shuts down, we will get EOS upon calling `.next()`)
    cell_rx: mpsc::UnboundedReceiver<(StreamId, AnyRelayMsg)>,
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
}

#[allow(unused)] // TODO(relay)
impl<T: HasRelayIds> BackwardReactor<T> {
    /// Create a new [`BackwardReactor`].
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        channel: Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        ccontrol: Arc<Mutex<CongestionControl>>,
        settings: &HopSettings,
        relay_format: RelayCellFormat,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
        cell_rx: mpsc::UnboundedReceiver<(StreamId, AnyRelayMsg)>,
        outgoing_chan_tx: mpsc::UnboundedSender<ChannelResult>,
        reactor_closed_tx: broadcast::Sender<void::Void>,
    ) -> (
        Self,
        mpsc::UnboundedSender<RelayCtrlMsg>,
        mpsc::UnboundedSender<RelayCtrlCmd>,
    ) {
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();

        let reactor = Self {
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
        };

        (reactor, control_tx, command_tx)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(super) async fn run(mut self) -> Result<()> {
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

    /// Helper for [`run`](Self::run).
    ///
    /// Handles cells arriving in the "backwards" direction (client-bound),
    /// flushes the backward Tor channel sinks, polls the stream map for messages
    /// that need to be delivered to the client, and the `cells_rx` stream
    /// for client messages received via the `ForwardReactor`
    /// that need to be delivered to the application.
    ///
    /// Because the application streams, the `cell_rx` streams,
    /// and the client-bound cell stream are driven concurrently using [`PollAll`],
    /// this function can, in theory, deliver a stream message to the application layer,
    /// and send up to 2 cells per call:
    ///
    ///    * a client-bound cell carrying stream data
    ///    * a client-bound cell, forwarded from the backward channel
    ///
    /// However, in practice, leaky pipe is not really used,
    /// and so relays that have application streams (i.e. the exits),
    /// are not going to have a don't have a forward channel,
    /// and so this will only really drive stream data,
    /// executing at most 2 actions per call:
    ///
    ///   * deliver client-bound cell carrying stream data on the backward channel
    ///   * deliver one message worth of application-bound stream data received
    ///     over `cell_rx`
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        /// The maximum number of events we expect to handle per reactor loop.
        ///
        /// This is bounded by the number of futures we push into the PollAll.
        const PER_LOOP_EVENT_COUNT: usize = 3;

        // A collection of futures we plan to drive concurrently.
        let mut poll_all = PollAll::<PER_LOOP_EVENT_COUNT, CircuitEvent>::new();

        // Flush the backward channel sink, and check it for readiness
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
        let backward_chan_ready = future::poll_fn(|cx| {
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

        // Concurrently, drive :
        //  1. a future that reads from the ready application streams
        //  (this resolves to a message that needs to be delivered to the client)
        poll_all.push(async move {
            // Avoid polling the application streams if the outgoing sink is blocked
            let _ = backward_chan_ready.await;

            // Kludge to notify the other future that the backward chan is ready
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

            let ev = ready_streams_fut.await;

            CircuitEvent::Stream(ev)
        });

        //  2. the stream of stream data coming from the client
        //  (this resolves to a message that needs to be delivered to an application stream)
        poll_all.push(async {
            match self.cell_rx.next().await {
                Some((sid, msg)) => CircuitEvent::Stream(StreamEvent::ClientMsg { sid, msg }),
                None => {
                    // The forward reactor has crashed, so we have to shut down.
                    CircuitEvent::ForwardShutdown
                }
            }
        });

        // 3. Messages moving from the exit towards the client,
        // if we have a forward channel, **iff** the backward sink (towards the client)
        // is ready to accept them
        //
        // NOTE: in practice (ignoring leaky pipe), exits won't have a forward channel,
        // so the poll_all will only really drive the two stream-related futures
        // (for reading from and writing to the application streams)
        poll_all.push(async {
            // Avoid reading from the forward channel (if there even is one!)
            // if the outgoing sink is blocked.
            let () = rx.await.expect("streams_fut future disappeared?!");

            if let Some(input) = self.input.as_mut() {
                // Forward channel unexpectedly closed, we should close too
                match input.next().await {
                    Some(cell) => CircuitEvent::Cell(cell),
                    None => {
                        // The forward reactor has crashed, so we have to shut down.
                        CircuitEvent::ForwardShutdown
                    }
                }
            } else {
                future::pending().await
            }
        });

        let events = select_biased! {
            res = self.command.next() => {
                let Some(cmd) = res else {
                    trace!(
                        circ_id = %self.unique_id,
                        reason = "command channel drop",
                        "reactor shutdown",
                    );

                    return Err(ReactorError::Shutdown);
                };

                return self.handle_command(&cmd);
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

                return self.handle_control(&msg);
            },
            res = poll_all.fuse() => res,
        };

        // Note: there shouldn't be more than N < PER_LOOP_EVENT_COUNT events to handle
        // per reactor loop. We need to be careful here, because we must avoid blocking
        // the reactor.
        //
        // If handling more than one event per loop turns out to be a problem, we may
        // need to dispatch this to a background task instead.
        for event in events {
            self.handle_event(event).await?;
        }

        Ok(())
    }

    /// Handle a circuit event.
    async fn handle_event(&mut self, event: CircuitEvent) -> StdResult<(), ReactorError> {
        use CircuitEvent::*;

        match event {
            Stream(e) => self.handle_stream_event(e),
            Cell(cell) => self.handle_backward_cell(cell),
            ForwardShutdown => {
                // The forward reactor has crashed, so we have to shut down.
                trace!(
                    circ_id = %self.unique_id,
                    "Backward relay reactor shutdown (forward reactor has closed)",
                );

                Err(ReactorError::Shutdown)
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
            StreamEvent::ClientMsg { .. } => todo!(),
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

/// A circuit event that must be handled by the [`BackwardReactor`].
enum CircuitEvent {
    /// A stream event
    Stream(StreamEvent),
    /// We received a client-bound cell that needs to be handled.
    Cell(RelayCircChanMsg),
    /// The forward reactor has shut down.
    ///
    /// We need to shut down too.
    ForwardShutdown,
}

/// A stream-related event.
#[allow(unused)] // TODO(relay)
enum StreamEvent {
    /// A stream was closed.
    ///
    /// It needs to be removed from the reactor's stream map.
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
    /// Received a client stream message.
    ///
    /// This needs to be delivered to the specified application stream.
    ClientMsg {
        /// The ID of the stream to close.
        sid: StreamId,
        /// The message.
        msg: AnyRelayMsg,
    },
}
