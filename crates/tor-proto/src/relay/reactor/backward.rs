//! A relay's view of the backward (away from the exit, towards the client) state of the circuit.

use crate::channel::Channel;
use crate::circuit::cell_sender::CircuitCellSender;
use crate::circuit::circhop::{CircHopOutbound, HopSettings, SendRelayCell};
use crate::circuit::{CircSyncView, UniqId};
use crate::crypto::cell::{InboundRelayLayer, RelayCellBody};
use crate::memquota::SpecificAccount as _;
use crate::relay::RelayCircChanMsg;
use crate::relay::channel_provider::ChannelResult;
use crate::stream::CloseStreamBehavior;
use crate::stream::cmdcheck::StreamStatus;
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::incoming::{
    InboundDataCmdChecker, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestHandler, StreamReqInfo,
};
use crate::stream::queue::stream_queue;
use crate::streammap;
use crate::util::err::ReactorError;
use crate::util::notify::NotifySender;
use crate::util::poll_all::PollAll;
use crate::{Error, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{
    PaddingController, PaddingEventStream, QueuedCellPaddingInfo,
};

// TOOD(relay): is this right?
use crate::client::circuit::CIRCUIT_BUFFER_SIZE;

use tor_async_utils::{SinkTrySend as _, SinkTrySendError as _};
use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanCmd, CircId};
use tor_cell::relaycell::msg::{AnyRelayMsg, Begin, End, EndReason, Sendme, SendmeTag};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId, UnparsedRelayMsg};
use tor_error::{internal, into_internal, trace_report};
use tor_log_ratelim::log_ratelim;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};
use tor_rtcompat::{DynTimeProvider, Runtime, SleepProvider as _};

use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, future, select_biased};
use postage::{broadcast, watch};
use tracing::{debug, trace};

use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::Poll;

use super::CircuitRxReceiver;

/// The "backward" circuit reactor of a relay.
///
/// Handles the "backward direction": moves cells towards the client,
/// and drives the application streams.
///
/// Shuts downs down if an error occurs, or if either the [`Reactor`](super::Reactor)
/// or the [`ForwardReactor`](super::ForwardReactor) shuts down:
///
///   * if `Reactor` shuts down, we are alerted via the `shutdown_tx` broadcast channel
///     (we will notice this its closure in the main loop)
///   * if `ForwardReactor` shuts down, `Reactor` will notice, and itself shutdown
///     (as in the previous case, we will notice this because the `shutdown_tx` channel will close)
///
//
// NOTE: the reactor is currently a bit awkward, because it's generic over
// the target relay `BuildSpec`. This will become slightly less awkward when
// we refactor this and the client circuit reactor to be based on an abstract
// reactor type.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(super) struct BackwardReactor {
    /// The state of this circuit hop.
    hop: CircHopOutbound,
    /// The time provider.
    time_provider: DynTimeProvider,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The circuit identifier on the backward Tor channel.
    circ_id: CircId,
    /// The reading end of the forward Tor channel, if we are not the last hop.
    ///
    /// Yields cells moving from the exit towards the client.
    input: Option<CircuitRxReceiver>,
    /// The sending end of the backward Tor channel.
    ///
    /// Delivers cells towards the client.
    chan_sender: CircuitCellSender,
    /// The cryptographic state for this circuit for client-bound cells.
    crypto_in: Box<dyn InboundRelayLayer + Send>,
    /// Receiver for Tor stream data that need to be delivered to a Tor stream.
    ///
    /// The sender is in [`ForwardReactor`](super::ForwardReactor), which will forward all cells
    /// carrying Tor stream data to us.
    ///
    /// This serves a dual purpose:
    ///   * it enables the `ForwardReactor` to deliver Tor stream data received from the client
    ///   * it lets the `BackwardReactor` know if the `ForwardReactor` has shut down:
    ///     we select! on this MPSC channel in the main loop, so if the `ForwardReactor`
    ///     shuts down, we will get EOS upon calling `.next()`)
    cell_rx: mpsc::Receiver<BackwardReactorCmd>,
    /// A sender for sending newly opened outgoing [`Channel`]`s to the reactor.
    ///
    /// This is passed to the [`ChannelProvider`](crate::relay::channel_provider::ChannelProvider)
    /// for each Tor channel request.
    outgoing_chan_tx: mpsc::UnboundedSender<ChannelResult>,
    /// A handler for incoming streams.
    incoming: IncomingStreamRequestHandler,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
    /// An event stream telling us about padding-related events.
    padding_event_stream: PaddingEventStream,
    /// A broadcast receiver used to detect when the
    /// [`Reactor`](super::Reactor) or
    /// [`ForwardReactor`](super::ForwardReactor) are dropped.
    shutdown_rx: broadcast::Receiver<void::Void>,
}

// TODO(relay): consider moving some of the BackwardReactor fields
// to a new Backward struct (to keep it more manageable, and for symmetry
// with the ForwardReactor design).
//
// TODO(relay): while doing this, consider moving some of the complexity
// out of the reactor impl:
//
// https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3369#note_3277225

#[allow(unused)] // TODO(relay)
impl BackwardReactor {
    /// Create a new [`BackwardReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new<R: Runtime>(
        runtime: R,
        channel: &Arc<Channel>,
        hop: CircHopOutbound,
        circ_id: CircId,
        unique_id: UniqId,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        settings: &HopSettings,
        cell_rx: mpsc::Receiver<BackwardReactorCmd>,
        outgoing_chan_tx: mpsc::UnboundedSender<ChannelResult>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        incoming: IncomingStreamRequestHandler,
        shutdown_rx: broadcast::Receiver<void::Void>,
    ) -> Self {
        let chan_sender = CircuitCellSender::from_channel_sender(channel.sender());

        Self {
            hop,
            time_provider: DynTimeProvider::new(runtime),
            input: None,
            chan_sender,
            crypto_in,
            unique_id,
            circ_id,
            outgoing_chan_tx,
            incoming,
            cell_rx,
            padding_ctrl,
            padding_event_stream,
            shutdown_rx,
        }
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
    /// that need to be delivered to the client, and the `cells_rx` MPSC stream
    /// for client messages received via the `ForwardReactor`
    /// that need to be delivered to the application.
    ///
    /// Because the application streams, the `cell_rx` MPSC streams,
    /// and the client-bound cell MPSC stream are driven concurrently using [`PollAll`],
    /// this function can, in theory, deliver a stream message to the application layer,
    /// and send up to 2 cells per call:
    ///
    ///    * a client-bound cell carrying Tor stream data
    ///    * a client-bound cell, forwarded from the backward Tor channel
    ///
    /// However, in practice, leaky pipe is not really used,
    /// and so relays that have application streams (i.e. the exits),
    /// are not going to have a forward Tor channel,
    /// and so this will only really drive Tor stream data,
    /// executing at most 2 actions per call:
    ///
    ///   * deliver client-bound cell carrying Tor stream data on the backward Tor channel
    ///   * deliver one message worth of application-bound Tor stream data received
    ///     over `cell_rx`
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        use postage::prelude::{Sink as _, Stream as _};

        /// The maximum number of events we expect to handle per reactor loop.
        ///
        /// This is bounded by the number of futures we push into the PollAll.
        const PER_LOOP_EVENT_COUNT: usize = 3;

        // A collection of futures we plan to drive concurrently.
        let mut poll_all = PollAll::<PER_LOOP_EVENT_COUNT, CircuitEvent>::new();

        // Flush the backward Tor channel sink, and check it for readiness
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

        let mut streams = Arc::clone(self.hop.stream_map());
        let ready_streams_fut = future::poll_fn(move |cx| {
            let mut streams = streams.lock().expect("lock poisoned");
            let Some((sid, msg)) = streams.poll_ready_streams_iter(cx).next() else {
                // No ready streams
                //
                // TODO(flushing): if there are no ready Tor streams, we might want to defer
                // flushing until stream data becomes available (or until a timeout elapses).
                // The deferred flushing approach should enable us to send
                // more than one message at a time to the channel reactor.
                return Poll::Pending;
            };

            if msg.is_none() {
                // This means the local sender has been dropped,
                // which presumably can only happen if an error occurs,
                // or if the Tor stream ends. In both cases, we're going to
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

        let cc_can_send = self.hop.ccontrol().can_send();

        // Concurrently, drive :
        //  1. a future that reads from the ready application streams
        //  (this resolves to a message that needs to be delivered to the client)
        poll_all.push(async move {
            if !cc_can_send {
                // We can't send anything on this hop that counts towards SENDME windows.
                //
                // Note: this does not block outgoing flow-control messages:
                //
                //   * circuit SENDMEs are initiated by the forward reactor,
                //     by sending a BackwardReactorCmd::SendSendme to us,
                //     which is received via cell_tx below
                //   * stream SENDMEs will be initiated by StreamTarget::send_sendme(),
                //     by sending a a control message to the reactor
                //     (TODO(relay): not yet implemented)
                //   * XOFFs are sent in response to messages on streams
                //     (i.e. RELAY messages with non-zero stream IDs).
                //     These messages are delivered to us by the forward reactor
                //     inside BackwardReactorCmd::HandleMsg
                //   * XON will be initiated by StreamTarget::drain_rate_update(),
                //     by sending a control message to the reactor
                //     (TODO(relay): not yet implemented)
                let () = future::pending().await;
            }

            let ev = ready_streams_fut.await;

            CircuitEvent::Stream(ev)
        });

        //  2. the stream of Tor stream data coming from the client
        //  (this resolves to a message that needs to be delivered to an application stream)
        poll_all.push(async {
            match self.cell_rx.next().await {
                Some(msg) => CircuitEvent::Forwarded(msg),
                None => {
                    // The forward reactor has crashed, so we have to shut down.
                    CircuitEvent::ForwardShutdown
                }
            }
        });

        // 3. Messages moving from the exit towards the client,
        // if we have a forward Tor channel.
        // NOTE: in practice (ignoring leaky pipe), exits won't have a forward Tor channel,
        // so the poll_all will only really drive the two Tor stream-related futures
        // (for reading from and writing to the application streams)
        poll_all.push(async {
            if let Some(input) = self.input.as_mut() {
                // Forward channel unexpectedly closed, we should close too
                match input.next().await {
                    Some(msg) => match msg.try_into() {
                        Err(e) => CircuitEvent::ProtoViolation(e),
                        Ok(cell) => CircuitEvent::Cell(cell),
                    },
                    None => {
                        // The forward reactor has crashed, so we have to shut down.
                        CircuitEvent::ForwardShutdown
                    }
                }
            } else {
                future::pending().await
            }
        });

        let poll_all = async move {
            // Avoid polling **any** of the futures if the outgoing sink is blocked.
            //
            // This implements backpressure: we avoid reading from our input sources
            // if we know we're unable to write to the backward sink.
            //
            // More specifically, if our sink towards the client is full and can no longer
            // accept cells, we stop reading:
            //
            //   1. From the application streams, if we have any.
            //
            //   2. From the cell_rx channel, used by the forward reactor to send us
            //     - a circuit-level SENDME that we have received, or
            //     - a circuit-level SENDME that we need to deliver to the client, or
            //     - a stream message that needs to be handled by our application streams
            //
            //     Not reading from the cell_rx channel, in turn, causes the forward reactor
            //     to block and therefore stop reading from **its** input sources,
            //     propagating backpressure all the way to the client.
            //
            //   3. From the Tor channel towards the exit, if there is one.
            //
            // This will delay any SENDMEs the client or exit might have sent along
            // the way, and therefore count as a congestion signal.
            //
            // TODO: memquota setup to make sure this doesn't turn into a memory DOS vector
            let _ = backward_chan_ready.await;

            poll_all.await
        };

        let events = select_biased! {
            _res = self.shutdown_rx.next().fuse() => {
                trace!(
                    circ_id = %self.unique_id,
                    "Forward relay reactor shutdown (received shutdown signal)",
                );

                return Err(ReactorError::Shutdown);
            }
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
            Stream(e) => self.handle_stream_event(e).await,
            Cell(cell) => self.handle_backward_cell(cell),
            Forwarded(msg) => self.handle_reactor_cmd(msg).await,
            ForwardShutdown => {
                // The forward reactor has crashed, so we have to shut down.
                trace!(
                    circ_id = %self.unique_id,
                    "Backward relay reactor shutdown (forward reactor has closed)",
                );

                Err(ReactorError::Shutdown)
            }
            ProtoViolation(err) => Err(err.into()),
        }
    }

    /// Handle a command sent to us by the forward reactor.
    ///
    /// This is either a message destined to us, or a circuit-level SENDME
    /// we need to send to the client.
    async fn handle_reactor_cmd(&mut self, msg: BackwardReactorCmd) -> StdResult<(), ReactorError> {
        use BackwardReactorCmd::*;

        let cell = match msg {
            HandleMsg {
                sid,
                msg,
                cell_counts_toward_windows,
            } => self.handle_msg(sid, msg, cell_counts_toward_windows)?,
            HandleSendme(sendme) => {
                self.handle_sendme(sendme).await?;
                None
            }
            SendSendme(sendme) => todo!(),
        };

        if let Some(SendRelayCell {
            hop: _,
            early,
            cell,
        }) = cell
        {
            // Note: if we reach this point, it means we are ready to send at least one cell
            // over the backward channel (because in the reactor main loop, we only read from
            // the cell_rx MPSC channel if chan_sender is ready)
            self.send_msg_to_client(cell, None).await?;
        }

        Ok(())
    }

    /// Handle a RELAY message that has a non-zero stream ID.
    ///
    // TODO(relay): this is very similar to the client impl from
    // Circuit::handle_in_order_relay_msg()
    fn handle_msg(
        &mut self,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
        cell_counts_toward_windows: bool,
    ) -> StdResult<Option<SendRelayCell>, ReactorError> {
        let cmd = msg.cmd();
        let possible_proto_violation_err = move |streamid: StreamId| {
            Error::StreamProto(format!(
                "Unexpected {cmd:?} message on unknown stream {streamid}"
            ))
        };
        let now = self.time_provider.now();

        // Check if any of our already-open streams want this message
        let res = self.hop.handle_msg(
            possible_proto_violation_err,
            cell_counts_toward_windows,
            streamid,
            msg,
            now,
        )?;

        // If it was an incoming stream request, we don't need to worry about
        // sending an XOFF as there's no stream data within this message.
        if let Some(msg) = res {
            return self.handle_incoming_stream_request(streamid, msg);
        }

        // We may want to send an XOFF if the incoming buffer is too large.
        if let Some(cell) = self.hop.maybe_send_xoff(streamid)? {
            let cell = AnyRelayMsgOuter::new(Some(streamid), cell.into());
            let cell = SendRelayCell {
                hop: None,
                early: false,
                cell,
            };

            return Ok(Some(cell));
        }

        Ok(None)
    }

    /// A helper for handling incoming stream requests.
    fn handle_incoming_stream_request(
        &mut self,
        sid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> StdResult<Option<SendRelayCell>, ReactorError> {
        let message_closes_stream =
            self.incoming.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        if message_closes_stream {
            self.hop
                .stream_map()
                .lock()
                .expect("poisoned lock")
                .ending_msg_received(sid)?;

            return Ok(None);
        }

        let req = parse_incoming_stream_req(msg)?;
        if let Some(reject) = self.should_reject_incoming(sid, &req)? {
            // We can't honor this request, so we bail by sending an END.
            Ok(Some(reject))
        } else {
            self.accept_incoming_stream(sid, req)
        }
    }

    /// Check if we should reject this incoming stream request or not.
    ///
    /// Returns a cell we need to send back to the client if we must reject the request,
    /// or `None` if we are allowed to accept it.
    ///`
    /// Any error returned from this function will shut down the reactor.
    fn should_reject_incoming(
        &mut self,
        sid: StreamId,
        request: &IncomingStreamRequest,
    ) -> StdResult<Option<SendRelayCell>, ReactorError> {
        use IncomingStreamRequestDisposition::*;

        let ctx = IncomingStreamRequestContext { request };

        // TODO(relay): put something in the sync view??
        let view = CircSyncView::new_relay();

        // Run the externally provided filter to check if we should
        // open the stream or not.
        match self.incoming.filter.as_mut().disposition(&ctx, &view)? {
            Accept => {
                // All is well, we can accept the stream request
                Ok(None)
            }
            CloseCircuit => Err(ReactorError::Shutdown),
            RejectRequest(end) => {
                let end_msg = AnyRelayMsgOuter::new(Some(sid), end.into());

                let cell = SendRelayCell {
                    hop: None,
                    early: false,
                    cell: end_msg,
                };

                Ok(Some(cell))
            }
        }
    }

    /// Accept the specified incoming stream request,
    /// by adding a new entry to our stream map.
    ///
    /// Returns the cell we need to send back to the client,
    /// if an error occurred and the stream cannot be opened.
    ///
    /// Returns None if everything went well
    /// (the CONNECTED response only comes if the external
    /// consumer of our [Stream](futures::Stream) of incoming Tor streams
    /// is able to actually establish the connection to the address
    /// specified in the BEGIN).
    ///
    /// Any error returned from this function will shut down the reactor.
    fn accept_incoming_stream(
        &mut self,
        sid: StreamId,
        req: IncomingStreamRequest,
    ) -> StdResult<Option<SendRelayCell>, ReactorError> {
        // TOOD(relay): hook the reactors up to the memquota system
        let memquota = todo!();

        let (sender, receiver) = stream_queue(
            #[cfg(not(feature = "flowctl-cc"))]
            STREAM_READER_BUFFER,
            &memquota,
            self.chan_sender.time_provider(),
        )
        .map_err(|e| ReactorError::Err(e.into()))?;

        let (msg_tx, msg_rx) = MpscSpec::new(CIRCUIT_BUFFER_SIZE)
            .new_mq(
                self.chan_sender.time_provider().clone(),
                memquota.as_raw_account(),
            )
            .map_err(|e| ReactorError::Err(e.into()))?;

        let (rate_limit_tx, rate_limit_rx) = watch::channel_with(StreamRateLimit::MAX);

        // A channel for the reactor to request a new drain rate from the reader.
        // Typically this notification will be sent after an XOFF is sent so that the reader can
        // send us a new drain rate when the stream data queue becomes empty.
        let mut drain_rate_request_tx = NotifySender::new_typed();
        let drain_rate_request_rx = drain_rate_request_tx.subscribe();

        let cmd_checker = InboundDataCmdChecker::new_connected();
        self.hop.add_ent_with_id(
            sender,
            msg_rx,
            rate_limit_tx,
            drain_rate_request_tx,
            sid,
            cmd_checker,
        )?;

        let outcome = Pin::new(&mut self.incoming.incoming_sender).try_send(StreamReqInfo {
            req,
            stream_id: sid,
            hop: None,
            msg_tx,
            receiver,
            rate_limit_stream: rate_limit_rx,
            drain_rate_request_stream: drain_rate_request_rx,
            memquota,
            relay_cell_format: self.hop.relay_cell_format(),
        });

        log_ratelim!("Delivering message to incoming stream handler"; outcome);

        if let Err(e) = outcome {
            if e.is_full() {
                // The IncomingStreamRequestHandler's stream is full; it isn't
                // handling requests fast enough. So instead, we reply with an
                // END cell.
                let end_msg = AnyRelayMsgOuter::new(
                    Some(sid),
                    End::new_with_reason(EndReason::RESOURCELIMIT).into(),
                );

                let cell = SendRelayCell {
                    hop: None,
                    early: false,
                    cell: end_msg,
                };

                return Ok(Some(cell));
            } else if e.is_disconnected() {
                // The IncomingStreamRequestHandler's stream has been dropped.
                // In the Tor protocol as it stands, this always means that the
                // circuit itself is out-of-use and should be closed.
                //
                // Note that we will _not_ reach this point immediately after
                // the IncomingStreamRequestHandler is dropped; we won't hit it
                // until we next get an incoming request.  Thus, if we later
                // want to add early detection for a dropped
                // IncomingStreamRequestHandler, we need to do it elsewhere, in
                // a different way.
                debug!(
                    circ_id = %self.unique_id,
                    "Incoming stream request receiver dropped",
                );
                // This will _cause_ the circuit to get closed.
                return Err(ReactorError::Err(Error::CircuitClosed));
            } else {
                // There are no errors like this with the current design of
                // futures::mpsc, but we shouldn't just ignore the possibility
                // that they'll be added later.
                return Err(
                    Error::from((into_internal!("try_send failed unexpectedly"))(e)).into(),
                );
            }
        }

        Ok(None)
    }

    /// Handle a circuit-level SENDME (stream ID = 0).
    ///
    /// Returns an error if the SENDME does not have an authentication tag
    /// (versions of Tor <=0.3.5 omit the SENDME tag, but we don't support
    /// those any longer).
    ///
    /// Any error returned from this function will shut down the reactor.
    ///
    // TODO(relay): this duplicates the logic from the client reactor's
    // handle_sendme() function
    async fn handle_sendme(&mut self, sendme: Sendme) -> StdResult<(), ReactorError> {
        let tag = sendme
            .into_sendme_tag()
            .ok_or_else(|| Error::CircProto("missing tag on circuit sendme".into()))?;

        // NOTE: it's okay to await. We are only awaiting on the congestion_signals
        // future which *should* resolve immediately
        let signals = self.chan_sender.congestion_signals().await;

        // Update the CC object that we received a SENDME along
        // with possible congestion signals.
        self.hop
            .ccontrol()
            .note_sendme_received(&self.time_provider, tag, signals)?;

        Ok(())
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
            .encode(self.hop.relay_cell_format(), &mut rand::rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();

        let tag = self.crypto_in.originate(ChanCmd::RELAY, &mut body);
        let msg = Relay::from(BoxedCellBody::from(body));
        let msg = AnyChanMsg::Relay(msg);

        Ok((msg, tag))
    }

    /// Send a RELAY cell with the specified `msg` to the client.
    async fn send_msg_to_client(
        &mut self,
        msg: AnyRelayMsgOuter,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError> {
        let (msg, tag) = self.encode_clientbound_relay_cell(self.hop.relay_cell_format(), msg)?;
        let cell = AnyChanCell::new(Some(self.circ_id), msg);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the async streams, so await won't block.
        Pin::new(&mut self.chan_sender)
            .send_unbounded((cell, info))
            .await?;

        Ok(())
    }

    /// Handle a [`StreamEvent`].
    async fn handle_stream_event(&mut self, event: StreamEvent) -> StdResult<(), ReactorError> {
        match event {
            StreamEvent::Closed { .. } => todo!(),
            StreamEvent::ReadyMsg { sid, msg } => {
                let msg = AnyRelayMsgOuter::new(Some(sid), msg);
                self.send_msg_to_client(msg, None).await
            }
        }
    }

    /// Handle a backward cell (moving from the exit towards the client).
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_backward_cell(&mut self, _cell: RelayCircChanMsg) -> StdResult<(), ReactorError> {
        Err(internal!("Cell relaying is not implemented").into())
    }
}

/// A circuit event that must be handled by the [`BackwardReactor`].
enum CircuitEvent {
    /// A Tor stream event
    Stream(StreamEvent),
    /// We received a client-bound cell that needs to be handled.
    Cell(RelayCircChanMsg),
    /// We received a cell from the ForwardReactor that we need to handle.
    ///
    /// This might be
    ///
    ///   * a circuit-level SENDME that we have received, or
    ///   * a circuit-level SENDME that we need to deliver to the client, or
    ///   * a stream message that needs to be handled by our application streams
    Forwarded(BackwardReactorCmd),
    /// The forward reactor has shut down.
    ///
    /// We need to shut down too.
    ForwardShutdown,
    /// Protocol violation.
    ///
    /// This can happen if we receive a channel message that is not supported
    /// on a relay-to-relay channel. The error is the cause of the violation.
    ProtoViolation(Error),
}

/// Instructions from the forward reactor.
pub(super) enum BackwardReactorCmd {
    /// Stream data received from the client
    /// that needs to be handled by [`BackwardReactor`].
    HandleMsg {
        /// The ID of the stream this message is for.
        sid: StreamId,
        /// The message.
        msg: UnparsedRelayMsg,
        /// Whether the cell this message came from counts towards flow-control windows.
        cell_counts_toward_windows: bool,
    },
    /// A circuit SENDME we received from the client.
    HandleSendme(Sendme),
    /// A circuit SENDME we need to send to the client.
    SendSendme(Sendme),
}

/// A Tor stream-related event.
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
}

/// Convert an incoming stream request message (BEGIN, BEGIN_DIR, RESOLVE, etc.)
/// to an [`IncomingStreamRequest`]
fn parse_incoming_stream_req(msg: UnparsedRelayMsg) -> crate::Result<IncomingStreamRequest> {
    // TODO(relay): support other stream-initiating messages, not just BEGIN
    let begin = msg
        .decode::<Begin>()
        .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
        .into_msg();

    Ok(IncomingStreamRequest::Begin(begin))
}
