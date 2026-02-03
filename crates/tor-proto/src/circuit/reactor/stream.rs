//! The stream reactor.

use crate::circuit::UniqId;
use crate::circuit::circhop::CircHopOutbound;
use crate::circuit::reactor::macros::derive_deftly_template_CircuitReactor;
use crate::congestion::{CongestionControl, sendme};
use crate::memquota::{CircuitAccount, SpecificAccount as _, StreamAccount};
use crate::stream::CloseStreamBehavior;
use crate::stream::cmdcheck::StreamStatus;
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::queue::stream_queue;
use crate::streammap;
use crate::util::err::ReactorError;
use crate::util::notify::NotifySender;
use crate::util::timeout::TimeoutEstimator;
use crate::{Error, HopNum};

#[cfg(any(feature = "hs-service", feature = "relay"))]
use crate::stream::incoming::{
    InboundDataCmdChecker, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestHandler, StreamReqInfo,
};

use tor_async_utils::{SinkTrySend as _, SinkTrySendError as _};
use tor_cell::relaycell::msg::{AnyRelayMsg, Begin, End, EndReason};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId, UnparsedRelayMsg};
use tor_error::into_internal;
use tor_log_ratelim::log_ratelim;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};
use tor_rtcompat::{DynTimeProvider, Runtime, SleepProvider as _};

use derive_deftly::Deftly;
use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt as _, future, select_biased};
use postage::watch;
use tracing::debug;

use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

/// Size of the buffer for communication between a StreamTarget and the reactor.
///
// TODO(tuning): figure out if this is a good size for this buffer
const CIRCUIT_BUFFER_SIZE: usize = 128;

/// The stream reactor for a given hop.
///
/// Drives the application streams.
///
/// This reactor accepts [`StreamMsg`]s from the forward reactor over its [`Self::cell_rx`]
/// MPSC channel, and delivers them to the corresponding stream entries in the stream map.
///
/// The local streams are polled from the main loop, and any ready messages are sent
/// to the backward reactor over the `bwd_tx` MPSC channel for packaging and delivery.
///
/// Shuts downs down if an error occurs, or if the sending end
/// of the `cell_rx` MPSC channel, i.e. the forward reactor, closes.
#[derive(Deftly)]
#[derive_deftly(CircuitReactor)]
#[deftly(reactor_name = "stream reactor")]
#[deftly(run_inner_fn = "Self::run_once")]
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct StreamReactor {
    /// The hop this stream reactor is for.
    ///
    /// This is `None` for relays.
    hopnum: Option<HopNum>,
    /// The state of this circuit hop.
    hop: CircHopOutbound,
    /// The time provider.
    time_provider: DynTimeProvider,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// Receiver for Tor stream data that need to be delivered to a Tor stream.
    ///
    /// The sender is in [`ForwardReactor`](super::ForwardReactor), which will forward all cells
    /// carrying Tor stream data to us.
    ///
    /// This serves a dual purpose:
    ///
    ///   * it enables the `ForwardReactor` to deliver Tor stream data received from the client
    ///   * it lets the `StreamReactor` know if the `ForwardReactor` has shut down:
    ///     we select! on this MPSC channel in the main loop, so if the `ForwardReactor`
    ///     shuts down, we will get EOS upon calling `.next()`)
    cell_rx: mpsc::Receiver<StreamMsg>,
    /// Sender for sending Tor stream data to [`BackwardReactor`](super::BackwardReactor).
    bwd_tx: mpsc::Sender<ReadyStreamMsg>,
    /// A handler for incoming streams.
    ///
    /// Set to `None` if incoming streams are not allowed on this circuit.
    ///
    /// This handler is shared with the [`HopMgr`](super::hop_mgr::HopMgr) of this reactor,
    /// which can install a new handler at runtime (for example, in response to a CtrlMsg).
    /// The ability to update the handler after the reactor is launched is needed
    /// for onion services, where the incoming stream request handler only gets installed
    /// after the virtual hop is created.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    incoming: Arc<Mutex<Option<IncomingStreamRequestHandler>>>,
    /// The circuit timeout estimator.
    ///
    /// Used for computing half-stream expiration.
    timeouts: Arc<dyn TimeoutEstimator>,
    /// Memory quota account
    memquota: CircuitAccount,
}

#[allow(unused)] // TODO(relay)
impl StreamReactor {
    /// Create a new [`StreamReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(crate) fn new<R: Runtime>(
        runtime: R,
        hopnum: Option<HopNum>,
        hop: CircHopOutbound,
        unique_id: UniqId,
        cell_rx: mpsc::Receiver<StreamMsg>,
        bwd_tx: mpsc::Sender<ReadyStreamMsg>,
        timeouts: Arc<dyn TimeoutEstimator>,
        #[cfg(any(feature = "hs-service", feature = "relay"))] //
        incoming: Arc<Mutex<Option<IncomingStreamRequestHandler>>>,
        memquota: CircuitAccount,
    ) -> Self {
        Self {
            hopnum,
            hop,
            time_provider: DynTimeProvider::new(runtime),
            unique_id,
            #[cfg(any(feature = "hs-service", feature = "relay"))]
            incoming,
            cell_rx,
            bwd_tx,
            timeouts,
            memquota,
        }
    }

    /// Helper for [`run`](Self::run).
    ///
    /// Polls the stream map for messages
    /// that need to be delivered to the other endpoint,
    /// and the `cells_rx` MPSC stream for stream messages received
    /// from the `ForwardReactor` that need to be delivered to the application streams.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        use postage::prelude::{Sink as _, Stream as _};

        // Garbage-collect all halfstreams that have expired.
        //
        // Note: this will iterate over the closed streams of this hop.
        // If we think this will cause perf issues, one idea would be to make
        // StreamMap::closed_streams into a min-heap, and add a branch to the
        // select_biased! below to sleep until the first expiry is due
        // (but my gut feeling is that iterating is cheaper)
        self.hop
            .stream_map()
            .lock()
            .expect("poisoned lock")
            .remove_expired_halfstreams(self.time_provider.now());

        let mut streams = Arc::clone(self.hop.stream_map());
        let can_send = self
            .hop
            .ccontrol()
            .lock()
            .expect("poisoned lock")
            .can_send();
        let mut ready_streams_fut = future::poll_fn(move |cx| {
            if !can_send {
                // We can't send anything on this hop that counts towards SENDME windows.
                //
                // Note: this does not block outgoing flow-control messages:
                //
                //   * circuit SENDMEs are initiated by the forward reactor,
                //     by sending a BackwardReactorCmd::SendRelayMsg to BWD,
                //   * stream SENDMEs will be initiated by StreamTarget::send_sendme(),
                //     by sending a a control message to the reactor
                //     (TODO(relay): not yet implemented)
                //   * XOFFs are sent in response to messages on streams
                //     (i.e. RELAY messages with non-zero stream IDs).
                //     These messages are delivered to us by the forward reactor
                //     inside BackwardReactorCmd::HandleMsg
                //   * XON will be initiated by StreamTarget::drain_rate_update(),
                //     by sending a control message to the reactor
                //     (TODO(relay): not yet implemented)\
                return Poll::Pending;
            }

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

        select_biased! {
            res = self.cell_rx.next().fuse() => {
                let Some(cmd) = res else {
                    // The forward reactor has shut down
                    return Err(ReactorError::Shutdown);
                };

                self.handle_reactor_cmd(cmd).await?;
            }
            event = ready_streams_fut.fuse() => {
                self.handle_stream_event(event).await?;
            }
        }

        Ok(())
    }

    /// Handle a stream message sent to us by the forward reactor.
    ///
    /// Delivers the message to its corresponding application stream.
    async fn handle_reactor_cmd(&mut self, msg: StreamMsg) -> StdResult<(), ReactorError> {
        let StreamMsg {
            sid,
            msg,
            cell_counts_toward_windows,
        } = msg;

        // We need to apply stream-level flow control *before* encoding the message.
        let msg = self.handle_msg(sid, msg, cell_counts_toward_windows)?;

        // TODO(DEDUP): this contains parts of Circuit::send_relay_cell_inner()
        if let Some(msg) = msg {
            // We might be out of capacity entirely; see if we are about to hit a limit.
            //
            // TODO: If we ever add a notion of _recoverable_ errors below, we'll
            // need a way to restore this limit, and similarly for about_to_send().
            self.hop.decrement_cell_limit()?;

            let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());

            // We need to apply stream-level flow control *before* encoding the message
            // (the BWD handles the encoding)
            if c_t_w {
                if let Some(stream_id) = msg.stream_id() {
                    self.hop
                        .about_to_send(self.unique_id, stream_id, msg.msg())?;
                }
            }

            // NOTE: on the client side, we call note_data_sent()
            // just before writing the cell to the channel.
            // We can't do that here, because we're not the ones
            // encoding the cell, so we don't have the SENDME tag
            // which is needed for note_data_sent().
            //
            // Instead, we notify the CC algorithm in the BWD,
            // right after we've finished sending the cell.

            self.send_msg_to_bwd(msg).await?;
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
    ) -> StdResult<Option<AnyRelayMsgOuter>, ReactorError> {
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
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "hs-service", feature = "relay"))] {
                    return self.handle_incoming_stream_request(streamid, msg);
                } else {
                    return Err(
                        tor_error::internal!(
                            "incoming stream not rejected, but relay and hs-service features are disabled?!"
                            ).into()
                    );
                }
            }
        }

        // We may want to send an XOFF if the incoming buffer is too large.
        if let Some(cell) = self.hop.maybe_send_xoff(streamid)? {
            let cell = AnyRelayMsgOuter::new(Some(streamid), cell.into());
            return Ok(Some(cell));
        }

        Ok(None)
    }

    /// A helper for handling incoming stream requests.
    ///
    /// Accepts the specified incoming stream request,
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
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    fn handle_incoming_stream_request(
        &mut self,
        sid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> StdResult<Option<AnyRelayMsgOuter>, ReactorError> {
        let mut lock = self.incoming.lock().expect("poisoned lock");
        let Some(handler) = lock.as_mut() else {
            return Err(
                Error::CircProto("Cannot handle BEGIN cells on this circuit".into()).into(),
            );
        };

        if self.hopnum != handler.hop_num {
            let expected_hopnum = match handler.hop_num {
                Some(hopnum) => hopnum.display().to_string(),
                None => "client".to_string(),
            };

            let actual_hopnum = match self.hopnum {
                Some(hopnum) => hopnum.display().to_string(),
                None => "None".to_string(),
            };

            return Err(Error::CircProto(format!(
                "Expecting incoming streams from {}, but received {} cell from unexpected hop {}",
                expected_hopnum,
                msg.cmd(),
                actual_hopnum,
            ))
            .into());
        }

        let message_closes_stream = handler.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        if message_closes_stream {
            self.hop
                .stream_map()
                .lock()
                .expect("poisoned lock")
                .ending_msg_received(sid)?;

            return Ok(None);
        }

        let req = parse_incoming_stream_req(msg)?;
        if let Some(reject) = Self::should_reject_incoming(handler, sid, &req)? {
            // We can't honor this request, so we bail by sending an END.
            return Ok(Some(reject));
        };

        let memquota =
            StreamAccount::new(&self.memquota).map_err(|e| ReactorError::Err(e.into()))?;

        let (sender, receiver) = stream_queue(
            #[cfg(not(feature = "flowctl-cc"))]
            crate::stream::STREAM_READER_BUFFER,
            &memquota,
            &self.time_provider,
        )
        .map_err(|e| ReactorError::Err(e.into()))?;

        let (msg_tx, msg_rx) = MpscSpec::new(CIRCUIT_BUFFER_SIZE)
            .new_mq(self.time_provider.clone(), memquota.as_raw_account())
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

        let outcome = Pin::new(&mut handler.incoming_sender).try_send(StreamReqInfo {
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

                return Ok(Some(end_msg));
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

    /// Check if we should reject this incoming stream request or not.
    ///
    /// Returns a cell we need to send back to the client if we must reject the request,
    /// or `None` if we are allowed to accept it.
    ///`
    /// Any error returned from this function will shut down the reactor.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    fn should_reject_incoming(
        handler: &mut IncomingStreamRequestHandler,
        sid: StreamId,
        request: &IncomingStreamRequest,
    ) -> StdResult<Option<AnyRelayMsgOuter>, ReactorError> {
        use IncomingStreamRequestDisposition::*;

        let ctx = IncomingStreamRequestContext { request };

        // TODO: this is supposed to take either a CircSyncView::Client,
        // or a CircSynvView::Relay, but this function is implementation-agnostic,
        // so we don't know whether we're a client or a relay!
        //
        // This needs a bit of a redesign: perhaps CircSynvView shouldn't be an enum,
        // but instead an implementation-agnostic wrapper object that provides
        // the n_open_streams() API.
        let view = todo!();

        // Run the externally provided filter to check if we should
        // open the stream or not.
        match handler.filter.as_mut().disposition(&ctx, &view)? {
            Accept => {
                // All is well, we can accept the stream request
                Ok(None)
            }
            CloseCircuit => Err(ReactorError::Shutdown),
            RejectRequest(end) => {
                let end_msg = AnyRelayMsgOuter::new(Some(sid), end.into());

                Ok(Some(end_msg))
            }
        }
    }

    /// Handle a [`StreamEvent`].
    async fn handle_stream_event(&mut self, event: StreamEvent) -> StdResult<(), ReactorError> {
        match event {
            StreamEvent::Closed { sid, behav, reason } => {
                let max_rtt = {
                    let mut ccontrol = self.hop.ccontrol().lock().expect("poisoned lock");

                    // Note: if we have no measurements for the RTT, this will be set to 0,
                    // and the timeout will be 2 * CBT.
                    ccontrol
                        .rtt()
                        .max_rtt_usec()
                        .map(|rtt| Duration::from_millis(u64::from(rtt)))
                        .unwrap_or_default()
                };

                // The length of the circuit up until the hop that has the half-streeam.
                //
                // +1, because HopNums are zero-based.
                //
                /// If we're an exit, the estimated circ_len is hard-coded to 3.
                /// TODO: But maybe we need a better way of estimating the circuit length here?...
                const FALLBACK_CIRC_HOP: usize = 2;
                let circ_len = self.hopnum.map(usize::from).unwrap_or(FALLBACK_CIRC_HOP) + 1;

                // We double the CBT to account for rend circuits,
                // which are twice as long (otherwise we risk expiring
                // the rend half-streams too soon).
                let timeout = std::cmp::max(max_rtt, 2 * self.estimate_cbt(circ_len));
                let expire_at = self.time_provider.now() + timeout;
                let res =
                    self.hop
                        .close_stream(self.unique_id, sid, None, behav, reason, expire_at)?;
                let Some(msg) = res else {
                    // We may not need to send anything at all...
                    return Ok(());
                };

                self.send_msg_to_bwd(msg.cell).await
            }
            StreamEvent::ReadyMsg { sid, msg } => {
                self.send_msg_to_bwd(AnyRelayMsgOuter::new(Some(sid), msg))
                    .await
            }
        }
    }

    /// Wrap `msg` in [`ReadyStreamMsg`], and send it to the backward reactor.
    async fn send_msg_to_bwd(&mut self, msg: AnyRelayMsgOuter) -> StdResult<(), ReactorError> {
        let msg = ReadyStreamMsg {
            hop: self.hopnum,
            relay_cell_format: self.hop.relay_cell_format(),
            ccontrol: Arc::clone(self.hop.ccontrol()),
            msg,
        };

        self.bwd_tx
            .send(msg)
            .await
            .map_err(|_| ReactorError::Shutdown)?;

        Ok(())
    }

    /// The estimated circuit build timeout for a circuit of the specified length.
    ///
    /// Note: this duplicates the client implementation
    fn estimate_cbt(&self, length: usize) -> Duration {
        self.timeouts.circuit_build_timeout(length)
    }
}

/// A Tor stream-related event.
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
#[cfg(any(feature = "hs-service", feature = "relay"))]
fn parse_incoming_stream_req(msg: UnparsedRelayMsg) -> crate::Result<IncomingStreamRequest> {
    // TODO(relay): support other stream-initiating messages, not just BEGIN
    let begin = msg
        .decode::<Begin>()
        .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
        .into_msg();

    Ok(IncomingStreamRequest::Begin(begin))
}

/// A stream message to be sent to the backward reactor for delivery.
pub(crate) struct ReadyStreamMsg {
    /// The hop number, or `None` if we are a relay.
    pub(crate) hop: Option<HopNum>,
    /// The message to send.
    pub(crate) msg: AnyRelayMsgOuter,
    /// The cell format used with the hop the message should be sent to.
    pub(crate) relay_cell_format: RelayCellFormat,
    /// The CC object to use.
    pub(crate) ccontrol: Arc<Mutex<CongestionControl>>,
}

/// Stream data received from the other endpoint
/// that needs to be handled by [`StreamReactor`].
pub(crate) struct StreamMsg {
    /// The ID of the stream this message is for.
    pub(crate) sid: StreamId,
    /// The message.
    pub(crate) msg: UnparsedRelayMsg,
    /// Whether the cell this message came from counts towards flow-control windows.
    pub(crate) cell_counts_toward_windows: bool,
}
