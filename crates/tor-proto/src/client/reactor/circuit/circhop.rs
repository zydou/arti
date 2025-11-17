//! Module exposing structures relating to the reactor's view of a circuit's hops.

use super::{CircuitCmd, CloseStreamBehavior};
use crate::circuit::circhop::{CircHopInbound, CircHopOutbound, HopSettings, SendRelayCell};
use crate::client::reactor::circuit::path::PathEntry;
use crate::congestion::CongestionControl;
use crate::crypto::cell::HopNum;
use crate::stream::StreamMpscReceiver;
use crate::stream::cmdcheck::AnyCmdChecker;
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::flow_ctrl::xon_xoff::reader::DrainRateRequest;
use crate::stream::queue::StreamQueueSender;
use crate::streammap::{self, StreamEntMut, StreamMap};
use crate::tunnel::TunnelScopedCircId;
use crate::util::notify::NotifySender;
use crate::util::tunnel_activity::TunnelActivity;
use crate::{Error, Result};

use futures::Stream;
use futures::stream::FuturesUnordered;
use postage::watch;
use smallvec::SmallVec;
use tor_cell::chancell::BoxedCellBody;
use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellDecoderResult, RelayCellFormat, StreamId,
    UnparsedRelayMsg,
};

use safelog::sensitive as sv;
use tor_error::Bug;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use std::time::Instant;

#[cfg(test)]
use tor_cell::relaycell::msg::SendmeTag;

/// The "usual" number of hops in a [`CircHopList`].
///
/// This saves us a heap allocation when the number of hops is less than or equal to this value.
const NUM_HOPS: usize = 3;

/// Represents the reactor's view of a circuit's hop.
#[derive(Default)]
pub(crate) struct CircHopList {
    /// The list of hops.
    hops: SmallVec<[CircHop; NUM_HOPS]>,
}

impl CircHopList {
    /// Return a reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn hop(&self, hopnum: HopNum) -> Option<&CircHop> {
        self.hops.get(Into::<usize>::into(hopnum))
    }

    /// Return a mutable reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn get_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Append the specified hop.
    pub(crate) fn push(&mut self, hop: CircHop) {
        self.hops.push(hop);
    }

    /// Returns `true` if the list contains no [`CircHop`]s.
    pub(crate) fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Returns the number of hops in the list.
    pub(crate) fn len(&self) -> usize {
        self.hops.len()
    }

    /// Returns a [`Stream`] of [`CircuitCmd`] to poll from the main loop.
    ///
    /// The iterator contains at most one [`CircuitCmd`] for each hop,
    /// representing the instructions for handling the ready-item, if any,
    /// of its highest priority stream.
    ///
    /// IMPORTANT: this stream locks the stream map mutexes of each `CircHop`!
    /// To avoid contention, never create more than one
    /// [`ready_streams_iterator`](Self::ready_streams_iterator)
    /// stream at a time!
    ///
    /// This is cancellation-safe.
    pub(in crate::client::reactor) fn ready_streams_iterator(
        &self,
        exclude: Option<HopNum>,
    ) -> impl Stream<Item = CircuitCmd> + use<> {
        self.hops
            .iter()
            .enumerate()
            .filter_map(|(i, hop)| {
                let hop_num = HopNum::from(i as u8);

                if exclude == Some(hop_num) {
                    // We must skip polling this hop
                    return None;
                }

                if !hop.ccontrol().can_send() {
                    // We can't send anything on this hop that counts towards SENDME windows.
                    //
                    // In theory we could send messages that don't count towards
                    // windows (like `RESOLVE`), and process end-of-stream
                    // events (to send an `END`), but it's probably not worth
                    // doing an O(N) iteration over flow-control-ready streams
                    // to see if that's the case.
                    //
                    // This *doesn't* block outgoing flow-control messages (e.g.
                    // SENDME), which are initiated via the control-message
                    // channel, handled above.
                    //
                    // TODO: Consider revisiting. OTOH some extra throttling when circuit-level
                    // congestion control has "bottomed out" might not be so bad, and the
                    // alternatives have complexity and/or performance costs.
                    return None;
                }

                let hop_map = Arc::clone(self.hops[i].stream_map());
                Some(futures::future::poll_fn(move |cx| {
                    // Process an outbound message from the first ready stream on
                    // this hop. The stream map implements round robin scheduling to
                    // ensure fairness across streams.
                    // TODO: Consider looping here to process multiple ready
                    // streams. Need to be careful though to balance that with
                    // continuing to service incoming and control messages.
                    let mut hop_map = hop_map.lock().expect("lock poisoned");
                    let Some((sid, msg)) = hop_map.poll_ready_streams_iter(cx).next() else {
                        // No ready streams for this hop.
                        return Poll::Pending;
                    };

                    if msg.is_none() {
                        return Poll::Ready(CircuitCmd::CloseStream {
                            hop: hop_num,
                            sid,
                            behav: CloseStreamBehavior::default(),
                            reason: streammap::TerminateReason::StreamTargetClosed,
                        });
                    };
                    let msg = hop_map.take_ready_msg(sid).expect("msg disappeared");

                    #[allow(unused)] // unused in non-debug builds
                    let Some(StreamEntMut::Open(s)) = hop_map.get_mut(sid) else {
                        panic!("Stream {sid} disappeared");
                    };

                    debug_assert!(
                        s.can_send(&msg),
                        "Stream {sid} produced a message it can't send: {msg:?}"
                    );

                    let cell = SendRelayCell {
                        hop: Some(hop_num),
                        early: false,
                        cell: AnyRelayMsgOuter::new(Some(sid), msg),
                    };
                    Poll::Ready(CircuitCmd::Send(cell))
                }))
            })
            .collect::<FuturesUnordered<_>>()
    }

    /// Remove all halfstreams that are expired at `now`.
    pub(super) fn remove_expired_halfstreams(&mut self, now: Instant) {
        for hop in self.hops.iter_mut() {
            hop.stream_map()
                .lock()
                .expect("lock poisoned")
                .remove_expired_halfstreams(now);
        }
    }

    /// Returns true if there are any streams on this circuit
    ///
    /// Important: this function locks the stream map of its each of the [`CircHop`]s
    /// in this circuit, so it must **not** be called from any function where the
    /// stream map lock is held (such as [`ready_streams_iterator`](Self::ready_streams_iterator).
    pub(super) fn has_streams(&self) -> bool {
        self.hops.iter().any(|hop| {
            hop.stream_map()
                .lock()
                .expect("lock poisoned")
                .n_open_streams()
                > 0
        })
    }

    /// Return the number of streams currently open on this circuit.
    pub(crate) fn n_open_streams(&self) -> usize {
        self.hops
            .iter()
            .map(|hop| hop.n_open_streams())
            // No need to worry about overflow; max streams per hop is U16_MAX
            .sum()
    }

    /// Return the most active [`TunnelActivity`] for any hop on this `CircHopList`.
    pub(crate) fn tunnel_activity(&self) -> TunnelActivity {
        self.hops
            .iter()
            .map(|hop| {
                hop.stream_map()
                    .lock()
                    .expect("Poisoned lock")
                    .tunnel_activity()
            })
            .max()
            .unwrap_or_else(TunnelActivity::never_used)
    }
}

/// Represents the reactor's view of a single hop.
pub(crate) struct CircHop {
    /// The unique ID of the circuit. Used for logging.
    unique_id: TunnelScopedCircId,
    /// Hop number in the path.
    hop_num: HopNum,
    /// The inbound state of the hop.
    ///
    /// Used for processing cells received from this hop.
    inbound: CircHopInbound,
    /// The outbound state of the hop.
    ///
    /// Used for preparing cells to send to this hop.
    outbound: CircHopOutbound,
}

impl CircHop {
    /// Create a new hop.
    pub(crate) fn new(
        unique_id: TunnelScopedCircId,
        hop_num: HopNum,
        settings: &HopSettings,
    ) -> Self {
        let relay_format = settings.relay_crypt_protocol().relay_cell_format();

        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));
        let inbound = CircHopInbound::new(
            Arc::clone(&ccontrol),
            RelayCellDecoder::new(relay_format),
            settings,
        );

        let outbound = CircHopOutbound::new(
            ccontrol,
            relay_format,
            Arc::new(settings.flow_ctrl_params.clone()),
            settings,
        );

        CircHop {
            unique_id,
            hop_num,
            inbound,
            outbound,
        }
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    pub(crate) fn begin_stream(
        &mut self,
        message: AnyRelayMsg,
        sender: StreamQueueSender,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(SendRelayCell, StreamId)> {
        self.outbound.begin_stream(
            Some(self.hop_num),
            message,
            sender,
            rx,
            rate_limit_updater,
            drain_rate_requester,
            cmd_checker,
        )
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// See [`CircHopOutbound::close_stream`].
    pub(crate) fn close_stream(
        &mut self,
        id: StreamId,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
        expiry: Instant,
    ) -> Result<Option<SendRelayCell>> {
        self.outbound
            .close_stream(self.unique_id, id, Some(self.hop_num), message, why, expiry)
    }

    /// Check if we should send an XON message.
    ///
    /// If we should, then returns the XON message that should be sent.
    pub(crate) fn maybe_send_xon(
        &mut self,
        rate: XonKbpsEwma,
        id: StreamId,
    ) -> Result<Option<Xon>> {
        self.outbound.maybe_send_xon(rate, id)
    }

    /// Check if we should send an XOFF message.
    ///
    /// If we should, then returns the XOFF message that should be sent.
    pub(crate) fn maybe_send_xoff(&mut self, id: StreamId) -> Result<Option<Xoff>> {
        self.outbound.maybe_send_xoff(id)
    }

    /// Return the format that is used for relay cells sent to this hop.
    ///
    /// For the most part, this format isn't necessary to interact with a CircHop;
    /// it becomes relevant when we are deciding _what_ we can encode for the hop.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.outbound.relay_cell_format()
    }

    /// Delegate to CongestionControl, for testing purposes
    #[cfg(test)]
    pub(crate) fn send_window_and_expected_tags(&self) -> (u32, Vec<SendmeTag>) {
        self.outbound.send_window_and_expected_tags()
    }

    /// Return the number of open streams on this hop.
    ///
    /// WARNING: because this locks the stream map mutex,
    /// it should never be called from a context where that mutex is already locked.
    pub(crate) fn n_open_streams(&self) -> usize {
        self.outbound.n_open_streams()
    }

    /// Return a mutable reference to our CongestionControl object.
    pub(crate) fn ccontrol(&self) -> MutexGuard<'_, CongestionControl> {
        self.outbound.ccontrol()
    }

    /// We're about to send `msg`.
    ///
    /// See [`OpenStreamEnt::about_to_send`](crate::streammap::OpenStreamEnt::about_to_send).
    //
    // TODO prop340: This should take a cell or similar, not a message.
    pub(crate) fn about_to_send(&mut self, stream_id: StreamId, msg: &AnyRelayMsg) -> Result<()> {
        self.outbound.about_to_send(self.unique_id, stream_id, msg)
    }

    /// Add an entry to this map using the specified StreamId.
    #[cfg(feature = "hs-service")]
    pub(crate) fn add_ent_with_id(
        &self,
        sink: StreamQueueSender,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
        stream_id: StreamId,
        cmd_checker: AnyCmdChecker,
    ) -> Result<()> {
        self.outbound.add_ent_with_id(
            sink,
            rx,
            rate_limit_updater,
            drain_rate_requester,
            stream_id,
            cmd_checker,
        )
    }

    /// Note that we received an END message (or other message indicating the end of
    /// the stream) on the stream with `id`.
    ///
    /// See [`StreamMap::ending_msg_received`](crate::streammap::StreamMap::ending_msg_received).
    #[cfg(feature = "hs-service")]
    pub(crate) fn ending_msg_received(&self, stream_id: StreamId) -> Result<()> {
        self.outbound.ending_msg_received(stream_id)
    }

    /// Parse a RELAY or RELAY_EARLY cell body.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub(crate) fn decode(&mut self, cell: BoxedCellBody) -> Result<RelayCellDecoderResult> {
        self.inbound.decode(cell)
    }

    /// Handle `msg`, delivering it to the stream with the specified `streamid` if appropriate.
    ///
    /// Returns back the provided `msg`, if the message is an incoming stream request
    /// that needs to be handled by the calling code.
    ///
    // TODO: the above is a bit of a code smell -- we should try to avoid passing the msg
    // back and forth like this.
    pub(super) fn handle_msg(
        &self,
        hop_detail: &PathEntry,
        cell_counts_toward_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
        now: Instant,
    ) -> Result<Option<UnparsedRelayMsg>> {
        let possible_proto_violation_err = |streamid: StreamId| Error::UnknownStream {
            src: sv(hop_detail.clone()),
            streamid,
        };

        self.outbound.handle_msg(
            possible_proto_violation_err,
            cell_counts_toward_windows,
            streamid,
            msg,
            now,
        )
    }

    /// Get the stream map of this hop.
    pub(crate) fn stream_map(&self) -> &Arc<Mutex<StreamMap>> {
        self.outbound.stream_map()
    }

    /// Set the stream map of this hop to `map`.
    ///
    /// Returns an error if the existing stream map of the hop has any open stream.
    pub(crate) fn set_stream_map(&mut self, map: Arc<Mutex<StreamMap>>) -> StdResult<(), Bug> {
        self.outbound.set_stream_map(map)
    }

    /// Decrement the limit of outbound cells that may be sent to this hop; give
    /// an error if it would reach zero.
    pub(crate) fn decrement_outbound_cell_limit(&mut self) -> Result<()> {
        self.outbound.decrement_cell_limit()
    }

    /// Decrement the limit of inbound cells that may be received from this hop; give
    /// an error if it would reach zero.
    pub(crate) fn decrement_inbound_cell_limit(&mut self) -> Result<()> {
        self.inbound.decrement_cell_limit()
    }
}
