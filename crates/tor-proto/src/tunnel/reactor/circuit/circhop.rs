//! Module exposing structures relating to the reactor's view of a circuit's hops.

use super::{CloseStreamBehavior, SendRelayCell, SEND_WINDOW_INIT};
use crate::circuit::HopSettings;
use crate::congestion::sendme;
use crate::congestion::CongestionControl;
use crate::crypto::cell::HopNum;
use crate::stream::{AnyCmdChecker, StreamSendFlowControl};
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::{StreamMpscReceiver, StreamMpscSender};
use crate::tunnel::streammap::{self, ShouldSendEnd};
use crate::Result;

use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellFormat, StreamId, UnparsedRelayMsg,
};

use tracing::trace;

use std::sync::{Arc, Mutex};

#[cfg(test)]
use tor_cell::relaycell::msg::SendmeTag;

/// Represents the reactor's view of a single hop.
pub(crate) struct CircHop {
    /// Reactor unique ID. Used for logging.
    pub(super) unique_id: UniqId,
    /// Hop number in the path.
    pub(super) hop_num: HopNum,
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    ///
    /// NOTE: this is behind a mutex because the reactor polls the `StreamMap`s
    /// of all hops concurrently, in a [`FuturesUnordered`]. Without the mutex,
    /// this wouldn't be possible, because it would mean holding multiple
    /// mutable references to `self` (the reactor). Note, however,
    /// that there should never be any contention on this mutex:
    /// we never create more than one [`Circuit::ready_streams_iterator`] stream
    /// at a time, and we never clone/lock the hop's `StreamMap` outside of
    /// [`Circuit::ready_streams_iterator`].
    ///
    // TODO: encapsulate the Vec<CircHop> into a separate CircHops structure,
    // and hide its internals from the Reactor. The CircHops implementation
    // should enforce the invariant described in the note above.
    pub(super) map: Arc<Mutex<streammap::StreamMap>>,
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    pub(super) ccontrol: CongestionControl,
    /// Decodes relay cells received from this hop.
    pub(super) inbound: RelayCellDecoder,
    /// Format to use for relay cells.
    //
    // When we have packed/fragmented cells, this may be replaced by a RelayCellEncoder.
    pub(super) relay_format: RelayCellFormat,
}

impl CircHop {
    /// Create a new hop.
    pub(super) fn new(
        unique_id: UniqId,
        hop_num: HopNum,
        relay_format: RelayCellFormat,
        settings: &HopSettings,
    ) -> Self {
        CircHop {
            unique_id,
            hop_num,
            map: Arc::new(Mutex::new(streammap::StreamMap::new())),
            ccontrol: CongestionControl::new(&settings.ccontrol),
            inbound: RelayCellDecoder::new(relay_format),
            relay_format,
        }
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    pub(crate) fn begin_stream(
        &mut self,
        message: AnyRelayMsg,
        sender: StreamMpscSender<UnparsedRelayMsg>,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(SendRelayCell, StreamId)> {
        let flow_ctrl = self.build_send_flow_ctrl();
        let r =
            self.map
                .lock()
                .expect("lock poisoned")
                .add_ent(sender, rx, flow_ctrl, cmd_checker)?;
        let cell = AnyRelayMsgOuter::new(Some(r), message);
        Ok((
            SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell,
            },
            r,
        ))
    }

    /// Close the stream associated with `id` because the stream was
    /// dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    /// If no END cell is specified, an END cell with the reason byte set to
    /// REASON_MISC will be sent.
    pub(super) fn close_stream(
        &mut self,
        id: StreamId,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
    ) -> Result<Option<SendRelayCell>> {
        let should_send_end = self.map.lock().expect("lock poisoned").terminate(id, why)?;
        trace!(
            "{}: Ending stream {}; should_send_end={:?}",
            self.unique_id,
            id,
            should_send_end
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if let (ShouldSendEnd::Send, CloseStreamBehavior::SendEnd(end_message)) =
            (should_send_end, message)
        {
            let end_cell = AnyRelayMsgOuter::new(Some(id), end_message.into());
            let cell = SendRelayCell {
                hop: self.hop_num,
                early: false,
                cell: end_cell,
            };

            return Ok(Some(cell));
        }
        Ok(None)
    }

    /// Return the format that is used for relay cells sent to this hop.
    ///
    /// For the most part, this format isn't necessary to interact with a CircHop;
    /// it becomes relevant when we are deciding _what_ we can encode for the hop.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.relay_format
    }

    /// Builds the (sending) flow control handler for a new stream.
    pub(super) fn build_send_flow_ctrl(&self) -> StreamSendFlowControl {
        if self.ccontrol.uses_stream_sendme() {
            let window = sendme::StreamSendWindow::new(SEND_WINDOW_INIT);
            StreamSendFlowControl::new_window_based(window)
        } else {
            StreamSendFlowControl::new_xon_xoff_based()
        }
    }

    /// Delegate to CongestionControl, for testing purposes
    #[cfg(test)]
    pub(crate) fn send_window_and_expected_tags(&self) -> (u32, Vec<SendmeTag>) {
        self.ccontrol.send_window_and_expected_tags()
    }

    /// Return the number of open streams on this hop.
    ///
    /// WARNING: because this locks the stream map mutex,
    /// it should never be called from a context where that mutex is already locked.
    pub(crate) fn n_open_streams(&self) -> usize {
        self.map.lock().expect("lock poisoned").n_open_streams()
    }

    /// Return a reference to our CongestionControl object.
    pub(crate) fn ccontrol(&self) -> &CongestionControl {
        &self.ccontrol
    }
}
