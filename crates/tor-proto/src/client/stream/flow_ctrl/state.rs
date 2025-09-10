//! Code for implementing flow control (stream-level).

use postage::watch;
use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use super::window::state::WindowFlowCtrl;
use super::xon_xoff::reader::DrainRateRequest;
use super::xon_xoff::state::XonXoffFlowCtrl;

use crate::Result;
use crate::congestion::sendme;
use crate::util::notify::NotifySender;

/// Private internals of [`StreamFlowCtrl`].
#[derive(Debug)]
enum StreamFlowCtrlEnum {
    /// "legacy" sendme-window-based flow control.
    WindowBased(WindowFlowCtrl),
    /// XON/XOFF flow control.
    #[cfg(feature = "flowctl-cc")]
    XonXoffBased(XonXoffFlowCtrl),
}

/// Manages flow control for a stream.
#[derive(Debug)]
pub(crate) struct StreamFlowCtrl {
    /// Private internal enum.
    e: StreamFlowCtrlEnum,
}

impl StreamFlowCtrl {
    /// Returns a new sendme-window-based [`StreamFlowCtrl`].
    pub(crate) fn new_window_based(window: sendme::StreamSendWindow) -> Self {
        Self {
            e: StreamFlowCtrlEnum::WindowBased(WindowFlowCtrl::new(window)),
        }
    }

    /// Returns a new xon/xoff-based [`StreamFlowCtrl`].
    #[cfg(feature = "flowctl-cc")]
    pub(crate) fn new_xon_xoff_based(
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        Self {
            e: StreamFlowCtrlEnum::XonXoffBased(XonXoffFlowCtrl::new(
                rate_limit_updater,
                drain_rate_requester,
            )),
        }
    }

    /// Whether this stream is ready to send `msg`.
    pub(crate) fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        match &self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.can_send(msg),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.can_send(msg),
        }
    }

    /// Take capacity to send `msg`. If there's insufficient capacity, returns
    /// an error.
    // TODO: Consider having this method wrap the message in a type that
    // "proves" we've applied flow control. This would make it easier to apply
    // flow control earlier, e.g. in `OpenStreamEntStream`, without introducing
    // ambiguity in the sending function as to whether flow control has already
    // been applied or not.
    pub(crate) fn take_capacity_to_send<M: RelayMsg>(&mut self, msg: &M) -> Result<()> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.take_capacity_to_send(msg),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.take_capacity_to_send(msg),
        }
    }

    /// Handle an incoming sendme.
    ///
    /// On success, return the number of cells left in the window.
    ///
    /// On failure, return an error: the caller should close the stream or
    /// circuit with a protocol error.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    pub(crate) fn put_for_incoming_sendme(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.put_for_incoming_sendme(msg),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.put_for_incoming_sendme(msg),
        }
    }

    /// Handle an incoming XON message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    pub(crate) fn handle_incoming_xon(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.handle_incoming_xon(msg),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.handle_incoming_xon(msg),
        }
    }

    /// Handle an incoming XOFF message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    pub(crate) fn handle_incoming_xoff(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.handle_incoming_xoff(msg),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.handle_incoming_xoff(msg),
        }
    }

    /// Check if we should send an XON message.
    ///
    /// If we should, then returns the XON message that should be sent.
    /// Returns an error if XON/XOFF messages aren't supported for this type of flow control.
    pub(crate) fn maybe_send_xon(
        &mut self,
        rate: XonKbpsEwma,
        buffer_len: usize,
    ) -> Result<Option<Xon>> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.maybe_send_xon(rate, buffer_len),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.maybe_send_xon(rate, buffer_len),
        }
    }

    /// Check if we should send an XOFF message.
    ///
    /// If we should, then returns the XOFF message that should be sent.
    /// Returns an error if XON/XOFF messages aren't supported for this type of flow control.
    pub(crate) fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>> {
        match &mut self.e {
            StreamFlowCtrlEnum::WindowBased(w) => w.maybe_send_xoff(buffer_len),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlEnum::XonXoffBased(x) => x.maybe_send_xoff(buffer_len),
        }
    }
}

/// A newtype wrapper for a tor stream rate limit that makes the units explicit.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StreamRateLimit {
    /// The rate in bytes/s.
    rate: u64,
}

impl StreamRateLimit {
    /// A maximum rate limit.
    pub(crate) const MAX: Self = Self::new_bytes_per_sec(u64::MAX);

    /// A rate limit of 0.
    pub(crate) const ZERO: Self = Self::new_bytes_per_sec(0);

    /// A new [`StreamRateLimit`] with `rate` bytes/s.
    pub(crate) const fn new_bytes_per_sec(rate: u64) -> Self {
        Self { rate }
    }

    /// The rate in bytes/s.
    pub(crate) const fn bytes_per_sec(&self) -> u64 {
        self.rate
    }
}

impl std::fmt::Display for StreamRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes/s", self.rate)
    }
}
