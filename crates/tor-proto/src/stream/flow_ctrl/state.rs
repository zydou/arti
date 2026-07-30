//! Code for implementing flow control (stream-level).

use std::sync::Arc;

use postage::watch;
use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKBpsEwma};
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use super::params::FlowCtrlParameters;
use super::window::state::{HalfStreamWindowFlowCtrl, WindowFlowCtrl};
use super::xon_xoff::reader::DrainRateRequest;
#[cfg(feature = "flowctl-cc")]
use super::xon_xoff::state::{HalfStreamXonXoffFlowCtrl, XonXoffFlowCtrl};

use crate::Result;
use crate::congestion::sendme;
use crate::util::notify::NotifySender;

/// Private internals of [`StreamFlowCtrl`].
#[enum_dispatch::enum_dispatch]
#[derive(Debug)]
enum StreamFlowCtrlInner {
    /// "legacy" sendme-window-based flow control.
    Window(WindowFlowCtrl),
    /// XON/XOFF flow control.
    #[cfg(feature = "flowctl-cc")]
    XonXoff(XonXoffFlowCtrl),
}

/// Manages the circuit reactor's flow control for a stream.
///
/// Note that the flow control logic can be distributed across multiple parts of Arti.
/// For example some flow control logic will exist in the circuit reactor,
/// but other logic will exist in the stream's `DataStream`.
/// So this doesn't include all flow control logic.
#[derive(Debug)]
pub(crate) struct StreamFlowCtrl {
    /// Private internal enum.
    inner: StreamFlowCtrlInner,
}

impl StreamFlowCtrl {
    /// Returns a new sendme-window-based [`StreamFlowCtrl`].
    pub(crate) fn new_window(window: sendme::StreamSendWindow) -> Self {
        Self {
            inner: StreamFlowCtrlInner::Window(WindowFlowCtrl::new(window)),
        }
    }

    /// Returns a new xon/xoff-based [`StreamFlowCtrl`].
    #[cfg(feature = "flowctl-cc")]
    pub(crate) fn new_xon_xoff(
        params: Arc<FlowCtrlParameters>,
        use_sidechannel_mitigations: bool,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        Self {
            inner: StreamFlowCtrlInner::XonXoff(XonXoffFlowCtrl::new(
                params,
                use_sidechannel_mitigations,
                rate_limit_updater,
                drain_rate_requester,
            )),
        }
    }

    /// Once this end of the stream is closed and the stream becomes a
    /// half-stream (`HalfStream`),
    /// this method will turn the flow control object into a version
    /// that is designed to be used for half-streams.
    pub(crate) fn half_stream(self) -> HalfStreamFlowCtrl {
        let inner = match self.inner {
            StreamFlowCtrlInner::Window(x) => {
                HalfStreamFlowCtrlInner::Window(HalfStreamWindowFlowCtrl::new(x))
            }
            #[cfg(feature = "flowctl-cc")]
            StreamFlowCtrlInner::XonXoff(x) => {
                HalfStreamFlowCtrlInner::XonXoff(HalfStreamXonXoffFlowCtrl::new(x))
            }
        };

        HalfStreamFlowCtrl { inner }
    }
}

// forward all trait methods to the inner enum
impl FlowCtrlHooks for StreamFlowCtrl {
    fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        self.inner.can_send(msg)
    }

    fn about_to_send(&mut self, msg: &AnyRelayMsg) -> Result<()> {
        self.inner.about_to_send(msg)
    }

    fn put_for_incoming_sendme(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        self.inner.put_for_incoming_sendme(msg)
    }

    fn handle_incoming_xon(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        self.inner.handle_incoming_xon(msg)
    }

    fn handle_incoming_xoff(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        self.inner.handle_incoming_xoff(msg)
    }

    fn maybe_send_xon(&mut self, rate: XonKBpsEwma, buffer_len: usize) -> Result<Option<Xon>> {
        self.inner.maybe_send_xon(rate, buffer_len)
    }

    fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>> {
        self.inner.maybe_send_xoff(buffer_len)
    }

    fn inbound_queue_max_len(&self) -> usize {
        self.inner.inbound_queue_max_len()
    }
}

/// Methods that can be called on a [`StreamFlowCtrl`].
///
/// We use a trait so that we can use `enum_dispatch` on the inner [`StreamFlowCtrlInner`] enum.
#[enum_dispatch::enum_dispatch(StreamFlowCtrlInner)]
pub(crate) trait FlowCtrlHooks {
    /// Whether this stream is ready to send `msg`.
    fn can_send<M: RelayMsg>(&self, msg: &M) -> bool;

    /// Inform the flow control code that we're about to send `msg`.
    /// Returns an error if the message should not be sent,
    /// and the circuit should be closed.
    // TODO: Consider having this method wrap the message in a type that
    // "proves" we've applied flow control. This would make it easier to apply
    // flow control earlier, e.g. in `OpenStreamEntStream`, without introducing
    // ambiguity in the sending function as to whether flow control has already
    // been applied or not.
    fn about_to_send(&mut self, msg: &AnyRelayMsg) -> Result<()>;

    /// Handle an incoming sendme.
    ///
    /// On success, return the number of cells left in the window.
    ///
    /// On failure, return an error: the caller should close the stream or
    /// circuit with a protocol error.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    fn put_for_incoming_sendme(&mut self, msg: UnparsedRelayMsg) -> Result<()>;

    /// Handle an incoming XON message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    fn handle_incoming_xon(&mut self, msg: UnparsedRelayMsg) -> Result<()>;

    /// Handle an incoming XOFF message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    fn handle_incoming_xoff(&mut self, msg: UnparsedRelayMsg) -> Result<()>;

    /// Check if we should send an XON message.
    ///
    /// If we should, then returns the XON message that should be sent.
    /// Returns an error if XON/XOFF messages aren't supported for this type of flow control.
    fn maybe_send_xon(&mut self, rate: XonKBpsEwma, buffer_len: usize) -> Result<Option<Xon>>;

    /// Check if we should send an XOFF message.
    ///
    /// If we should, then returns the XOFF message that should be sent.
    /// Returns an error if XON/XOFF messages aren't supported for this type of flow control.
    fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>>;

    /// The max queue length that should be used for stream messages incoming from the Tor network.
    ///
    /// This is the queue length between the user-facing stream reader (`DataReader`)
    /// and the circuit reactor.
    ///
    /// If the queue would ever exceed this many messages, the stream should be closed.
    fn inbound_queue_max_len(&self) -> usize;
}

/// Manages flow control for a half-stream (`HalfStream`).
#[derive(Debug)]
pub(crate) struct HalfStreamFlowCtrl {
    /// Private internal enum.
    inner: HalfStreamFlowCtrlInner,
}

/// Private internals of [`HalfStreamFlowCtrl`].
#[enum_dispatch::enum_dispatch]
#[derive(Debug)]
enum HalfStreamFlowCtrlInner {
    /// "legacy" sendme-window-based flow control.
    Window(HalfStreamWindowFlowCtrl),
    /// XON/XOFF flow control.
    #[cfg(feature = "flowctl-cc")]
    XonXoff(HalfStreamXonXoffFlowCtrl),
}

/// Methods that can be called on a [`HalfStreamFlowCtrl`].
///
/// We use a trait so that we can use `enum_dispatch` on the inner [`HalfStreamFlowCtrlInner`] enum.
/// While this may seem unnecessary since this trait currently only has two methods,
/// it's consistent with the [`FlowCtrlHooks`] trait above.
#[enum_dispatch::enum_dispatch(HalfStreamFlowCtrlInner)]
pub(crate) trait HalfStreamFlowCtrlHooks {
    /// Handle some number of dropped stream messages.
    ///
    /// We don't know what kinds of stream messages were dropped, only the number of them.
    ///
    /// This method exists because currently the stream entry may drop some incoming stream
    /// messages and they would never be processed by this flow control object otherwise.
    fn handle_incoming_dropped(&mut self, msg_count: u16) -> Result<()>;

    /// Handle an incoming message.
    ///
    /// If it's a flow control message, it will be consumed and `None` will be returned.
    /// Otherwise the original message will be returned.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    fn handle_incoming_msg(&mut self, msg: UnparsedRelayMsg) -> Result<Option<UnparsedRelayMsg>>;
}

// forward all trait methods to the inner enum
impl HalfStreamFlowCtrlHooks for HalfStreamFlowCtrl {
    fn handle_incoming_dropped(&mut self, msg_count: u16) -> Result<()> {
        self.inner.handle_incoming_dropped(msg_count)
    }

    fn handle_incoming_msg(&mut self, msg: UnparsedRelayMsg) -> Result<Option<UnparsedRelayMsg>> {
        self.inner.handle_incoming_msg(msg)
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
