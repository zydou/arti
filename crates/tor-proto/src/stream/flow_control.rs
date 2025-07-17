//! Code for implementing flow control (stream-level).

use postage::watch;
use tor_cell::relaycell::flow_ctrl::{FlowCtrlVersion, Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::Sendme;
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use crate::congestion::sendme;
use crate::util::notify::NotifySender;
use crate::{Error, Result};

/// The threshold number of incoming data bytes buffered on a stream at which we send an XOFF.
// TODO(arti#534): We want to get the value from the consensus. The value in the consensus is the
// number of relay cells, not number of bytes. But do we really want to use the number of relays
// cells rather than bytes?
#[cfg(feature = "flowctl-cc")]
const CC_XOFF_CLIENT: usize = 250_000;

/// Private internals of [`StreamFlowControl`].
#[derive(Debug)]
enum StreamFlowControlEnum {
    /// "legacy" sendme-window-based flow control.
    WindowBased(sendme::StreamSendWindow),
    /// XON/XOFF flow control.
    #[cfg(feature = "flowctl-cc")]
    XonXoffBased(XonXoffControl),
}

/// Manages flow control for a stream.
#[derive(Debug)]
pub(crate) struct StreamFlowControl {
    /// Private internal enum.
    e: StreamFlowControlEnum,
}

impl StreamFlowControl {
    /// Returns a new sendme-window-based [`StreamFlowControl`].
    // TODO: Maybe take the raw u16 and create StreamSendWindow ourselves?
    // Unclear whether we need or want to support creating this object from a
    // preexisting StreamSendWindow.
    pub(crate) fn new_window_based(window: sendme::StreamSendWindow) -> Self {
        Self {
            e: StreamFlowControlEnum::WindowBased(window),
        }
    }

    /// Returns a new xon/xoff-based [`StreamFlowControl`].
    #[cfg(feature = "flowctl-cc")]
    pub(crate) fn new_xon_xoff_based(
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        Self {
            e: StreamFlowControlEnum::XonXoffBased(XonXoffControl {
                rate_limit_updater,
                drain_rate_requester,
                last_sent_xon_xoff: None,
            }),
        }
    }

    /// Whether this stream is ready to send `msg`.
    pub(crate) fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        match &self.e {
            StreamFlowControlEnum::WindowBased(w) => {
                !sendme::cmd_counts_towards_windows(msg.cmd()) || w.window() > 0
            }
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(_) => {
                // we perform rate-limiting in the `DataWriter`,
                // so we send any messages that made it past the `DataWriter`
                true
            }
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
            StreamFlowControlEnum::WindowBased(w) => {
                if sendme::cmd_counts_towards_windows(msg.cmd()) {
                    w.take().map(|_| ())
                } else {
                    // TODO: Maybe make this an error?
                    // Ideally caller would have checked this already.
                    Ok(())
                }
            }
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(_) => {
                // xon/xoff flow control doesn't have "capacity";
                // the capacity is effectively controlled by the congestion control
                Ok(())
            }
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
            StreamFlowControlEnum::WindowBased(w) => {
                let _sendme = msg
                    .decode::<Sendme>()
                    .map_err(|e| {
                        Error::from_bytes_err(e, "failed to decode stream sendme message")
                    })?
                    .into_msg();

                w.put()
            }
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(_) => Err(Error::CircProto(
                "Stream level SENDME not allowed due to congestion control".into(),
            )),
        }
    }

    /// Handle an incoming XON message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    pub(crate) fn handle_incoming_xon(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        match &mut self.e {
            StreamFlowControlEnum::WindowBased(_) => Err(Error::CircProto(
                "XON messages not allowed with window flow control".into(),
            )),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(control) => {
                let xon = msg
                    .decode::<Xon>()
                    .map_err(|e| Error::from_bytes_err(e, "failed to decode XON message"))?
                    .into_msg();

                // > Parties SHOULD treat XON or XOFF cells with unrecognized versions as a protocol
                // > violation.
                if *xon.version() != 0 {
                    return Err(Error::CircProto("Unrecognized XON version".into()));
                }

                let rate = match xon.kbps_ewma() {
                    XonKbpsEwma::Limited(rate_kbps) => {
                        let rate_kbps = u64::from(rate_kbps.get());
                        // convert from kbps to bytes/s
                        StreamRateLimit::new_bytes_per_sec(rate_kbps * 1000 / 8)
                    }
                    XonKbpsEwma::Unlimited => StreamRateLimit::MAX,
                };

                *control.rate_limit_updater.borrow_mut() = rate;
                Ok(())
            }
        }
    }

    /// Handle an incoming XOFF message.
    ///
    /// Takes the [`UnparsedRelayMsg`] so that we don't even try to decode it if we're not using the
    /// correct type of flow control.
    pub(crate) fn handle_incoming_xoff(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        match &mut self.e {
            StreamFlowControlEnum::WindowBased(_) => Err(Error::CircProto(
                "XOFF messages not allowed with window flow control".into(),
            )),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(control) => {
                let xoff = msg
                    .decode::<Xoff>()
                    .map_err(|e| Error::from_bytes_err(e, "failed to decode XOFF message"))?
                    .into_msg();

                // > Parties SHOULD treat XON or XOFF cells with unrecognized versions as a protocol
                // > violation.
                if *xoff.version() != 0 {
                    return Err(Error::CircProto("Unrecognized XOFF version".into()));
                }

                *control.rate_limit_updater.borrow_mut() = StreamRateLimit::ZERO;
                Ok(())
            }
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
            StreamFlowControlEnum::WindowBased(_) => Err(Error::CircProto(
                "XON messages cannot be sent with window flow control".into(),
            )),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(control) => {
                if buffer_len > CC_XOFF_CLIENT {
                    // we can't send an XON, and we should have already sent an XOFF when the queue first
                    // exceeded the limit (see `maybe_send_xoff()`)
                    debug_assert!(matches!(
                        control.last_sent_xon_xoff,
                        Some(LastSentXonXoff::Xoff),
                    ));

                    // inform the stream reader that we need a new drain rate
                    control.drain_rate_requester.notify();
                    return Ok(None);
                }

                control.last_sent_xon_xoff = Some(LastSentXonXoff::Xon(rate));

                Ok(Some(Xon::new(FlowCtrlVersion::V0, rate)))
            }
        }
    }

    /// Check if we should send an XOFF message.
    ///
    /// If we should, then returns the XOFF message that should be sent.
    /// Returns an error if XON/XOFF messages aren't supported for this type of flow control.
    pub(crate) fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>> {
        match &mut self.e {
            StreamFlowControlEnum::WindowBased(_) => Err(Error::CircProto(
                "XOFF messages cannot be sent with window flow control".into(),
            )),
            #[cfg(feature = "flowctl-cc")]
            StreamFlowControlEnum::XonXoffBased(control) => {
                // if the last XON/XOFF we sent was an XOFF, no need to send another
                if matches!(control.last_sent_xon_xoff, Some(LastSentXonXoff::Xoff)) {
                    return Ok(None);
                }

                if buffer_len <= CC_XOFF_CLIENT {
                    return Ok(None);
                }

                // either we have never sent an XOFF or XON, or we last sent an XON

                // remember that we last sent an XOFF
                control.last_sent_xon_xoff = Some(LastSentXonXoff::Xoff);

                // inform the stream reader that we need a new drain rate
                control.drain_rate_requester.notify();

                Ok(Some(Xoff::new(FlowCtrlVersion::V0)))
            }
        }
    }
}

/// Control state for XON/XOFF flow control.
#[derive(Debug)]
struct XonXoffControl {
    /// How we communicate rate limit updates to the
    /// [`DataWriter`](crate::stream::data::DataWriter).
    rate_limit_updater: watch::Sender<StreamRateLimit>,
    /// How we communicate requests for new drain rate updates to the
    /// [`XonXoffReader`](crate::stream::xon_xoff::XonXoffReader).
    drain_rate_requester: NotifySender<DrainRateRequest>,
    /// The last rate limit we sent.
    last_sent_xon_xoff: Option<LastSentXonXoff>,
}

/// The last XON/XOFF message that we sent.
#[derive(Debug)]
enum LastSentXonXoff {
    /// XON message with a rate.
    // TODO: I'm expecting that we'll want the `XonKbpsEwma` in the future.
    // If that doesn't end up being the case, then we should remove it.
    #[expect(dead_code)]
    Xon(XonKbpsEwma),
    /// XOFF message.
    Xoff,
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

/// A marker type for a [`NotifySender`] indicating that notifications are for new drain rate
/// requests.
#[derive(Debug)]
pub(crate) struct DrainRateRequest;
