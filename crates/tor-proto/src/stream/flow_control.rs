//! Code for implementing flow control (stream-level).

use postage::watch;
use tor_cell::relaycell::msg::Sendme;
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use crate::congestion::sendme;
use crate::{Error, Result};

/// Private internals of [`StreamSendFlowControl`].
#[derive(Debug)]
enum StreamSendFlowControlEnum {
    /// "legacy" sendme-window-based flow control.
    WindowBased(sendme::StreamSendWindow),
    /// XON/XOFF flow control.
    XonXoffBased(XonXoffControl),
}

/// Manages outgoing flow control for a stream.
#[derive(Debug)]
pub(crate) struct StreamSendFlowControl {
    /// Private internal enum.
    e: StreamSendFlowControlEnum,
}

impl StreamSendFlowControl {
    /// Returns a new sendme-window-based [`StreamSendFlowControl`].
    // TODO: Maybe take the raw u16 and create StreamSendWindow ourselves?
    // Unclear whether we need or want to support creating this object from a
    // preexisting StreamSendWindow.
    pub(crate) fn new_window_based(window: sendme::StreamSendWindow) -> Self {
        Self {
            e: StreamSendFlowControlEnum::WindowBased(window),
        }
    }

    /// Returns a new xon/xoff-based [`StreamSendFlowControl`].
    ///
    /// **NOTE:** This isn't actually implemented yet,
    /// and is currently a no-op congestion control.
    // TODO(#534): remove the note above
    pub(crate) fn new_xon_xoff_based(rate_limit_updater: watch::Sender<StreamRateLimit>) -> Self {
        Self {
            e: StreamSendFlowControlEnum::XonXoffBased(XonXoffControl { rate_limit_updater }),
        }
    }

    /// Whether this stream is ready to send `msg`.
    pub(crate) fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        match &self.e {
            StreamSendFlowControlEnum::WindowBased(w) => {
                !sendme::cmd_counts_towards_windows(msg.cmd()) || w.window() > 0
            }
            StreamSendFlowControlEnum::XonXoffBased(_) => {
                // TODO(#534): xon-based will depend on number of bytes in the body of DATA messages
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
            StreamSendFlowControlEnum::WindowBased(w) => {
                if sendme::cmd_counts_towards_windows(msg.cmd()) {
                    w.take().map(|_| ())
                } else {
                    // TODO: Maybe make this an error?
                    // Ideally caller would have checked this already.
                    Ok(())
                }
            }
            StreamSendFlowControlEnum::XonXoffBased(_) => {
                // TODO(#534): xon-based will update state based on number of bytes in the body of
                // DATA messages
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
            StreamSendFlowControlEnum::WindowBased(w) => {
                let _sendme = msg
                    .decode::<Sendme>()
                    .map_err(|e| {
                        Error::from_bytes_err(e, "failed to decode stream sendme message")
                    })?
                    .into_msg();

                w.put()
            }
            StreamSendFlowControlEnum::XonXoffBased(_) => Err(Error::CircProto(
                "Stream level SENDME not allowed due to congestion control".into(),
            )),
        }
    }

    // TODO(#534): Add methods for handling incoming xon, xoff.
}

/// Control state for XON/XOFF flow control.
#[derive(Debug)]
struct XonXoffControl {
    /// How we communicate rate limit updates to the
    /// [`DataWriter`](crate::stream::data::DataWriter).
    rate_limit_updater: watch::Sender<StreamRateLimit>,
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
    pub(crate) const fn get_bytes_per_sec(&self) -> u64 {
        self.rate
    }
}

impl std::fmt::Display for StreamRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes/s", self.rate)
    }
}
