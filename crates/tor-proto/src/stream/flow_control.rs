//! Code for implementing flow control (stream-level).

use tor_cell::relaycell::RelayMsg;

use crate::circuit::sendme;
use crate::Result;

/// Private internals of [`StreamSendFlowControl`].
#[derive(Debug)]
enum StreamSendFlowControlEnum {
    /// "legacy" sendme-window-based flow control.
    WindowBased(sendme::StreamSendWindow),
    // TODO: add xon/xoff alternative
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

    /// Whether this stream is ready to send `msg`.
    pub(crate) fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        match &self.e {
            StreamSendFlowControlEnum::WindowBased(w) => {
                !sendme::cmd_counts_towards_windows(msg.cmd()) || w.window() > 0
            } // xon-based will depend on number of bytes in the body of DATA
              // messages.
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
                    w.take(&()).map(|_| ())
                } else {
                    // TODO: Maybe make this an error?
                    // Ideally caller would have checked this already.
                    Ok(())
                }
            } // xon-based will update state based on number of bytes in the body
              // of DATA messages.
        }
    }

    /// Handle an incoming sendme.
    ///
    /// On success, return the number of cells left in the window.
    ///
    /// On failure, return an error: the caller should close the stream or
    /// circuit with a protocol error.
    pub(crate) fn put_for_incoming_sendme(&mut self) -> Result<u16> {
        match &mut self.e {
            StreamSendFlowControlEnum::WindowBased(w) => w.put(Some(())),
            // xon-based will return an error.
        }
    }

    // TODO: Add methods for handling incoming xon, xoff.
}
