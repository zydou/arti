//! Declare the lowest level of stream: a stream that operates on raw
//! cells.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project::pin_project;
use tor_async_utils::peekable_stream::UnobtrusivePeekableStream;
use tor_cell::relaycell::{RelayCmd, UnparsedRelayMsg};
use tracing::debug;

use crate::congestion::sendme;
use crate::stream::StreamTarget;
use crate::stream::queue::StreamQueueReceiver;
use crate::{Error, Result};

/// The read part of a stream on a particular circuit.
///
/// This [`Stream`](Stream) will return incoming messages for this Tor stream, excluding flow control
/// related messages like SENDME, XON, and XOFF.
///
/// To avoid ambiguity, the following uses "stream" to refer to the `futures::Stream`, not the Tor
/// stream.
///
/// If the stream ends unexpectedly (before an END message), the stream will return an error.
/// After the stream returns an END message or an error, this stream will be "terminated" and future
/// [`poll_next`](Stream::poll_next) calls will return `None`.
// I think it would be better to *not* return an error if the stream ends before an END message is
// received, and just return `None`. The caller will know if it received an END message or not, so
// returning an error isn't very useful and is maybe unexpected.
#[derive(Debug)]
#[pin_project]
pub struct StreamReceiver {
    /// The underlying `StreamTarget` for this stream.
    ///
    /// A reader has this target in order to:
    ///   * Make the reactor send SENDME messages.
    ///   * Tell the reactor when there is a protocol error.
    ///   * Keep the stream alive at least until the StreamReceiver
    ///     is dropped.
    pub(crate) target: StreamTarget,
    /// Channel to receive stream messages from the reactor.
    #[pin]
    pub(crate) receiver: StreamQueueReceiver,
    /// Congestion control receive window for this stream.
    ///
    /// Having this here means we're only going to update it when the end consumer of this stream
    /// actually reads things, meaning we don't ask for more data until it's actually needed (as
    /// opposed to having the reactor assume we're always reading, and potentially overwhelm itself
    /// with having to buffer data).
    pub(crate) recv_window: sendme::StreamRecvWindow,
    /// Whether or not this stream has ended.
    pub(crate) ended: bool,
}

impl StreamReceiver {
    /// Try to read the next relay message from this stream.
    fn poll_next_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Result<Poll<UnparsedRelayMsg>> {
        let msg = match self.as_mut().project().receiver.poll_next(cx) {
            Poll::Ready(Some(msg)) => msg,
            Poll::Ready(None) => {
                // The channel is indicating that it has terminated, likely from a dropped sender.
                // But if we're here, it means we never received an END cell.
                //
                // This generally (exclusively?) means that the circuit was destroyed before the
                // peer sent an END message.
                return Err(Error::CircuitClosed);
            }
            Poll::Pending => return Ok(Poll::Pending),
        };

        if sendme::cell_counts_towards_windows(&msg) && self.recv_window.take()? {
            if let Err(e) = self.target.send_sendme() {
                if matches!(e, Error::CircuitClosed) {
                    // If the tunnel has closed, sending a message to the tunnel reactor may fail.
                    // But this is okay. We still want the user to be able to continue reading the
                    // remaining queued data for this stream, and if the tunnel has closed it
                    // wouldn't make sense to send a SENDME message anyways.
                    debug!("Failed to send stream-level SENDME. Ignoring: {e}");
                } else {
                    // This error is unexpected. Let's return it to the user.
                    return Err(e);
                }
            }
            self.recv_window.put();
        }

        Ok(Poll::Ready(msg))
    }

    /// Shut down this stream.
    pub fn protocol_error(&mut self) {
        self.target.protocol_error();
    }

    /// Is the stream currently empty?
    ///
    /// This method is inherently subject to race conditions. More data may arrive even before this
    /// method returns, so a result of `true` might have been outdated before the method even
    /// returned.
    ///
    /// This takes a `&mut` so that we can peek the stream.
    ///
    /// We provide an `is_empty` method rather than implementing [`UnobtrusivePeekableStream`]
    /// directly since `UnobtrusivePeekableStream` allows you to mutate the peeked item, which could
    /// break any accounting we do here in `StreamReceiver` (like stream sendme accounting). Also
    /// the stream types are incompatible (the inner receiver returns items of `UnparsedRelayMsg`,
    /// but this [`StreamReceiver`] returns items of `Result<UnparsedRelayMsg>`).
    pub(crate) fn is_empty(&mut self) -> bool {
        // The `StreamQueueReceiver` gives us two ways of checking if the queue is empty:
        // `unobtrusive_peek().is_none()` and `approx_stream_bytes() == 0`. The peek seems like a
        // better approach, so we do that here.
        // TODO(arti#534): Should reconsider using `unobtrusive_peek()`. What we really want to know
        // is if there is more stream data in the queue. But peeking only tells us if there are more
        // messages. There could be more messages, but none of them data messages.
        let peek_is_none = Pin::new(&mut self.receiver).unobtrusive_peek().is_none();

        // if the peek says that the stream is empty, assert that `approx_stream_bytes()` shows 0
        // bytes
        #[cfg(debug_assertions)]
        if peek_is_none {
            assert_eq!(self.receiver.approx_stream_bytes(), 0);
        } else {
            // if the peek is not empty it doesn't mean that approx_stream_bytes() != 0,
            // since there may be messages that contain no stream data
        }

        peek_is_none
    }
}

impl Stream for StreamReceiver {
    type Item = Result<UnparsedRelayMsg>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            // Prevent reading more messages from streams after they've ended. `None` indicates that
            // the stream is complete/terminated.
            return Poll::Ready(None);
        }

        match self.as_mut().poll_next_inner(cx) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(msg)) => {
                if msg.cmd() == RelayCmd::END {
                    // We return the END cell, and future polls will return `None`.
                    self.ended = true;
                }
                Poll::Ready(Some(Ok(msg)))
            }
            Err(e) => {
                // We return the error, and future polls will return `None`.
                self.ended = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}
