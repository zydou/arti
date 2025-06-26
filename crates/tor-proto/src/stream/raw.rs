//! Declare the lowest level of stream: a stream that operates on raw
//! cells.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::Stream;
use pin_project::pin_project;
use tor_cell::relaycell::{RelayCmd, UnparsedRelayMsg};
use tracing::debug;

use crate::congestion::sendme;
use crate::tunnel::circuit::StreamMpscReceiver;
use crate::tunnel::StreamTarget;
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
    pub(crate) receiver: StreamMpscReceiver<UnparsedRelayMsg>,
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
                // I don't think this is unexpected, since a circuit may be destroyed before the
                // peer sends an END message.
                // TODO: Is there a better message or error variant we could provide here?
                return Err(Error::StreamProto(
                    "stream channel disappeared without END cell?".into(),
                ));
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
