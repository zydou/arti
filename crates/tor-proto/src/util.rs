//! Utilities used for the tor protocol.

pub(crate) mod ct;
pub(crate) mod err;
pub(crate) mod keyed_futures_unordered;
pub(crate) mod skew;
pub(crate) mod sometimes_unbounded_sink;
pub(crate) mod stream_poll_set;
pub(crate) mod ts;

use futures::Sink;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Extension trait for `Sink`
pub(crate) trait SinkExt<T>: Sink<T> {
    /// Calls `futures::Sink::poll_ready` but requires `Unpin` and returns `bool`
    ///
    /// Various gnarly places in the circuit reactor find this convenient.
    ///
    /// TODO #1397 (circuit reactor) probably remove this when the circuit reactor is rewritten.
    fn poll_ready_unpin_bool(&mut self, cx: &mut Context<'_>) -> Result<bool, Self::Error>
    where
        Self: Unpin,
    {
        Ok(match Sink::poll_ready(Pin::new(self), cx) {
            Poll::Ready(Ok(())) => true,
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => false,
        })
    }
}
impl<T, S: Sink<T>> SinkExt<T> for S {}

/// Convenience alias for
/// [`memquota::SpecificAccount::new_noop()`](crate::memquota::SpecificAccount::new_noop())
///
/// Available only in tests, which makes diff hunks which call this more obviously correct.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn fake_mq<A: crate::memquota::SpecificAccount>() -> A {
    A::new_noop()
}
