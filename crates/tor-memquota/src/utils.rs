//! Miscellanous internal utilities

use crate::internal_prelude::*;

/// Convenience extension trait to provide `.take()`
///
/// Convenient way to provide `.take()` on some of our types.
pub(crate) trait DefaultExtTake: Default {
    /// Returns `*self`, replacing it with the default value.
    fn take(&mut self) -> Self {
        mem::take(self)
    }
}

/// `std::task::Waker::noop` but that's nightly
///
/// Note that no-op wakers must be used with care,
/// so don't just move or copy this elsewhere without consideration.
/// See <https://github.com/rust-lang/rust/pull/128064>.
//
// TODO if that MR is merged in some form, refer to the final version in the actual docs.
// If that MR is *not* merged, put some version of the warning here.
pub(crate) struct NoopWaker;
impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}
