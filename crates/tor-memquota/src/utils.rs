//! Miscellaneous utilities

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

/// Convenience wrapper for creating a no-op tracker
///
/// Equivalent to [`MemoryQuotaTracker::new_noop()`]`.into()`.
/// Provides `tor_proto::memquota::TopLevelAccount::new_noop()`
pub trait ArcMemoryQuotaTrackerExt {
    /// Create a new dummy toplevel tracker for testing purposes
    fn new_noop() -> Self;
}
impl ArcMemoryQuotaTrackerExt for Arc<MemoryQuotaTracker> {
    fn new_noop() -> Self {
        MemoryQuotaTracker::new_noop()
    }
}
