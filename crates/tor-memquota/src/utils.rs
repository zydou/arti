//! Miscellaneous internal utilities

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
