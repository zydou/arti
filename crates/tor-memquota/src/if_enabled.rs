//! Helper type for disabling memory tracking when not wanted

use crate::internal_prelude::*;

/// Either `T`, if we're enabled, or nothing if we're no-op
///
/// Used for runtime control of whether the memory quota is enabled:
/// we support explicitly creating a no-op tracker
/// with [`MemoryQuotaTracker::new_noop`](crate::MemoryQuotaTracker::new_noop).
///
/// We use this rather than just `Option` because we also have data structures
/// (trackers, `Account`s and so on)
/// which have been torn down, or are "dummy" or "dangling",
/// which are supposed to return errors rather than no-op successes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IfEnabled<T> {
    /// We're enabled, and supposed to be tracking memory
    ///
    /// The 2nd member causes this variant to prove that tracking is enabled.
    /// If tracking is disabled at compile time, this variant is uninhabited
    /// and the whole `IfEnabled` becomes a unit.
    Enabled(T, EnabledToken),

    /// We're inenabled and everything should be a lightweight no-op
    Noop,
}

use IfEnabled::*;

impl<T> IfEnabled<T> {
    /// Convert to `Option`: return `Some` if this is `Enabled`
    pub(crate) fn into_enabled(self) -> Option<T> {
        match self {
            Enabled(y, _e) => Some(y),
            Noop => None,
        }
    }

    /// Take reference; analogous to `Option::as_ref`
    pub(crate) fn as_ref(&self) -> IfEnabled<&T> {
        match self {
            Enabled(y, e) => Enabled(y, *e),
            Noop => Noop,
        }
    }

    /// Take reference and convert to `Option`
    ///
    /// Convenience helper equivalent to `.as_ref().into_enabled()`.
    pub(crate) fn as_enabled(&self) -> Option<&T> {
        self.as_ref().into_enabled()
    }

    /// Return the contents of the `Enabled`, or declare it a [`Bug`]
    #[track_caller]
    pub(crate) fn enabled_or_bug(self) -> Result<T, Bug> {
        match self {
            Enabled(y, _e) => Ok(y),
            Noop => Err(internal!("IfEnabled unexpectedly Noop")),
        }
    }
}
