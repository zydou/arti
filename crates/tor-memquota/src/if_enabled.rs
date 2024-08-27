//! Helper type for disabling memory tracking when not wanted

use crate::internal_prelude::*;

/// Token indicating that memory quota tracking is enabled, at both compile and runtime
///
/// If support is compiled in this is a unit.
///
/// If the `memquota` cargo feature is not enabled, this type is uninhabited.
/// Scattering values of this type around in relevant data structures
/// and parameters lists
/// allows the compiler to eliminate the unwanted code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EnabledToken {
    /// Make non-exhaustive even within the crate
    _hidden: (),

    /// Uninhabited if the feature isn't enabled.
    #[cfg(not(feature = "memquota"))]
    _forbid: Void,
}

impl Eq for EnabledToken {}

impl EnabledToken {
    /// Obtain an `EnabledToken` (only available if tracking is compiled in)
    #[allow(clippy::new_without_default)] // a conditional Default impl would be rather odd
    #[cfg(feature = "memquota")]
    pub fn new() -> Self {
        EnabledToken { _hidden: () }
    }

    /// Obtain an `EnabledToken` if memory-tracking is compiled in, or `None` otherwise
    #[allow(clippy::unnecessary_wraps)] // Will be None if compiled out
    #[allow(unreachable_code)]
    pub fn new_if_compiled_in() -> Option<Self> {
        Some(EnabledToken {
            _hidden: (),

            #[cfg(not(feature = "memquota"))]
            _forbid: return None,
        })
    }
}

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
