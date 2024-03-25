//! Wrapper for coarsetime.
//!
// (Note that this is the doc comment for a private module,
// not public API docs.
// So this describes the implementation and rationale.)
//
//! We want to be able to mock coarsetime in tor-rtmock,
//! so we need coarse time provision to to be part of a `Runtime`.
//!
//! (We can't just use `coarsetime`'s mocking facilities,
//! because they still use a process-wide global for the current time.)
//!
//! We use [`coarsetime::Instant::now`],
//! which in turn calls the OS's
//! `CLOCK_MONOTONIC_COARSE`, `CLOCK_MONOTONIC_FAST`, or similar.
//!
//! We don't use the non-updating coarsetime methods
//! such as `coarsetime::Instant:: now_without_cache_update`.
//! So, nor do we start a [`coarsetime::Updater`] update thread
//! (that would wake up frequently).
//!
//! We don't use (or expose any way to use) `coarsetime::Clock`;
//! we don't think that's a useful thing.
//!
//! ### Future possibilities
//!
//! If we ever need to mix-and-match coarse time values
//! from low-level crates like tor-proto,
//! with the wrapped-up coarsetime we have here,
//! we have the following options:
//!
//!  a. move much of this (perhaps the whole module) to a lower-layer crate
//!    (let's call it tor-coarsetime) and have everyone use that.
//!    Even the `CoarseTimeProvider` trait could be moved down,
//!    since it doesn't depend on anything else from tor-rtcompat.
//!
//!  b1. semver-expose coarsetime here in tor-rtcompat,
//!    perhaps optionally, by exposing a conversions
//!    with coarsetime::Instant.
//!
//!  b2. abolish the newtypes and instead make the types
//!    here aliases for coarsetime

use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time;

use derive_more::{Add, AddAssign, Sub, SubAssign};
use paste::paste;

use crate::traits::CoarseTimeProvider;

/// A duration with reduced precision, and, in the future, saturating arithmetic
///
/// This type represents a (nonnegative) period
/// between two [`CoarseInstant`]s.
///
/// This is (slightly lossily) interconvertible with `std::time::Duration`.
///
/// ### Range and precision
///
/// A `CoarseDuration` can represent at least 2^31 seconds,
/// at a granularity of at least 1 second.
// We may want to promise a better precision; that would be fine.
///
/// ### Panics
///
/// Currently, operations on `CoarseDuration` (including conversions)
/// can panic on under/overflow.
/// We regard this as a bug.
/// The intent is that all operations will saturate.
//
// Currently this type's API is a bit anaemic.
// If that turns out to be annoying, we might want to add
// methods like `from_secs`, `as_secs` etc.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)] //
#[derive(Add, Sub, AddAssign, SubAssign)]
pub struct CoarseDuration(coarsetime::Duration);

/// A monotonic timestamp with reduced precision, and, in the future, saturating arithmetic
///
/// Like `std::time::Instant`, but:
///
///  - [`RealCoarseTimeProvider::now_coarse()`] is cheap on all platforms,
///    unlike `std::time::Instant::now`.
///
///  - **Not true yet**: Arithmetic is saturating (so, it's panic-free).
///
///  - Precision and accuracy are reduced.
///
///  - *Cannot* be compared with, or converted to/from, `std::time::Instant`.
///    It has a completely different timescale to `Instant`.
///
/// You can obtain this (only) from `CoarseTimeProvider::now_coarse`.
///
/// ### Range and precision
///
/// The range of a `CoarseInstant` is not directly visible,
/// since the absolute value isn't.
/// `CoarseInstant`s are valid only within the context of one program execution (process).
///
/// Correct behaviour with processes that run for more than 2^31 seconds (about 30 years)
/// is not guaranteed.
///
/// The precision is no worse than 1 second.
// We may want to promise a better precision; that would be fine.
///
/// ### Panics
///
/// Currently, operations on `CoarseInstant` and `CoarseDuration`
/// can panic on under/overflow.
/// We regard this as a bug.
/// The intent is that all operations will saturate.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)] //
pub struct CoarseInstant(coarsetime::Instant);

impl From<time::Duration> for CoarseDuration {
    fn from(td: time::Duration) -> CoarseDuration {
        CoarseDuration(td.into())
    }
}
impl From<CoarseDuration> for time::Duration {
    fn from(cd: CoarseDuration) -> time::Duration {
        cd.0.into()
    }
}
/// implement `$AddSub<CoarseDuration> for CoarseInstant`, and `*Assign`
macro_rules! impl_add_sub { { $($AddSub:ident),* $(,)? } => { paste! { $(
    impl $AddSub<CoarseDuration> for CoarseInstant {
        type Output = CoarseInstant;
        fn [< $AddSub:lower >](self, rhs: CoarseDuration) -> CoarseInstant {
            CoarseInstant(self.0. [< $AddSub:lower >]( rhs.0 ))
        }
    }
    impl [< $AddSub Assign >]<CoarseDuration> for CoarseInstant {
        fn [< $AddSub:lower _assign >](&mut self, rhs: CoarseDuration) {
            *self = self.[< $AddSub:lower >](rhs);
        }
    }
)* } } }
impl_add_sub!(Add, Sub);

/// Provider of reduced-precision timestamps using the real OS clock
///
/// This is a ZST.
#[derive(Default, Clone, Debug)]
#[non_exhaustive]
pub struct RealCoarseTimeProvider {}

impl RealCoarseTimeProvider {
    /// Returns a new `RealCoarseTimeProvider`
    ///
    /// All `RealCoarseTimeProvider`s are equivalent.
    #[inline]
    pub fn new() -> Self {
        RealCoarseTimeProvider::default()
    }
}

impl CoarseTimeProvider for RealCoarseTimeProvider {
    fn now_coarse(&self) -> CoarseInstant {
        CoarseInstant(coarsetime::Instant::now())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::erasing_op)]
    use super::*;

    #[test]
    fn basic() {
        let t1 = RealCoarseTimeProvider::new().now_coarse();
        let t2 = t1 + CoarseDuration::from(time::Duration::from_secs(10));
        let t0 = t1 - CoarseDuration::from(time::Duration::from_secs(10));

        assert!(t0 < t1);
        assert!(t0 < t2);
        assert!(t1 < t2);
    }
}
