//! [`MockTimeCore`] and [`MockCoarseTimeProvider`]

use derive_adhoc::{define_derive_adhoc, Adhoc};
use std::time::{Duration, Instant, SystemTime};
use tor_rtcompat::{CoarseDuration, CoarseInstant};
use tor_rtcompat::{CoarseTimeProvider, RealCoarseTimeProvider};

define_derive_adhoc! {
    /// Derive getters for struct fields.
    ///
    /// Like `amplify::Getters` but `pub(crate)`.
    ///
    /// TODO add this feature to `amplify`.
    CrateGetters =
    ${define REF ${if not(fmeta(getter_copy)) { & }}}
    $(
        impl $ttype {
            ${fattrs doc}
            pub(crate) fn $fname(&self) -> $REF $ftype {
                $REF self.$fname
            }
        }
    )
}

/// Mock time, as a value
///
/// Contains an `Instant`, `SystemTime` and `CoarseInstant`.
///
/// Arranges that they are all moved in step,
/// unless explicitly requested otherwise.
#[derive(Clone, Debug, Adhoc)]
#[derive_adhoc(CrateGetters)]
pub(crate) struct MockTimeCore {
    /// Current time (monotonic clock)
    #[adhoc(getter_copy)]
    instant: Instant,

    /// Current wallclock time
    #[adhoc(getter_copy)]
    wallclock: SystemTime,

    /// Coarse time tracking
    coarse: MockCoarseTimeProvider,
}

impl MockTimeCore {
    /// Create a new `MockTimeCore`
    pub(crate) fn new(instant: Instant, wallclock: SystemTime) -> Self {
        MockTimeCore {
            instant,
            coarse: MockCoarseTimeProvider::new(),
            wallclock,
        }
    }

    /// Advance by a duration
    ///
    /// All three time values are advanced in step.
    pub(crate) fn advance(&mut self, d: Duration) {
        self.instant += d;
        self.wallclock += d;
        self.coarse.advance(d);
    }

    /// Warp the wallclock (only)
    //
    // We *could* just expose the field for mutable access,
    // but this way seems more regular.
    pub(crate) fn jump_wallclock(&mut self, new_wallclock: SystemTime) {
        self.wallclock = new_wallclock;
    }
}

/// A mockable [`CoarseTimeProvider`]
#[derive(Clone, Debug)]
pub(crate) struct MockCoarseTimeProvider {
    /// Starting point
    started: CoarseInstant,

    /// How much we have advanced
    ///
    /// We track this as a `Duration`, not a [`CoarseDuration`] (or [`CoarseInstant`])
    /// to avoid accumulating rounding errors,
    /// which might otherwise cause the mocked `Instant` and `CoarseInstant`
    /// clocks to run at noticeably different *rates*.
    elapsed: Duration,
}

impl MockCoarseTimeProvider {
    /// Start a new [`MockCoarseTimeProvider`]
    pub(crate) fn new() -> Self {
        MockCoarseTimeProvider {
            started: RealCoarseTimeProvider::new().now_coarse(),
            elapsed: Duration::ZERO,
        }
    }

    /// Advance the mocked coarse time by `dur`
    pub(crate) fn advance(&mut self, dur: Duration) {
        self.elapsed += dur;
    }
}

impl CoarseTimeProvider for MockCoarseTimeProvider {
    fn now_coarse(&self) -> CoarseInstant {
        self.started + CoarseDuration::from(self.elapsed)
    }
}
