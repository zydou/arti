//! [`MockCoarseTimeProvider`]

use std::time::Duration;
use tor_rtcompat::{CoarseDuration, CoarseInstant};
use tor_rtcompat::{CoarseTimeProvider, RealCoarseTimeProvider};

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
