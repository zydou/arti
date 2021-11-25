//! Implement a fast 'timestamp' for determining when an event last
//! happened.

use std::sync::atomic::{AtomicU64, Ordering};

/// An object for determining when an event last happened.
///
/// Every `Timestamp` has internal mutability.  A timestamp can move
/// forward in time, but never backwards.
///
/// Internally, it uses the `coarsetime` crate to represent times in a way
/// that lets us do atomic updates.
#[derive(Default, Debug)]
pub(crate) struct Timestamp {
    /// A timestamp (from `coarsetime`) describing when this timestamp
    /// was last updated.
    ///
    /// I'd rather just use [`coarsetime::Instant`], but that doesn't have
    /// an atomic form.
    latest: AtomicU64,
}
impl Timestamp {
    /// Construct a new timestamp that has never been updated.
    pub(crate) const fn new() -> Self {
        Timestamp {
            latest: AtomicU64::new(0),
        }
    }
    /// Update this timestamp to (at least) the current time.
    pub(crate) fn update(&self) {
        // TODO: Do we want to use 'Instant::recent() instead,' and
        // add an updater thread?
        self.update_to(coarsetime::Instant::now());
    }
    /// Update this timestamp to (at least) the time `now`.
    #[inline]
    pub(crate) fn update_to(&self, now: coarsetime::Instant) {
        self.latest.fetch_max(now.as_ticks(), Ordering::Relaxed);
    }

    /// Return the time since `update` was last called.
    ///
    /// Returns 0 if update was never called.
    pub(crate) fn time_since_update(&self) -> coarsetime::Duration {
        self.time_since_update_at(coarsetime::Instant::now())
    }

    /// Return the time between the time when `update` was last
    /// called, and the time `now`.
    ///
    /// Returns 0 if `update` was never called, or if `now` is before
    /// that time.
    #[inline]
    pub(crate) fn time_since_update_at(&self, now: coarsetime::Instant) -> coarsetime::Duration {
        let earlier = self.latest.load(Ordering::Relaxed);
        let now = now.as_ticks();
        if now >= earlier && earlier != 0 {
            coarsetime::Duration::from_ticks(now - earlier)
        } else {
            coarsetime::Duration::from_secs(0)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn timestamp() {
        use coarsetime::{Duration, Instant};

        let ts = Timestamp::new();

        let zero = Duration::from_secs(0);
        let one_sec = Duration::from_secs(1);

        let first = Instant::now();
        let in_a_bit = first + one_sec * 10;
        let even_later = first + one_sec * 25;

        assert_eq!(ts.time_since_update_at(first), zero);

        ts.update_to(first);
        assert_eq!(ts.time_since_update_at(first), zero);
        assert_eq!(ts.time_since_update_at(in_a_bit), one_sec * 10);

        ts.update_to(in_a_bit);
        assert_eq!(ts.time_since_update_at(first), zero);
        assert_eq!(ts.time_since_update_at(in_a_bit), zero);
        assert_eq!(ts.time_since_update_at(even_later), one_sec * 15);

        // Make sure we can't move backwards.
        ts.update_to(first);
        assert_eq!(ts.time_since_update_at(first), zero);
        assert_eq!(ts.time_since_update_at(in_a_bit), zero);
        assert_eq!(ts.time_since_update_at(even_later), one_sec * 15);
    }
}
