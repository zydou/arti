//! Implement a fast 'timestamp' for determining when an event last
//! happened.

use std::sync::atomic::{AtomicU64, Ordering};

/// An object for determining whether an event happened,
/// and if yes, when it happened.
///
/// Every `Timestamp` has internal mutability.  A timestamp can move
/// forward in time, but never backwards.
///
/// Internally, it uses the `coarsetime` crate to represent times in a way
/// that lets us do atomic updates.
#[derive(Default, Debug)]
pub(crate) struct OptTimestamp {
    /// A timestamp (from `coarsetime`) describing when this timestamp
    /// was last updated.
    ///
    /// I'd rather just use [`coarsetime::Instant`], but that doesn't have
    /// an atomic form.
    latest: AtomicU64,
}
impl OptTimestamp {
    /// Construct a new timestamp that has never been updated.
    pub(crate) const fn new() -> Self {
        OptTimestamp {
            latest: AtomicU64::new(0),
        }
    }

    /// Update this timestamp to (at least) the current time.
    pub(crate) fn update(&self) {
        // TODO: Do we want to use 'Instant::recent() instead,' and
        // add an updater thread?
        self.update_to(coarsetime::Instant::now());
    }

    /// If the timestamp is currently unset, then set it to the current time.
    /// Otherwise leave it alone.
    pub(crate) fn update_if_none(&self) {
        let now = coarsetime::Instant::now().as_ticks();

        let _ignore = self
            .latest
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Clear the timestamp and make it not updated again.
    pub(crate) fn clear(&self) {
        self.latest.store(0, Ordering::Relaxed);
    }

    /// Return the time since `update` was last called.
    ///
    /// Return `None` if update was never called.
    pub(crate) fn time_since_update(&self) -> Option<coarsetime::Duration> {
        self.time_since_update_at(coarsetime::Instant::now())
    }

    /// Return the time between the time when `update` was last
    /// called, and the time `now`.
    ///
    /// Return `None` if `update` was never called, or `now` is before
    /// that time.
    #[inline]
    pub(crate) fn time_since_update_at(
        &self,
        now: coarsetime::Instant,
    ) -> Option<coarsetime::Duration> {
        let earlier = self.latest.load(Ordering::Relaxed);
        let now = now.as_ticks();
        if now >= earlier && earlier != 0 {
            Some(coarsetime::Duration::from_ticks(now - earlier))
        } else {
            None
        }
    }

    /// Update this timestamp to (at least) the time `now`.
    #[inline]
    pub(crate) fn update_to(&self, now: coarsetime::Instant) {
        self.latest.fetch_max(now.as_ticks(), Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    use super::*;

    #[test]
    fn opt_timestamp() {
        use coarsetime::{Duration, Instant};

        let ts = OptTimestamp::new();
        assert!(ts.time_since_update().is_none());

        let zero = Duration::from_secs(0);
        let one_sec = Duration::from_secs(1);

        let first = Instant::now();
        let in_a_bit = first + one_sec * 10;
        let even_later = first + one_sec * 25;

        assert!(ts.time_since_update_at(first).is_none());

        ts.update_to(first);
        assert_eq!(ts.time_since_update_at(first), Some(zero));
        assert_eq!(ts.time_since_update_at(in_a_bit), Some(one_sec * 10));

        ts.update_to(in_a_bit);
        assert!(ts.time_since_update_at(first).is_none());
        assert_eq!(ts.time_since_update_at(in_a_bit), Some(zero));
        assert_eq!(ts.time_since_update_at(even_later), Some(one_sec * 15));

        // Make sure we can't move backwards.
        ts.update_to(first);
        assert!(ts.time_since_update_at(first).is_none());
        assert_eq!(ts.time_since_update_at(in_a_bit), Some(zero));
        assert_eq!(ts.time_since_update_at(even_later), Some(one_sec * 15));

        ts.clear();
        assert!(ts.time_since_update_at(first).is_none());
        assert!(ts.time_since_update_at(in_a_bit).is_none());
        assert!(ts.time_since_update_at(even_later).is_none());
    }

    #[test]
    fn update_if_none() {
        let ts = OptTimestamp::new();
        assert!(ts.time_since_update().is_none());

        // Calling "update_if_none" on a None OptTimestamp should set it.
        let time1 = coarsetime::Instant::now();
        ts.update_if_none();
        let d = ts.time_since_update();
        let time2 = coarsetime::Instant::now();
        assert!(d.is_some());
        assert!(d.unwrap() <= time2 - time1);

        std::thread::sleep(std::time::Duration::from_millis(100));
        // Calling "update_if_none" on a Some OptTimestamp doesn't change it.
        let time3 = coarsetime::Instant::now();
        // If coarsetime doesn't register this, then the rest of our test won't work.
        assert!(time3 > time2);
        ts.update_if_none();
        let d2 = ts.time_since_update();
        assert!(d2.is_some());
        assert!(d2.unwrap() > d.unwrap());
    }
}
