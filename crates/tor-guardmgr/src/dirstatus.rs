//! Types and code to track the readiness status of a directory cache.

use std::time::{Duration, Instant};
use tor_basic_utils::retry::RetryDelay;

/// Status information about whether a
/// [`FallbackDir`](crate::fallback::FallbackDir) or
/// [`Guard`](crate::guard::Guard) is currently usable as a directory cache.
///
/// This structure is used to track whether the cache has recently failed, and
/// if so, when it can be retried.
#[derive(Debug, Clone)]
pub(crate) struct DirStatus {
    /// Used to decide how long to delay before retrying a fallback cache
    /// that has failed.
    delay: RetryDelay,
    /// A time before which we should assume that this fallback cache is broken.
    ///
    /// If None, then this fallback cache is ready to use right away.
    retry_at: Option<Instant>,
}

impl DirStatus {
    /// Construct a new DirStatus object with a given lower-bound for delays
    /// after failure.
    pub(crate) fn new(delay_floor: Duration) -> Self {
        DirStatus {
            delay: RetryDelay::from_duration(delay_floor),
            retry_at: None,
        }
    }

    /// Return true if this `Status` is usable at the time `now`.
    pub(crate) fn usable_at(&self, now: Instant) -> bool {
        match self.retry_at {
            Some(ready) => now >= ready,
            None => true,
        }
    }

    /// Return the time at which this `Status` can next be retried.
    ///
    /// A return value of `None`, or of a time in the past, indicates that this
    /// status can be used immediately.
    pub(crate) fn next_retriable(&self) -> Option<Instant> {
        self.retry_at
    }

    /// Record that the associated fallback directory has been used successfully.
    ///
    /// This should only be done after successfully handling a whole reply from the
    /// directory.
    pub(crate) fn note_success(&mut self) {
        self.retry_at = None;
        self.delay.reset();
    }

    /// Record that the associated fallback directory has failed.
    pub(crate) fn note_failure(&mut self, now: Instant) {
        let mut rng = rand::thread_rng();
        self.retry_at = Some(now + self.delay.next_delay(&mut rng));
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
    use super::*;

    #[test]
    fn status_basics() {
        let now = Instant::now();

        /// floor to use for testing.
        const FLOOR: Duration = Duration::from_secs(99);

        let mut status = DirStatus::new(FLOOR);
        // newly created status is usable.
        assert!(status.usable_at(now));

        // no longer usable after a failure.
        status.note_failure(now);
        assert_eq!(status.next_retriable().unwrap(), now + FLOOR);
        assert!(!status.usable_at(now));

        // Not enough time has passed.
        assert!(!status.usable_at(now + FLOOR / 2));

        // Enough time has passed.
        assert!(status.usable_at(now + FLOOR));

        // Mark as failed again; the timeout will (probably) be longer.
        status.note_failure(now + FLOOR);
        assert!(status.next_retriable().unwrap() >= now + FLOOR * 2);
        assert!(!status.usable_at(now + FLOOR));

        // Mark as succeeded; it should be usable immediately.
        status.note_success();
        assert!(status.usable_at(now + FLOOR));
    }
}
