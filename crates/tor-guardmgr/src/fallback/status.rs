//! Types and code to track the readiness status of a fallback directory.

use std::time::{Duration, Instant};
use tor_basic_utils::retry::RetryDelay;

/// Status information about whether a [`FallbackDir`](super::FallbackDir) is
/// currently usable.
///
/// This structure is used to track whether the fallback cache has recently
/// failed, and if so, when it can be retried.
#[derive(Debug, Clone)]
pub(crate) struct Status {
    /// Used to decide how long to delay before retrying a fallback cache
    /// that has failed.
    delay: RetryDelay,
    /// A time before which we should assume that this fallback cache is broken.
    ///
    /// If None, then this fallback cache is ready to use right away.
    retry_at: Option<Instant>,
}

/// Least amount of time we'll wait before retrying a fallback cache.
//
// TODO: we may want to make this configurable to a smaller value for chutney networks.
const FALLBACK_RETRY_FLOOR: Duration = Duration::from_secs(150);

impl Default for Status {
    fn default() -> Self {
        Status {
            delay: RetryDelay::from_duration(FALLBACK_RETRY_FLOOR),
            retry_at: None,
        }
    }
}

impl Status {
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
        self.delay = RetryDelay::from_duration(FALLBACK_RETRY_FLOOR);
    }

    /// Record that the associated fallback directory has failed.
    pub(crate) fn note_failure(&mut self, now: Instant) {
        let mut rng = rand::thread_rng();
        self.retry_at = Some(now + self.delay.next_delay(&mut rng));
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn status_basics() {
        let now = Instant::now();

        let mut status = Status::default();
        // newly created status is usable.
        assert!(status.usable_at(now));

        // no longer usable after a failure.
        status.note_failure(now);
        assert_eq!(status.next_retriable().unwrap(), now + FALLBACK_RETRY_FLOOR);
        assert!(!status.usable_at(now));

        // Not enough time has passed.
        assert!(!status.usable_at(now + FALLBACK_RETRY_FLOOR / 2));

        // Enough time has passed.
        assert!(status.usable_at(now + FALLBACK_RETRY_FLOOR));

        // Mark as failed again; the timeout will (probably) be longer.
        status.note_failure(now + FALLBACK_RETRY_FLOOR);
        assert!(status.next_retriable().unwrap() >= now + FALLBACK_RETRY_FLOOR * 2);
        assert!(!status.usable_at(now + FALLBACK_RETRY_FLOOR));

        // Mark as succeeded; it should be usable immediately.
        status.note_success();
        assert!(status.usable_at(now + FALLBACK_RETRY_FLOOR));
    }
}
