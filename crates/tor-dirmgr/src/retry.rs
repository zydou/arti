//! Configure timers for a timer for retrying a single failed fetch or object.
//!
//! For a more information on the algorithm, see
//! [`RetryDelay`](tor_basic_utils::retry::RetryDelay).

use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;

use serde::Deserialize;
use tor_basic_utils::retry::RetryDelay;

/// Configuration for how many times to retry a download, with what
/// frequency.
#[derive(Debug, Copy, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DownloadSchedule {
    /// How many times to retry before giving up?
    num_retries: NonZeroU32,

    /// The amount of time to delay after the first failure, and a
    /// lower-bound for future delays.
    #[serde(with = "humantime_serde")]
    initial_delay: Duration,

    /// When we want to download a bunch of these at a time, how many
    /// attempts should we try to launch at once?
    #[serde(default = "default_parallelism")]
    parallelism: NonZeroU8,
}

impl Default for DownloadSchedule {
    fn default() -> Self {
        DownloadSchedule::new(3, Duration::from_millis(1000), 1)
    }
}

/// Return the default parallelism for DownloadSchedule.
fn default_parallelism() -> NonZeroU8 {
    #![allow(clippy::unwrap_used)]
    1.try_into().unwrap()
}

impl DownloadSchedule {
    /// Create a new DownloadSchedule to control our logic for retrying
    /// a given download.
    ///
    /// The resulting configuration will always make at least one
    /// attempt, and at most `attempts`.  After a failure, it will
    /// wait at least `initial_delay` before trying again.
    #[allow(clippy::missing_panics_doc)] // can't really panic.
    pub fn new(attempts: u32, initial_delay: Duration, parallelism: u8) -> Self {
        // If unwrapping `1.try_into()` is not safe there are bigger problems
        #![allow(clippy::unwrap_used)]
        let num_retries = attempts
            .try_into()
            .unwrap_or_else(|_| 1.try_into().unwrap());
        let parallelism = parallelism
            .try_into()
            .unwrap_or_else(|_| 1.try_into().unwrap());
        DownloadSchedule {
            num_retries,
            initial_delay,
            parallelism,
        }
    }

    /// Return an iterator to use over all the supported attempts for
    /// this configuration.
    pub fn attempts(&self) -> impl Iterator<Item = u32> {
        0..(self.num_retries.into())
    }

    /// Return the number of times that we're supposed to retry, according
    /// to this DownloadSchedule.
    pub fn n_attempts(&self) -> u32 {
        self.num_retries.into()
    }

    /// Return the number of parallel attempts that we're supposed to launch,
    /// according to this DownloadSchedule.
    pub fn parallelism(&self) -> u8 {
        self.parallelism.into()
    }

    /// Return a RetryDelay object for this configuration.
    ///
    /// If the initial delay is longer than 32
    pub fn schedule(&self) -> RetryDelay {
        RetryDelay::from_duration(self.initial_delay)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn config() {
        // default configuration is 3 tries, 1000 msec initial delay
        let cfg = DownloadSchedule::default();
        let one_sec = Duration::from_secs(1);
        let zero_sec = Duration::from_secs(0);
        let mut rng = rand::thread_rng();

        assert_eq!(cfg.n_attempts(), 3);
        let v: Vec<_> = cfg.attempts().collect();
        assert_eq!(&v[..], &[0, 1, 2]);

        assert_eq!(cfg.initial_delay, one_sec);
        let mut sched = cfg.schedule();
        assert_eq!(sched.next_delay(&mut rng), one_sec);

        // Try a zero-attempt schedule, and have it get remapped to 1,1
        let cfg = DownloadSchedule::new(0, zero_sec, 0);
        assert_eq!(cfg.n_attempts(), 1);
        assert_eq!(cfg.parallelism(), 1);
        let v: Vec<_> = cfg.attempts().collect();
        assert_eq!(&v[..], &[0]);

        assert_eq!(cfg.initial_delay, zero_sec);
        let mut sched = cfg.schedule();
        assert_eq!(sched.next_delay(&mut rng), one_sec);
    }
}
