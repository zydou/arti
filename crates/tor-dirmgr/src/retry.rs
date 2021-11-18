//! Implement a timer for retrying a single failed fetch or object,
//! using the [decorrelated jitter] algorithm.
//!
//! For a more full specification, see [`dir-spec.txt`].
//!
//! [decorrelated jitter]: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
//! [`dir-spec.txt`]: https://spec.torproject.org/dir-spec

use rand::Rng;
use std::convert::TryInto;
use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;

use serde::Deserialize;

/// An implementation for retrying downloads based on a decorrelated jitter
/// schedule.
///
/// The algorithm used here has several desirable properties:
///    * It is randomized, so that multiple timeouts don't have a
///      danger of getting synchronized with each other and hammering the
///      same directory servers all at once.
///    * It tends on average to wait longer and longer over time, so
///      that if the directory server is down, it won't get pummeled by
///      a zillion failing clients when it comes back up.
///    * It has a chance of retrying promptly, which results in better
///      client performance on average.
pub struct RetryDelay {
    /// The last delay that this retry delay returned (in msec), or 0
    /// if this never returned a delay.
    last_delay_ms: u32,
    /// The lowest allowable delay (in msec).
    low_bound_ms: u32,
}

/// Lowest possible lower bound, in milliseconds.
// We're doing this in MS, and Tor does it in seconds, so I'm
// multiplying the minimum by 1000 here.
const MIN_LOW_BOUND: u32 = 1000;

/// Largest possible lower bound, in milliseconds.
const MAX_LOW_BOUND: u32 = std::u32::MAX - 1;

/// Maximum amount to multiply the previous delay by.
const MAX_DELAY_MULT: u32 = 3;

impl RetryDelay {
    /// Construct a new RetryDelay from a given base delay in
    /// milliseconds.
    ///
    /// The base delay defines the lowest possible interval that can
    /// be returned.
    ///
    /// # Limitations
    ///
    /// If the base delay is less than 1000, a base delay of 1000 is
    /// used instead, since that's what the C tor implementation does.
    pub fn from_msec(base_delay_msec: u32) -> Self {
        let low_bound_ms = base_delay_msec.clamp(MIN_LOW_BOUND, MAX_LOW_BOUND);
        RetryDelay {
            last_delay_ms: 0,
            low_bound_ms,
        }
    }

    /// Construct a new RetryDelay from a given base delay.
    ///
    /// See from_msec for more information.
    pub fn from_duration(d: Duration) -> Self {
        let msec = d.as_millis();
        let msec = std::cmp::min(msec, u128::from(MAX_LOW_BOUND)) as u32;
        RetryDelay::from_msec(msec)
    }

    /// Helper: Return a lower and upper bound for the next delay to
    /// be yielded.
    fn delay_bounds(&self) -> (u32, u32) {
        let low = self.low_bound_ms;
        let high = std::cmp::max(
            // We don't need a saturating_add here, since low is always
            // less than high, so low cannot be equal to u32::MAX.
            low + 1,
            self.last_delay_ms.saturating_mul(MAX_DELAY_MULT),
        );
        (low, high)
    }

    /// Return the next delay to be used (in milliseconds), according
    /// to a given random number generator.
    pub fn next_delay_msec<R: Rng>(&mut self, rng: &mut R) -> u32 {
        let (low, high) = self.delay_bounds();
        assert!(low < high);

        let val = rng.gen_range(low..high);
        self.last_delay_ms = val;
        val
    }

    /// Return the next delay to be used (as a [`Duration`]),
    /// according to a given random number generator.
    pub fn next_delay<R: Rng>(&mut self, rng: &mut R) -> Duration {
        Duration::from_millis(u64::from(self.next_delay_msec(rng)))
    }
}

impl Default for RetryDelay {
    fn default() -> Self {
        RetryDelay::from_msec(0)
    }
}

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
    fn init() {
        let rd = RetryDelay::from_msec(2000);
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 2000);

        let rd = RetryDelay::from_msec(0);
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 1000);

        let rd = RetryDelay::from_duration(Duration::new(1, 500_000_000));
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 1500);
    }

    #[test]
    fn bounds() {
        let mut rd = RetryDelay::from_msec(1000);
        assert_eq!(rd.delay_bounds(), (1000, 1001));
        rd.last_delay_ms = 1500;
        assert_eq!(rd.delay_bounds(), (1000, 4500));
        rd.last_delay_ms = 3_000_000_000;
        assert_eq!(rd.delay_bounds(), (1000, std::u32::MAX));
    }

    #[test]
    fn rng() {
        let mut rd = RetryDelay::from_msec(50);
        let real_low_bound = std::cmp::max(50, MIN_LOW_BOUND);

        let mut rng = rand::thread_rng();
        for _ in 1..100 {
            let (b_lo, b_hi) = rd.delay_bounds();
            assert!(b_lo == real_low_bound);
            assert!(b_hi > b_lo);
            let delay = rd.next_delay(&mut rng).as_millis() as u32;
            assert_eq!(delay, rd.last_delay_ms);
            assert!(delay >= b_lo);
            assert!(delay < b_hi);
        }
    }

    #[test]
    fn config() {
        // default configuration is 3 tries, 1000 msec initial delay
        let cfg = DownloadSchedule::default();

        assert_eq!(cfg.n_attempts(), 3);
        let v: Vec<_> = cfg.attempts().collect();
        assert_eq!(&v[..], &[0, 1, 2]);

        let sched = cfg.schedule();
        assert_eq!(sched.last_delay_ms, 0);
        assert_eq!(sched.low_bound_ms, 1000);

        // Try a zero-attempt schedule, and have it get remapped to 1,1
        let cfg = DownloadSchedule::new(0, Duration::new(0, 0), 0);
        assert_eq!(cfg.n_attempts(), 1);
        assert_eq!(cfg.parallelism(), 1);
        let v: Vec<_> = cfg.attempts().collect();
        assert_eq!(&v[..], &[0]);

        let sched = cfg.schedule();
        assert_eq!(sched.last_delay_ms, 0);
        assert_eq!(sched.low_bound_ms, 1000);
    }
}
