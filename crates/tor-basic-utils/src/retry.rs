//! An implementation of the "decorrelated jitter" algorithm for scheduling retries.
//!
//! See [`RetryDelay`] for more information.

use std::time::Duration;

use crate::RngExt as _;
use rand::Rng;

/// An implementation for retrying a remote operation based on a [decorrelated
/// jitter] schedule.
///
/// The algorithm used here has several desirable properties:
///    * It is randomized, so that multiple timeouts don't have a danger of
///      getting synchronized with each other and hammering the same servers all
///      at once.
///    * It tends on average to wait longer and longer over time, so that if the
///      server is down, it won't get pummeled by a zillion failing clients
///      when it comes back up.
///    * It has a chance of retrying promptly, which results in better client
///      performance on average.
///
/// For a more full specification, see [`dir-spec.txt`].
///
/// [decorrelated jitter]:
///     https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
/// [`dir-spec.txt`]: https://spec.torproject.org/dir-spec
#[derive(Clone, Debug)]
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
    ///
    /// Values are in milliseconds.
    ///
    /// The return value `(low, high)` is guaranteed to have `low < high`.
    fn delay_bounds(&self) -> (u32, u32) {
        let low = self.low_bound_ms;
        let high = std::cmp::max(
            // We don't need a saturating_add here, since low is always
            // <= MAX_LOW_BOUND, so low cannot be equal to u32::MAX.
            low + 1,
            self.last_delay_ms.saturating_mul(MAX_DELAY_MULT),
        );
        (low, high)
    }

    /// Return the next delay to be used (in milliseconds), according
    /// to a given random number generator.
    fn next_delay_msec<R: Rng>(&mut self, rng: &mut R) -> u32 {
        let (low, high) = self.delay_bounds();
        let val = rng.gen_range_checked(low..high).expect("low as not < high");
        self.last_delay_ms = val;
        val
    }

    /// Return the next delay to be used (as a [`Duration`]),
    /// according to a given random number generator.
    pub fn next_delay<R: Rng>(&mut self, rng: &mut R) -> Duration {
        Duration::from_millis(u64::from(self.next_delay_msec(rng)))
    }

    /// Return this [`RetryDelay`] to its original state.
    pub fn reset(&mut self) {
        self.last_delay_ms = 0;
    }
}

impl Default for RetryDelay {
    fn default() -> Self {
        RetryDelay::from_msec(0)
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
    use crate::test_rng::testing_rng;

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
        rd.reset();
        assert_eq!(rd.delay_bounds(), (1000, 1001));
    }

    #[test]
    fn rng() {
        let mut rd = RetryDelay::from_msec(50);
        let real_low_bound = std::cmp::max(50, MIN_LOW_BOUND);

        let mut rng = testing_rng();
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
}
