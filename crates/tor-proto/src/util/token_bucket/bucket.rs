//! A token bucket implementation.

use std::fmt::Debug;
use std::time::{Duration, Instant};

/// A token bucket.
///
/// Calculations are performed at microsecond resolution.
/// You likely want to call [`refill()`](Self::refill) each time you want to access or perform an
/// operation on the token bucket.
///
/// This is partially inspired by tor's `token_bucket_ctr_t`,
/// but the implementation is quite a bit different.
/// We use larger values here (for example `u64`),
/// and we aim to avoid drift when refills occur at times that aren't exactly in period with the
/// refill rate.
///
/// It's possible that we could relax these requirements to reduce memory usage and computation
/// complexity, but that optimization should probably only be made if/when needed since it would
/// make the code more difficult to reason about, and possibly more complex.
#[derive(Debug)]
pub(crate) struct TokenBucket<I> {
    /// The refill rate in tokens/second.
    rate: u64,
    /// The max amount of tokens in the bucket.
    /// Commonly referred to as the "burst".
    bucket_max: u64,
    /// Current amount of tokens in the bucket.
    // It's possible that in the future we may want a token bucket to allow negative values. For
    // example we might want to send a few extra bytes over the allowed limit if it would mean that
    // we send a complete TLS record.
    bucket: u64,
    /// Time that the most recent token was added to the bucket.
    ///
    /// While this can be thought of as the last time the bucket was partially refilled, it more
    /// specifically is the time that the most recent token was added. For example if the bucket
    /// refills one token every 100 ms, and the bucket is refilled at time 510 ms, the bucket would
    /// gain 5 tokens and the stored time would be 500 ms.
    last_refill: I,
}

impl<I: TokenBucketInstant> TokenBucket<I> {
    /// A new [`TokenBucket`] with a given `rate` in tokens/second and a `max` token limit.
    ///
    /// The bucket will initially be full.
    /// The value `max` is commonly referred to as the "burst".
    pub(crate) fn new(config: &TokenBucketConfig, now: I) -> Self {
        Self {
            rate: config.rate,
            bucket_max: config.bucket_max,
            bucket: config.bucket_max,
            last_refill: now,
        }
    }

    /// Are there no tokens in the bucket?
    // remove this if we use it in the future
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn is_empty(&self) -> bool {
        self.bucket == 0
    }

    /// The maximum number of tokens that this bucket can hold.
    pub(crate) fn max(&self) -> u64 {
        self.bucket_max
    }

    /// Remove `count` tokens from the bucket.
    // remove this if we use it in the future
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn drain(&mut self, count: u64) -> Result<BecameEmpty, InsufficientTokensError> {
        Ok(self.claim(count)?.commit())
    }

    /// Claim a number of tokens.
    ///
    /// The claim will be held by the returned [`ClaimedTokens`], and committed when dropped.
    ///
    /// **Note:** You probably want to call [`refill()`](Self::refill) before this.
    // Since the `ClaimedTokens` holds a `&mut` to this `TokenBucket`, we don't need to worry about
    // other calls accessing the `TokenBucket` before the `ClaimedTokens` are committed.
    pub(crate) fn claim(
        &mut self,
        count: u64,
    ) -> Result<ClaimedTokens<I>, InsufficientTokensError> {
        if count > self.bucket {
            return Err(InsufficientTokensError {
                available: self.bucket,
            });
        }

        Ok(ClaimedTokens::new(self, count))
    }

    /// Adjust the refill rate and max tokens of the bucket.
    ///
    /// If the new max is smaller than the existing number of tokens,
    /// the number of tokens will be reduced to the new max.
    ///
    /// A rate and/or max of 0 is allowed.
    // remove this when we use it in the future
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn adjust(&mut self, config: &TokenBucketConfig) {
        self.rate = config.rate;
        self.bucket_max = config.bucket_max;
        self.bucket = std::cmp::min(self.bucket, self.bucket_max);
    }

    /// An estimated time at which the bucket will have `tokens` available.
    ///
    /// It is not guaranteed that `tokens` will be available at the returned time.
    ///
    /// If there are already enough tokens available, a time in the past may be returned.
    ///
    /// A value of `None` implies "never",
    /// for example if the refill rate is 0,
    /// the bucket max is too small,
    /// or the time is too large to be represented as an `I`.
    pub(crate) fn tokens_available_at(&self, tokens: u64) -> Result<I, NeverEnoughTokensError> {
        let tokens_needed = tokens.saturating_sub(self.bucket);

        // check if we currently have enough tokens before considering refilling
        if tokens_needed == 0 {
            return Ok(self.last_refill);
        }

        // if the rate is 0, we'll never get more tokens
        if self.rate == 0 {
            return Err(NeverEnoughTokensError::ZeroRate);
        }

        // if more tokens are wanted than the capacity of the bucket, we'll never get enough
        if tokens > self.bucket_max {
            return Err(NeverEnoughTokensError::ExceedsMaxTokens);
        }

        // this may underestimate the time if either argument is very large
        let time_needed = Self::tokens_to_duration(tokens_needed, self.rate)
            .ok_or(NeverEnoughTokensError::ZeroRate)?;

        // Always return at least 1 microsecond since:
        // 1. We don't want to return `Duration::ZERO` if the tokens aren't ready,
        //    which may occur if the rate is very large (<1 ns/token).
        // 2. Clocks generally don't operate at <1 us resolution.
        let time_needed = std::cmp::max(time_needed, Duration::from_micros(1));

        self.last_refill
            .checked_add(time_needed)
            .ok_or(NeverEnoughTokensError::InstantNotRepresentable)
    }

    /// Refill the bucket.
    pub(crate) fn refill(&mut self, now: I) -> BecameNonEmpty {
        // time since the last refill
        let elapsed = now.saturating_duration_since(self.last_refill);

        // If we exceeded the threshold, update the timestamp and return.
        // This is taken from tor, which has the comment below:
        //
        // > Skip over updates that include an overflow or a very large jump. This can happen for
        // > platform specific reasons, such as the old ~48 day windows timer.
        //
        // It's unclear if this type of OS bug is still common enough that this check is useful,
        // but it shouldn't hurt.
        if elapsed > I::IGNORE_THRESHOLD {
            tracing::debug!(
                "Time jump of {elapsed:?} is larger than {:?}; not refilling token bucket",
                I::IGNORE_THRESHOLD,
            );
            self.last_refill = now;
            return BecameNonEmpty::No;
        }

        let old_bucket = self.bucket;

        // Compute how much we should increment the bucket by.
        // This may be underestimated in some cases.
        let bucket_inc = Self::duration_to_tokens(elapsed, self.rate);

        self.bucket = std::cmp::min(self.bucket_max, self.bucket.saturating_add(bucket_inc));

        // Compute how much we should increment the last refill time by. This avoids drifting if the
        // `bucket_inc` was underestimated, and avoids rounding errors which could cause the token
        // bucket to effectively use a lower rate. For example if the rate was "1 token / sec" and
        // the elapsed time was "1.2 sec", we only want to refill 1 token and increment the time by
        // 1 second.
        //
        // While the docs for `tokens_to_duration` say that a smaller than expected duration may be
        // returned, we have a test `test_duration_token_round_trip` which ensures that
        // `tokens_to_duration` returns the expected value when used with the result from
        // `duration_to_tokens`.
        let last_refill_inc =
            Self::tokens_to_duration(bucket_inc, self.rate).unwrap_or(Duration::ZERO);

        self.last_refill = self
            .last_refill
            .checked_add(last_refill_inc)
            .expect("overflowed time");
        debug_assert!(self.last_refill <= now);

        if old_bucket == 0 && self.bucket != 0 {
            BecameNonEmpty::Yes
        } else {
            BecameNonEmpty::No
        }
    }

    /// How long would it take to refill `tokens` at `rate`?
    ///
    /// The result is rounded up to the nearest microsecond.
    /// If the number of `tokens` is large,
    /// the result may be much lower than the expected duration due to saturating 64-bit arithmetic.
    ///
    /// `None` will be returned if the `rate` is 0.
    fn tokens_to_duration(tokens: u64, rate: u64) -> Option<Duration> {
        // Perform the calculation in microseconds rather than nanoseconds since timers typically
        // have microsecond granularity, and it lowers the chance that the calculation overflows the
        // `u64::MAX` limit compared to nanoseconds. In the case that the calculation saturates, the
        // returned duration will be shorter than the real value.
        //
        // For example with `tokens = u64::MAX` and `rate = u64::MAX` we'd expect a result of 1
        // second, but:
        // u64::MAX.saturating_mul(1000 * 1000).div_ceil(u64::MAX) = 1 microsecond
        //
        // The `div_ceil` ensures we always round up to the nearest microsecond.
        //
        // dimensional analysis:
        // (tokens) * (microseconds / second) / (tokens / second) = microseconds
        if rate == 0 {
            return None;
        }
        let micros = tokens.saturating_mul(1000 * 1000).div_ceil(rate);
        Some(Duration::from_micros(micros))
    }

    /// How many tokens would be refilled within `time` at `rate`?
    ///
    /// The `time` is truncated to microsecond granularity.
    /// If the `time` or `rate` is large,
    /// the result may be much lower than the expected number of tokens due to saturating 64-bit
    /// arithmetic.
    fn duration_to_tokens(time: Duration, rate: u64) -> u64 {
        let micros = u64::try_from(time.as_micros()).unwrap_or(u64::MAX);
        // dimensional analysis:
        // (tokens / second) * (microseconds) / (microseconds / second) = tokens
        rate.saturating_mul(micros) / (1000 * 1000)
    }
}

/// The refill rate and token max for a [`TokenBucket`].
pub(crate) struct TokenBucketConfig {
    /// The refill rate in tokens/second.
    pub(crate) rate: u64,
    /// The max amount of tokens in the bucket.
    /// Commonly referred to as the "burst".
    pub(crate) bucket_max: u64,
}

/// A handle to a number of claimed tokens.
///
/// Dropping this handle will commit the claim.
#[derive(Debug)]
pub(crate) struct ClaimedTokens<'a, I> {
    /// The bucket that the claim is for.
    bucket: &'a mut TokenBucket<I>,
    /// How many tokens to remove from the bucket.
    count: u64,
}

impl<'a, I> ClaimedTokens<'a, I> {
    /// Create a new [`ClaimedTokens`] that will remove `count` tokens from the token `bucket` when
    /// dropped.
    fn new(bucket: &'a mut TokenBucket<I>, count: u64) -> Self {
        Self { bucket, count }
    }

    /// Commit the claimed tokens.
    ///
    /// This is equivalent to just dropping the [`ClaimedTokens`], but also returns whether the
    /// token bucket became empty or not.
    pub(crate) fn commit(mut self) -> BecameEmpty {
        self.commit_impl()
    }

    /// Reduce the claim to a fewer number of tokens than the original claim.
    ///
    /// If `count` is larger than the original claim, an error will be returned containing the
    /// current number of claimed tokens.
    pub(crate) fn reduce(&mut self, count: u64) -> Result<(), InsufficientTokensError> {
        if count > self.count {
            return Err(InsufficientTokensError {
                available: self.count,
            });
        }

        self.count = count;
        Ok(())
    }

    /// Discard the claim.
    ///
    /// This does not remove any tokens from the token bucket.
    pub(crate) fn discard(mut self) {
        self.count = 0;
    }

    /// The commit implementation.
    ///
    /// After calling [`commit_impl()`](Self::commit_impl),
    /// the [`ClaimedTokens`] should no longer be used and should be dropped immediately.
    fn commit_impl(&mut self) -> BecameEmpty {
        // when the `ClaimedTokens` was created by the `TokenBucket`, it should have ensured that
        // there were enough tokens
        self.bucket.bucket = self
            .bucket
            .bucket
            .checked_sub(self.count)
            .unwrap_or_else(|| {
                panic!(
                    "claim commit failed: {}, {}",
                    self.count, self.bucket.bucket,
                )
            });

        // when `self` is dropped some time after this function ends,
        // we don't want to subtract again
        self.count = 0;

        if self.bucket.bucket > 0 {
            BecameEmpty::No
        } else {
            BecameEmpty::Yes
        }
    }
}

impl<'a, I> std::ops::Drop for ClaimedTokens<'a, I> {
    fn drop(&mut self) {
        self.commit_impl();
    }
}

/// An operation was attempted to reduce the number of tokens,
/// but the token bucket did not have enough tokens.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("insufficient tokens for operation")]
pub(crate) struct InsufficientTokensError {
    /// The number of tokens that are available to drain/commit.
    available: u64,
}

impl InsufficientTokensError {
    /// Get the number of tokens that are available to drain/commit.
    pub(crate) fn available_tokens(&self) -> u64 {
        self.available
    }
}

/// The token bucket will never have the requested number of tokens.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("there will never be enough tokens for this operation")]
pub(crate) enum NeverEnoughTokensError {
    /// The request exceeds the bucket's maximum number of tokens.
    ExceedsMaxTokens,
    /// The refill rate is 0.
    ZeroRate,
    /// The time is not representable.
    ///
    /// For example the if the rate is low and a large number of tokens were requested, it may be
    /// too far in the future that it cannot be represented as a time value.
    InstantNotRepresentable,
}

/// The token bucket transitioned from "empty" to "non-empty".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BecameNonEmpty {
    /// Token bucket became non-empty.
    Yes,
    /// Token bucket remains empty.
    No,
}

/// The token bucket transitioned from "non-empty" to "empty".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BecameEmpty {
    /// Token bucket became empty.
    Yes,
    /// Token bucket remains non-empty.
    No,
}

/// Any type implementing this must be represented as a measurement of a monotonically nondecreasing
/// clock.
pub(crate) trait TokenBucketInstant: Copy + Clone + Debug + PartialEq + PartialOrd {
    /// An unrealistically large time jump.
    ///
    /// We assume that any time change larger than this indicates a broken monotonic clock,
    /// and the bucket will not be refilled.
    const IGNORE_THRESHOLD: Duration;

    /// See [`Instant::checked_add`].
    fn checked_add(&self, duration: Duration) -> Option<Self>;

    /// See [`Instant::checked_duration_since`].
    fn checked_duration_since(&self, earlier: Self) -> Option<Duration>;

    /// See [`Instant::saturating_duration_since`].
    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }
}

impl TokenBucketInstant for Instant {
    // This value is taken from tor (see `elapsed_ticks <= UINT32_MAX/4` in
    // `src/lib/evloop/token_bucket.c`).
    const IGNORE_THRESHOLD: Duration = Duration::from_secs((u32::MAX / 4) as u64);

    #[inline]
    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.checked_add(duration)
    }

    #[inline]
    fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
        self.checked_duration_since(earlier)
    }

    #[inline]
    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use rand::Rng;

    #[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
    struct MillisTimestamp(u64);

    impl TokenBucketInstant for MillisTimestamp {
        const IGNORE_THRESHOLD: Duration = Duration::from_millis(1_000_000_000);

        fn checked_add(&self, duration: Duration) -> Option<Self> {
            let duration = u64::try_from(duration.as_millis()).ok()?;
            self.0.checked_add(duration).map(Self)
        }

        fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
            Some(Duration::from_millis(self.0.checked_sub(earlier.0)?))
        }
    }

    #[test]
    fn adjust() {
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };
        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));
        assert_eq!(tb.bucket, 100);
        assert_eq!(tb.bucket_max, 100);
        assert_eq!(tb.rate, 10);

        tb.adjust(&TokenBucketConfig {
            rate: 20,
            bucket_max: 100,
        });
        assert_eq!(tb.bucket, 100);
        assert_eq!(tb.bucket_max, 100);

        tb.adjust(&TokenBucketConfig {
            rate: 20,
            bucket_max: 40,
        });
        assert_eq!(tb.bucket, 40);
        assert_eq!(tb.bucket_max, 40);

        tb.adjust(&TokenBucketConfig {
            rate: 20,
            bucket_max: 100,
        });
        assert_eq!(tb.bucket, 40);
        assert_eq!(tb.bucket_max, 100);

        tb.adjust(&TokenBucketConfig {
            rate: 200,
            bucket_max: 100,
        });
        assert_eq!(tb.bucket, 40);
        assert_eq!(tb.bucket_max, 100);
        assert_eq!(tb.rate, 200);
    }

    #[test]
    fn adjust_zero() {
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };

        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));
        tb.adjust(&TokenBucketConfig {
            rate: 0,
            bucket_max: 200,
        });
        assert_eq!(tb.bucket, 100);
        assert_eq!(tb.bucket_max, 200);
        assert_eq!(tb.rate, 0);
        // bucket should not increase
        tb.refill(MillisTimestamp(10_000_000));
        assert_eq!(tb.bucket, 100);

        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));
        tb.adjust(&TokenBucketConfig {
            rate: 10,
            bucket_max: 0,
        });
        assert_eq!(tb.bucket, 0);
        assert_eq!(tb.bucket_max, 0);
        assert_eq!(tb.rate, 10);
        // bucket should stay empty
        tb.refill(MillisTimestamp(10_000_000));
        assert_eq!(tb.bucket, 0);

        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));
        tb.adjust(&TokenBucketConfig {
            rate: 0,
            bucket_max: 0,
        });
        assert_eq!(tb.bucket, 0);
        assert_eq!(tb.bucket_max, 0);
        assert_eq!(tb.rate, 0);
        // bucket should stay empty
        tb.refill(MillisTimestamp(10_000_000));
        assert_eq!(tb.bucket, 0);
    }

    #[test]
    fn is_empty() {
        // increases 10 tokens/second (one every 100 ms)
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };
        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));
        assert!(!tb.is_empty());

        tb.drain(99).unwrap();
        assert!(!tb.is_empty());

        tb.drain(1).unwrap();
        assert!(tb.is_empty());

        tb.refill(MillisTimestamp(199));
        assert!(tb.is_empty());

        tb.refill(MillisTimestamp(200));
        assert!(!tb.is_empty());
    }

    #[test]
    fn correctness() {
        // increases 10 tokens/second (one every 100 ms)
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };
        let mut tb = TokenBucket::new(&config, MillisTimestamp(100));

        tb.drain(50).unwrap();
        assert_eq!(tb.bucket, 50);

        tb.refill(MillisTimestamp(1100));
        assert_eq!(tb.bucket, 60);

        tb.drain(50).unwrap();
        assert_eq!(tb.bucket, 10);

        tb.refill(MillisTimestamp(2100));
        assert_eq!(tb.bucket, 20);

        tb.refill(MillisTimestamp(2101));
        assert_eq!(tb.bucket, 20);
        tb.refill(MillisTimestamp(2199));
        assert_eq!(tb.bucket, 20);
        tb.refill(MillisTimestamp(2200));
        assert_eq!(tb.bucket, 21);
    }

    #[test]
    fn rounding() {
        // increases 10 tokens/second (one every 100 ms)
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };
        let mut tb = TokenBucket::new(&config, MillisTimestamp(0));
        tb.drain(100).unwrap();

        // ensure that refilling at 150 ms does not change the last refill time to 150 ms,
        // otherwise the next refill wouldn't occur until 250 ms instead of 200 ms
        tb.refill(MillisTimestamp(99));
        assert_eq!(tb.bucket, 0);
        tb.refill(MillisTimestamp(150));
        assert_eq!(tb.bucket, 1);
        tb.refill(MillisTimestamp(199));
        assert_eq!(tb.bucket, 1);
        tb.refill(MillisTimestamp(200));
        assert_eq!(tb.bucket, 2);
    }

    #[test]
    fn tokens_available_at() {
        // increases 10 tokens/second (one every 100 ms)
        let config = TokenBucketConfig {
            rate: 10,
            bucket_max: 100,
        };
        let mut tb = TokenBucket::new(&config, MillisTimestamp(0));

        // bucket is empty at 0 ms, next token at 100 ms
        tb.drain(100).unwrap();

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(0)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(200)));

        // bucket is still empty at 40 ms, next token at 100 ms
        tb.refill(MillisTimestamp(40));

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(0)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(200)));

        // bucket has 1 token at 100 ms, next token at 200 ms
        tb.refill(MillisTimestamp(100));

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(200)));

        // bucket is empty at 100 ms, next token at 200 ms
        tb.drain(1).unwrap();

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(300)));

        // bucket is empty at 140 ms, next token at 200 ms
        tb.refill(MillisTimestamp(140));

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(100)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(300)));

        // bucket has 1 token at 210 ms, next token at 300 ms
        tb.refill(MillisTimestamp(210));

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(2), Ok(MillisTimestamp(300)));

        use NeverEnoughTokensError as NETE;

        assert_eq!(tb.tokens_available_at(100), Ok(MillisTimestamp(10_100)));
        assert_eq!(tb.tokens_available_at(101), Err(NETE::ExceedsMaxTokens));
        assert_eq!(
            tb.tokens_available_at(u64::MAX),
            Err(NETE::ExceedsMaxTokens),
        );

        // set the refill rate to 0
        tb.adjust(&TokenBucketConfig {
            rate: 0,
            bucket_max: 100,
        });

        assert_eq!(tb.tokens_available_at(0), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(1), Ok(MillisTimestamp(200)));
        assert_eq!(tb.tokens_available_at(2), Err(NETE::ZeroRate));
    }

    #[test]
    fn test_duration_token_round_trip() {
        let tokens_to_duration = TokenBucket::<Instant>::tokens_to_duration;
        let duration_to_tokens = TokenBucket::<Instant>::duration_to_tokens;

        // start with some hand-picked cases
        let mut duration_rate_pairs = vec![
            (Duration::from_nanos(0), 1),
            (Duration::from_nanos(1), 1),
            (Duration::from_micros(2), 1),
            (Duration::MAX, 1),
            (Duration::from_nanos(0), 3),
            (Duration::from_nanos(1), 3),
            (Duration::from_micros(2), 3),
            (Duration::MAX, 3),
            (Duration::from_nanos(0), 1000),
            (Duration::from_nanos(1), 1000),
            (Duration::from_micros(2), 1000),
            (Duration::MAX, 1000),
            (Duration::from_nanos(0), u64::MAX),
            (Duration::from_nanos(1), u64::MAX),
            (Duration::from_micros(2), u64::MAX),
            (Duration::MAX, u64::MAX),
        ];

        let mut rng = rand::rng();

        // add some fuzzing
        for _ in 0..10_000 {
            let secs = rng.random();
            let nanos = rng.random();
            // Duration::new() may panic, so just skip if there's a panic rather than trying to
            // write our own logic to avoid the panic in the first place
            let Ok(random_duration) = std::panic::catch_unwind(|| Duration::new(secs, nanos))
            else {
                continue;
            };
            let random_rate = rng.random();
            duration_rate_pairs.push((random_duration, random_rate));
        }

        // for various combinations of durations and rates, we ensure that after an initial
        // `duration_to_tokens` calculation which may truncate, a round-trip between
        // `tokens_to_duration` and `duration_to_tokens` isn't lossy
        for (original_duration, rate) in duration_rate_pairs {
            // this may give a smaller number of tokens than expected (see docs on
            // `TokenBucket::duration_to_tokens`)
            let tokens = duration_to_tokens(original_duration, rate);

            // we want to ensure that converting these `tokens` to a duration and then back to
            // tokens is not lossy, which implies that `tokens_to_duration` is returning the
            // expected value and not a truncated value due to saturating arithmetic
            let duration = tokens_to_duration(tokens, rate).unwrap();
            assert_eq!(tokens, duration_to_tokens(duration, rate));
        }
    }
}
