//! Declare the `RetryTime` enumeration and related code.

use derive_more::{From, Into};
use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};
use strum::EnumDiscriminants;

/// A description of when an operation may be retried.
///
/// # Retry times values are contextual.
///
/// Note that retrying is necessarily contextual, depending on what exactly
/// we're talking about retrying.
///
/// For an example of how context matters:  suppose that we try to build a
/// circuit, and encounter a failure extending to the second hop.  If we try to
/// build a circuit _through the same path_ immediately, it's likely to fail
/// again.  But if we try to build a circuit through a different path, then
/// there's no reason to expect that same kind of error.
///
/// Thus, the same inner error condition ("failed to extend to the nth hop") can
/// indicate either a "Retry after waiting for a while" or "Retry immediately."
///
/// # Retry times depend on what we think might change.
///
/// Whether retrying will help depends on what we think is likely to change in
/// the near term.
///
/// For example, we generally assume an unreachable relay has some likelihood of
/// becoming reachable in the near future, and therefore connecting to such a
/// relay is worth retrying.
///
/// On the other hand, we _don't_ assume that the network is changing wildly
/// over time.  Thus, if there is currently no relay that supports delivering
/// traffic to port 23 (telnet), we say that building a request for such a relay
/// is not retriable, even though technically such a relay might appear in the
/// next consensus.
#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumDiscriminants)]
#[non_exhaustive]
// We define a discriminant type so we can simplify loose_cmp.
#[strum_discriminants(derive(Ord, PartialOrd))]
// We don't want to expose RetryTimeDiscriminants.
#[strum_discriminants(vis())]
pub enum RetryTime {
    /// The operation can be retried immediately, and no delay is needed.
    ///
    /// The recipient of this `RetryTime` variant may retry the operation
    /// immediately without waiting.
    ///
    /// This case should be used cautiously: it risks making code retry in a
    /// loop without delay.  It should only be used for error conditions that
    /// are necessarily produced via a process that itself introduces a delay.
    /// (For example, this case is suitable for errors caused by a remote
    /// timeout.)
    Immediate,

    /// The operation can be retried after a short delay, to prevent overloading
    /// the network.  
    ///
    /// The recipient of this `RetryTime` variant should delay a short amount of
    /// time before retrying.  The amount of time to delay should be randomized,
    /// and should tend to grow larger the more failures there have been
    /// recently for the given operation.  (The `RetryDelay` type from
    /// `tor-basic-utils` is suitable for managing this calculation.)
    ///
    /// This case should be used for problems that tend to be "self correcting",
    /// such as remote server failures (the server might come back up).
    AfterWaiting,

    /// The operation can be retried after a particular delay.
    ///
    /// The recipient of this `RetryTime` variant should wait for at least the
    /// given duration before retrying the operation.
    ///
    /// This case should only be used if there is some reason not to return
    /// `AfterWaiting`: for example, if the implementor is providing their own
    /// back-off algorithm instead of using `RetryDelay.`
    ///
    /// (This is a separate variant from `At`, since the constructor may not
    /// have convenient access to (a mocked view of) the current time.  If you
    /// know that the current time is `now`, then `After(d)` is equivalent to
    /// `At(now + d)`.)
    After(Duration),

    /// The operation can be retried at some particular time in the future.
    ///
    /// The recipient of this this `RetryTime` variant should wait until the
    /// current time (as returned by `Instant::now` or `SleepProvider::now` as
    /// appropriate) is at least this given instant.
    ///
    /// This case is appropriate for when we have a failure condition caused by
    /// waiting for multiple other timeouts.  (For example, if we believe that
    /// all our guards are down, then we won't be able to try getting a guard
    /// until the next time guard is scheduled to be marked as retriable.)
    At(Instant),

    /// Retrying is unlikely to make this operation succeed, unless something
    /// else is fixed first.
    ///
    /// The recipient of this `RetryTime` variant should generally give up, and
    /// stop retrying the given operation.
    ///
    /// We don't mean "literally" that the operation will never succeed: only
    /// that retrying it in the near future without fixing the underlying cause
    /// is unlikely to help.
    ///
    /// This case is appropriate for issues like misconfiguration, internal
    /// errors, and requests for operations that the network doesn't support.
    ///
    /// This case is also appropriate for a problem that is "technically"
    /// retriable, but where any resolution is likelier to take days or weeks
    /// instead  of minutes or hours.
    Never,
}

/// A `RetryTime` wrapped so that it compares according to [`RetryTime::loose_cmp`]
#[derive(From, Into, Copy, Clone, Debug, Eq, PartialEq)]
pub struct LooseCmpRetryTime(RetryTime);

/// Trait for an error object that can tell us when the operation which
/// generated it can be retried.
pub trait HasRetryTime {
    /// Return the time when the operation that gave this error can be retried.
    ///
    /// See all caveats and explanations on [`RetryTime`].
    fn retry_time(&self) -> RetryTime;

    /// Return an absolute retry when the operation that gave this error can be
    /// retried.
    ///
    /// Requires that `now` is the current time, and `choose_delay` is a
    /// function to choose a delay for [`RetryTime::AfterWaiting`].
    fn abs_retry_time<F>(&self, now: Instant, choose_delay: F) -> AbsRetryTime
    where
        F: FnOnce() -> Duration,
        Self: Sized,
    {
        self.retry_time().absolute(now, choose_delay)
    }
}

/// An absolute [`RetryTime`].
///
/// Unlike `RetryTime`, this type always denotes a particular instant in time.
/// You can derive it using [`RetryTime::absolute`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[allow(clippy::exhaustive_enums)]
pub enum AbsRetryTime {
    /// See [`RetryTime::Immediate`].
    Immediate,
    /// See [`RetryTime::At`].
    At(Instant),
    /// See [`RetryTime::Never`].
    Never,
}

impl AbsRetryTime {
    /// Construct an AbsRetryTime representing `base` + `plus`.
    fn from_sum(base: Instant, plus: Duration) -> Self {
        match base.checked_add(plus) {
            Some(t) => AbsRetryTime::At(t),
            None => AbsRetryTime::Never,
        }
    }
}

impl RetryTime {
    /// Convert this [`RetryTime`] in to an absolute time.
    ///
    /// Requires that `now` is the current time, and `choose_delay` is a
    /// function to choose a delay for [`RetryTime::AfterWaiting`].
    pub fn absolute<F>(self, now: Instant, choose_delay: F) -> AbsRetryTime
    where
        F: FnOnce() -> Duration,
    {
        match self {
            RetryTime::Immediate => AbsRetryTime::Immediate,
            RetryTime::AfterWaiting => AbsRetryTime::from_sum(now, choose_delay()),
            RetryTime::After(d) => AbsRetryTime::from_sum(now, d),
            RetryTime::At(t) => AbsRetryTime::At(t),
            RetryTime::Never => AbsRetryTime::Never,
        }
    }

    /// Convert all the provided `items` into [`AbsRetryTime`] values, and
    /// return the earliest one.
    ///
    /// Requires that `now` is the current time, and `choose_delay` is a
    /// function to choose a delay for [`RetryTime::AfterWaiting`].
    ///
    /// Differs from `items.map(AbsRetryTime::absolute(now,
    /// choose_delay)).min()` in that it calls `choose_delay` at most once.
    pub fn earliest_absolute<I, F>(items: I, now: Instant, choose_delay: F) -> Option<AbsRetryTime>
    where
        I: Iterator<Item = RetryTime>,
        F: FnOnce() -> Duration,
    {
        let chosen_delay =
            once_cell::unsync::Lazy::new(|| AbsRetryTime::from_sum(now, choose_delay()));

        items
            .map(|item| match item {
                RetryTime::AfterWaiting => *chosen_delay,
                other => other.absolute(now, || unreachable!()),
            })
            .min()
    }

    /// Return the "approximately earliest" item for an iterator of retry times.
    ///
    /// This is necessarily an approximation, since we can't be sure what time
    /// will be chosen if the retry is supposed to happen at a random time, and
    /// therefore cannot tell whether `AfterWaiting` comes before or after
    /// particular `At` and `After` instances.
    ///
    /// If you need an exact answer, use earliest_absolute.
    pub fn earliest_approx<I>(items: I) -> Option<RetryTime>
    where
        I: Iterator<Item = RetryTime>,
    {
        items.min_by(|a, b| a.loose_cmp(b))
    }

    /// A loose-but-total comparison operator, suitable for choosing a retry
    /// time when multiple attempts have failed.
    ///
    /// If you need an absolute comparison operator, convert to [`AbsRetryTime`] first.
    ///
    /// See also:
    /// [`LooseCmpRetryTime`], a wrapper for `RetryTime` that uses this comparison.
    pub fn loose_cmp(&self, other: &Self) -> Ordering {
        use RetryTime as RT;

        match (self, other) {
            // When we have the same type with an internal embedded duration or time,
            // we compare based on the duration or time.
            (RT::After(d1), RetryTime::After(d2)) => d1.cmp(d2),
            (RT::At(t1), RetryTime::At(t2)) => t1.cmp(t2),

            // Otherwise, we compare based on discriminant type.
            //
            // This can't do a perfect "apples-to-apples" comparison for
            // `AfterWaiting` vs `At` vs `After`, but at least it imposes a
            // total order.
            (a, b) => RetryTimeDiscriminants::from(a).cmp(&RetryTimeDiscriminants::from(b)),
        }
    }
}

impl Ord for LooseCmpRetryTime {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.loose_cmp(&other.0)
    }
}
impl PartialOrd for LooseCmpRetryTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
    fn comparison() {
        use RetryTime as RT;
        let sec = Duration::from_secs(1);
        let now = Instant::now();

        let sorted = vec![
            RT::Immediate,
            RT::AfterWaiting,
            RT::After(sec * 10),
            RT::After(sec * 20),
            RT::At(now),
            RT::At(now + sec * 30),
            RT::Never,
        ];

        // Verify that these objects are actually in loose-cmp sorted order.
        for (i, a) in sorted.iter().enumerate() {
            for (j, b) in sorted.iter().enumerate() {
                assert_eq!(a.loose_cmp(b), i.cmp(&j));
            }
        }
    }

    #[test]
    fn abs_comparison() {
        use AbsRetryTime as ART;
        let sec = Duration::from_secs(1);
        let now = Instant::now();

        let sorted = vec![
            ART::Immediate,
            ART::At(now),
            ART::At(now + sec * 30),
            ART::Never,
        ];

        // Verify that these objects are actually in loose-cmp sorted order.
        for (i, a) in sorted.iter().enumerate() {
            for (j, b) in sorted.iter().enumerate() {
                assert_eq!(a.cmp(b), i.cmp(&j));
            }
        }
    }

    #[test]
    fn earliest_absolute() {
        let sec = Duration::from_secs(1);
        let now = Instant::now();

        let times = vec![RetryTime::AfterWaiting, RetryTime::Never];

        let earliest = RetryTime::earliest_absolute(times.into_iter(), now, || sec);
        assert_eq!(
            earliest.expect("no absolute time"),
            AbsRetryTime::At(now + sec)
        );
    }

    #[test]
    fn abs_from_sum() {
        let base = Instant::now();
        let delta = Duration::from_secs(1);
        assert_eq!(
            AbsRetryTime::from_sum(base, delta),
            AbsRetryTime::At(base + delta)
        );

        assert_eq!(
            AbsRetryTime::from_sum(base, Duration::MAX),
            AbsRetryTime::Never
        );
    }
}
