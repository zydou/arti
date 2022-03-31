//! Declare the `RetryStrategy` enumeration and related code.

use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};

/// A description of when an operation may be retried.
///
/// # Retry strategies values are contextual.
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
/// # Retry strategies depend on what we think might change.
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryTime {
    /// The operation can be retried immediately, and no delay is needed.
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
    /// The length of the delay will usually depend on how frequently the
    /// operation has failed in the past.  The `RetryDelay` type from
    /// `tor-basic-utils` is how we usually schedule these within Arti.
    ///
    /// This case should be used for problems that tend to be "self correcting",
    /// such as remote server failures (the server might come back up).
    AfterWaiting,

    /// The operation can be retried after a particular delay.
    ///
    /// This case should only be used if there is some reason not to return
    /// `AfterWaiting`: for example, if the implementor is providing their own
    /// back-off algorithm instead of using `RetryDelay.`
    After(Duration),

    /// The operation can be retried at some particular time in the future.
    ///
    /// This case is appropriate for when we have a failure condition caused by
    /// waiting for multiple other timeouts.  (For example, if we believe that
    /// all our guards are down, then we won't be able to try getting a guard
    /// until the next time guard is scheduled to be marked as retriable.)
    At(Instant),

    /// Retrying is unlikely to make this operation succeed, unless something
    /// else is fixed first.
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
    // Requires that `now` is the current time, and `choose_delay` is a
    /// function to choose a delay for [`RetryTime::AfterWaiting`].
    fn abs_retry_time<F>(&self, now: Instant, choose_delay: F) -> AbsRetryTime
    where
        F: FnOnce() -> Duration,
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
            RetryTime::AfterWaiting => AbsRetryTime::At(now + choose_delay()),
            RetryTime::After(d) => AbsRetryTime::At(now + d),
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
        let chosen_delay = once_cell::unsync::Lazy::new(choose_delay);

        items
            .map(|item| match item {
                RetryTime::AfterWaiting => AbsRetryTime::At(now + *chosen_delay),
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
    fn loose_cmp(&self, other: &Self) -> Ordering {
        use Ordering::*;
        match (self, other) {
            // Immediate precedes everything.
            (RetryTime::Immediate, RetryTime::Immediate) => Equal,
            (RetryTime::Immediate, _) => Less,
            (_, RetryTime::Immediate) => Greater,

            // When we have the same type, then we can compare based on actual
            // times.
            (RetryTime::AfterWaiting, RetryTime::AfterWaiting) => Equal,
            (RetryTime::After(d1), RetryTime::After(d2)) => d1.cmp(d2),
            (RetryTime::At(t1), RetryTime::At(t2)) => t1.cmp(t2),

            // Otherwise: pretend AfterWaiting is shorter than After, is shorter
            // than At.
            (RetryTime::AfterWaiting, RetryTime::After(_)) => Less,
            (RetryTime::AfterWaiting, RetryTime::At(_)) => Less,
            (RetryTime::After(_), RetryTime::AfterWaiting) => Greater,
            (RetryTime::After(_), RetryTime::At(_)) => Less,
            (RetryTime::At(_), RetryTime::AfterWaiting) => Greater,
            (RetryTime::At(_), RetryTime::After(_)) => Greater,

            // Everything precedes Never.
            (RetryTime::Never, RetryTime::Never) => Equal,
            (RetryTime::Never, _) => Greater,
            (_, RetryTime::Never) => Less,
        }
    }
}
