//! Definitions for [`SleepProviderExt`] and related types.

use crate::traits::SleepProvider;
use futures::{Future, FutureExt};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

/// An error value given when a function times out.
///
/// This value is generated when the timeout from
/// [`SleepProviderExt::timeout`] expires before the provided future
/// is ready.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_structs)]
pub struct TimeoutError;
impl std::error::Error for TimeoutError {}
impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timeout expired")
    }
}

impl From<TimeoutError> for std::io::Error {
    fn from(err: TimeoutError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, err)
    }
}

/// An extension trait on [`SleepProvider`] for timeouts and clock delays.
pub trait SleepProviderExt: SleepProvider {
    /// Wrap a [`Future`] with a timeout.
    ///
    /// The output of the new future will be the returned value of
    /// `future` if it completes within `duration`.  Otherwise, it
    /// will be `Err(TimeoutError)`.
    ///
    /// # Limitations
    ///
    /// This uses [`SleepProvider::sleep`] for its timer, and is
    /// subject to the same limitations.
    #[must_use = "timeout() returns a future, which does nothing unless used"]
    fn timeout<F: Future>(&self, duration: Duration, future: F) -> Timeout<F, Self::SleepFuture> {
        let sleep_future = self.sleep(duration);

        Timeout {
            future,
            sleep_future,
        }
    }

    /// Pause until the wall-clock is at `when` or later, trying to
    /// recover from clock jumps.
    ///
    /// Unlike [`SleepProvider::sleep()`], the future returned by this function will
    /// wake up periodically to check the current time, and see if
    /// it is at or past the target.
    ///
    /// # Limitations
    ///
    /// The ability of this function to detect clock jumps is limited
    /// to its granularity; it may finish a while after the declared
    /// wallclock time if the system clock jumps forward.
    ///
    /// This function does not detect backward clock jumps; arguably,
    /// we should have another function to do that.
    ///
    /// This uses [`SleepProvider::sleep`] for its timer, and is
    /// subject to the same limitations.
    #[must_use = "sleep_until_wallclock() returns a future, which does nothing unless used"]
    fn sleep_until_wallclock(&self, when: SystemTime) -> SleepUntilWallclock<'_, Self> {
        SleepUntilWallclock {
            provider: self,
            target: when,
            sleep_future: None,
        }
    }
}

impl<T: SleepProvider> SleepProviderExt for T {}

/// A timeout returned by [`SleepProviderExt::timeout`].
#[pin_project]
pub struct Timeout<T, S> {
    /// The future we want to execute.
    #[pin]
    future: T,
    /// The future implementing the timeout.
    #[pin]
    sleep_future: S,
}

impl<T, S> Future for Timeout<T, S>
where
    T: Future,
    S: Future<Output = ()>,
{
    type Output = Result<T::Output, TimeoutError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(x) = this.future.poll(cx) {
            return Poll::Ready(Ok(x));
        }

        match this.sleep_future.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(Err(TimeoutError)),
        }
    }
}

/// A future implementing [`SleepProviderExt::sleep_until_wallclock`].
pub struct SleepUntilWallclock<'a, SP: SleepProvider> {
    /// Reference to the provider that we use to make new SleepFutures.
    provider: &'a SP,
    /// The time that we are waiting for.
    target: SystemTime,
    /// The future representing our current delay.
    sleep_future: Option<Pin<Box<SP::SleepFuture>>>,
}

impl<'a, SP> Future for SleepUntilWallclock<'a, SP>
where
    SP: SleepProvider,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Strategy: we implement sleep_until_wallclock by
        // waiting in increments of up to MAX_SLEEP, checking the
        // wall clock before and after each increment.  This makes
        // us wake up a bit more frequently, but enables us to detect it
        // if the system clock jumps forward.
        let target = self.target;
        loop {
            let now = self.provider.wallclock();
            if now >= target {
                return Poll::Ready(());
            }

            let (last_delay, delay) = calc_next_delay(now, target);

            // Note that we store this future to keep it from being
            // cancelled, even though we don't ever poll it more than
            // once.
            //
            // TODO: I'm not sure that it's actually necessary to keep
            // this future around.
            self.sleep_future.take();

            let mut sleep_future = Box::pin(self.provider.sleep(delay));
            match sleep_future.poll_unpin(cx) {
                Poll::Pending => {
                    self.sleep_future = Some(sleep_future);
                    return Poll::Pending;
                }
                Poll::Ready(()) => {
                    if last_delay {
                        return Poll::Ready(());
                    }
                }
            }
        }
    }
}

/// We never sleep more than this much, in case our system clock jumps.
///
/// Note that there's a tradeoff here: Making this duration
/// shorter helps our accuracy, but makes us wake up more
/// frequently and consume more CPU.
const MAX_SLEEP: Duration = Duration::from_secs(600);

/// Return the amount of time we should wait next, when running
/// sleep_until_wallclock().  Also return a boolean indicating whether we
/// expect this to be the final delay.
///
/// (This is a separate function for testing.)
pub(crate) fn calc_next_delay(now: SystemTime, when: SystemTime) -> (bool, Duration) {
    let remainder = when
        .duration_since(now)
        .unwrap_or_else(|_| Duration::from_secs(0));
    if remainder > MAX_SLEEP {
        (false, MAX_SLEEP)
    } else {
        (true, remainder)
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
    #![allow(clippy::erasing_op)]
    use super::*;

    #[test]
    fn sleep_delay() {
        fn calc(now: SystemTime, when: SystemTime) -> Duration {
            calc_next_delay(now, when).1
        }
        let minute = Duration::from_secs(60);
        let second = Duration::from_secs(1);
        let start = SystemTime::now();

        let target = start + 30 * minute;

        assert_eq!(calc(start, target), minute * 10);
        assert_eq!(calc(target + minute, target), minute * 0);
        assert_eq!(calc(target, target), minute * 0);
        assert_eq!(calc(target - second, target), second);
        assert_eq!(calc(target - minute * 9, target), minute * 9);
        assert_eq!(calc(target - minute * 11, target), minute * 10);
    }
}
