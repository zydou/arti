//! Channel padding
//!
//! Tor spec `padding-spec.txt` section 2.

use std::pin::Pin;
// TODO, coaursetime maybe?  But see arti#496 and also we want to use the mockable SleepProvider
use std::time::{Duration, Instant};

use educe::Educe;
use futures::future::{self, FusedFuture};
use futures::FutureExt;
use pin_project::pin_project;
use rand::distributions::Distribution;
use tracing::error;

use tor_cell::chancell::msg::Padding;
use tor_rtcompat::SleepProvider;

/// Timer that organises wakeups when channel padding should be sent
///
/// Use [`next()`](Timer::next) to find when to send padding, and
/// [`note_cell_sent()`](Timer::note_cell_sent) to reset the timeout when data flows.
///
/// A `Timer` can be in "disabled" state, in which case `next()` never completes.
///
/// `Timer` must be pinned before use
/// (this allows us to avoid involving the allocator when we reschedule).
#[pin_project(project = PaddingTimerProj)]
pub(crate) struct Timer<R: SleepProvider> {
    /// [`SleepProvider`]
    sleep_prov: R,

    /// Parameters controlling distribution of padding time intervals
    parameters: PreparedParameters,

    /// Gap that we intend to leave between last sent cell, and the padding
    ///
    /// We only resample this (calculating a new random delay) after the previous
    /// timeout actually expired.
    ///
    /// `None` if the timer is disabled.
    /// (This can be done explicitly, but also occurs on time calculation overflow.)
    selected_timeout: Option<Duration>,

    /// Absolute time at which we should send padding
    ///
    /// `None` if cells more recently sent than we were polled.
    /// That would mean that we are currently moving data out through this channel.
    /// The absolute timeout will need to be recalculated when the data flow pauses.
    ///
    /// `Some` means our `next` has been demanded recently.
    /// Then `trigger_at` records the absolute timeout at which we should send padding,
    /// which was calculated the first time we were polled (after data).
    trigger_at: Option<Instant>,

    /// Actual waker from the `SleepProvider`
    ///
    /// This is created and updated lazily, because we suspect that with some runtimes
    /// setting timeouts may be slow.
    /// Laxy updating means that with intermittent data traffic, we do not keep scheduling,
    /// descheduling, and adjusting, a wakeup time.
    ///
    /// The wakeup time here may well be earlier than `trigger_at` -- even in the past.
    /// When we wake up and discover this situation., we reschedule a new waker.
    ///
    /// The time at which this waker will trigger here is never *later* than `trigger_at`.
    #[pin]
    waker: Option<R::SleepFuture>,
}

/// Timing parameters, as described in `padding-spec.txt`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Parameters {
    /// Low end of the distribution of `X`
    pub(crate) low_ms: u32,
    /// High end of the distribution of `X` (inclusive)
    pub(crate) high_ms: u32,
}

/// Timing parameters, "compiled" into a form which can be sampled more efficiently
///
/// According to the docs for [`rand::Rng::gen_range`],
/// it is better to construct a distribution,
/// than to call `gen_range` repeatedly on the same range.
#[derive(Debug, Clone)]
struct PreparedParameters {
    /// The distribution of `X` (not of the ultimate delay, which is `max(X1,X2)`)
    x_distribution_ms: rand::distributions::Uniform<u32>,
}

/// Return value from `prepare_to_sleep`: instructions for what caller ought to do
#[derive(Educe)]
#[educe(Debug)]
enum SleepInstructions<'f, R: SleepProvider> {
    /// Caller should send padding immediately
    Immediate {
        /// The current `Instant`, returned so that the caller need not call `now` again
        now: Instant,
    },
    /// Caller should wait forever
    Forever,
    /// Caller should `await` this
    Waker(#[educe(Debug(ignore))] Pin<&'f mut R::SleepFuture>),
}

impl<R: SleepProvider> Timer<R> {
    /// Create a new `Timer`
    #[allow(dead_code)]
    pub(crate) fn new(sleep_prov: R, parameters: Parameters) -> Self {
        let mut self_ = Self::new_disabled(sleep_prov, parameters);
        // We would like to call select_fresh_timeout but we don't have
        // (and can't have) Pin<&mut self>
        self_.selected_timeout = Some(self_.parameters.select_timeout());
        self_
    }

    /// Create a new `Timer` which starts out disabled
    pub(crate) fn new_disabled(sleep_prov: R, parameters: Parameters) -> Self {
        Timer {
            sleep_prov,
            parameters: parameters.prepare(),
            selected_timeout: None,
            trigger_at: None,
            waker: None,
        }
    }

    /// Disable this `Timer`
    ///
    /// Idempotent.
    pub(crate) fn disable(self: &mut Pin<&mut Self>) {
        *self.as_mut().project().selected_timeout = None;
    }

    /// Enable this `Timer`
    ///
    /// (If the timer was disabled, the timeout will only start to run when `next()`
    /// is next polled.)
    ///
    /// Idempotent.
    pub(crate) fn enable(self: &mut Pin<&mut Self>) {
        if !self.is_enabled() {
            self.as_mut().select_fresh_timeout();
        }
    }

    /// Eqnuire whether this `Timer` is currently enabled
    pub(crate) fn is_enabled(&self) -> bool {
        self.selected_timeout.is_some()
    }

    /// Select a fresh timeout (and enable)
    fn select_fresh_timeout(self: Pin<&mut Self>) -> Duration {
        let mut self_ = self.project();
        let timeout = self_.parameters.select_timeout();
        *self_.selected_timeout = Some(timeout);
        // This is no longer invalide; recalculate it on next poll
        *self_.trigger_at = None;
        // Timeout might be earlier, so we will need a new waker too.
        // (Technically this is not possible in a bad way right now, since any stale waker
        // must be older, and so earlier, albeit from a previous random timeout.
        // However in the future we may want to be able to adjust the timeout at runtime
        // and then a stale waker might be harmfully too late.)
        self_.waker.set(None);
        timeout
    }

    /// Note that data has been sent (ie, reset the timeout, delaying the next padding)
    pub(crate) fn note_cell_sent(self: &mut Pin<&mut Self>) {
        // Fast path, does not need to do anything but clear the absolute expiry time
        let self_ = self.as_mut().project();
        *self_.trigger_at = None;
    }

    /// Calculate when to send padding, and return a suitable waker
    ///
    /// In the usual case returns [`SleepInstructions::Waker`].
    fn prepare_to_sleep(mut self: Pin<&mut Self>, now: Option<Instant>) -> SleepInstructions<R> {
        let mut self_ = self.as_mut().project();

        let timeout = match self_.selected_timeout {
            None => return SleepInstructions::Forever,
            Some(t) => *t,
        };

        if self_.waker.is_some() {
            // We need to do this with is_some and expect because we need to consume self
            // to get a return value with the right lifetimes.
            let waker = self
                .project()
                .waker
                .as_pin_mut()
                .expect("None but we just checked");
            return SleepInstructions::Waker(waker);
        }

        let now = now.unwrap_or_else(|| self_.sleep_prov.now());

        let trigger_at = match self_.trigger_at {
            Some(t) => t,
            None => self_.trigger_at.insert(match now.checked_add(timeout) {
                None => {
                    error!("timeout overflowed computing next channel padding");
                    self.disable();
                    return SleepInstructions::Forever;
                }
                Some(r) => r,
            }),
        };

        let remaining = trigger_at.checked_duration_since(now).unwrap_or_default();
        if remaining.is_zero() {
            return SleepInstructions::Immediate { now };
        }

        //dbg!(timeout, remaining, now, trigger_at);

        // There is no Option::get_pin_mut_or_set_with
        if self_.waker.is_none() {
            self_.waker.set(Some(self_.sleep_prov.sleep(remaining)));
        }
        let waker = self
            .project()
            .waker
            .as_pin_mut()
            .expect("None but we just inserted!");
        SleepInstructions::Waker(waker)
    }

    /// Wait until we should next send padding, and then return the padding message
    ///
    /// Should be used as a low-priority branch within `select_biased!`.
    /// The returned future is async-cancel-safe,
    /// but once it yields, the padding must actually be sent.
    pub(crate) fn next(self: Pin<&mut Self>) -> impl FusedFuture<Output = Padding> + '_ {
        self.next_inner().fuse()
    }

    /// Wait until we should next send padding (not `FusedFuture`)
    ///
    /// Callers wants a [`FusedFuture`] because `select!` needs one.
    async fn next_inner(mut self: Pin<&mut Self>) -> Padding {
        let now = loop {
            match self.as_mut().prepare_to_sleep(None) {
                SleepInstructions::Forever => future::pending().await,
                SleepInstructions::Immediate { now } => break now,
                SleepInstructions::Waker(waker) => waker.await,
            }

            // This timer has fired and has therefore been used up.
            // When we go round again we will make a new one.
            //
            // TODO: have SleepProviders provide a reschedule function, and use it.
            // That is likely to be faster where supported.
            self.as_mut().project().waker.set(None);
        };

        // It's time to send padding.

        // Firstly, calculate the new timeout for the *next* padding,
        // so that we leave the `Timer` properly programmed.
        self.as_mut().select_fresh_timeout();

        // Bet that we will be going to sleep again, and set up the new trigger time
        // and waker now.  This will save us a future call to Instant::now.
        self.as_mut().prepare_to_sleep(Some(now));

        Padding::new()
    }
}

impl Parameters {
    /// "Compile" the parameters into a form which can be quickly sampled
    fn prepare(self) -> PreparedParameters {
        PreparedParameters {
            x_distribution_ms: rand::distributions::Uniform::new_inclusive(
                self.low_ms,
                self.high_ms,
            ),
        }
    }
}

impl PreparedParameters {
    /// Randomly select a timeout (as per `padding-spec.txt`)
    fn select_timeout(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let ms = std::cmp::max(
            self.x_distribution_ms.sample(&mut rng),
            self.x_distribution_ms.sample(&mut rng),
        );
        Duration::from_millis(ms.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::bool_assert_comparison)]
mod test {
    use super::*;
    use futures::future::ready;
    use futures::select_biased;
    use tokio::pin;
    use tokio_crate as tokio;
    use tor_rtcompat::*;

    async fn assert_not_ready<R: Runtime>(timer: &mut Pin<&mut Timer<R>>) {
        select_biased! {
            _ = timer.as_mut().next() => panic!("unexpedtedly ready"),
            _ = ready(()) => { },
        };
    }

    async fn assert_is_ready<R: Runtime>(timer: &mut Pin<&mut Timer<R>>) {
        let _: Padding = select_biased! {
            p = timer.as_mut().next() => p,
            _ = ready(()) => panic!("pad timer failed to yield"),
        };
    }

    #[test]
    fn timer_impl() {
        let runtime = tor_rtcompat::tokio::TokioNativeTlsRuntime::create().unwrap();
        let runtime = tor_rtmock::MockSleepRuntime::new(runtime);

        let parameters = Parameters {
            low_ms: 1000,
            high_ms: 1000,
        };

        let () = runtime.block_on(async {
            let timer = Timer::new(runtime.clone(), parameters);
            pin!(timer);
            assert_eq! { true, timer.is_enabled() }

            // expiry time not yet caqlculated
            assert_eq! { timer.as_mut().trigger_at, None };

            // ---------- timeout value ----------

            // Just created, not ready yet
            assert_not_ready(&mut timer).await;

            runtime.advance(Duration::from_millis(999)).await;
            // Not quite ready
            assert_not_ready(&mut timer).await;

            runtime.advance(Duration::from_millis(1)).await;
            // Should go off precisely now
            assert_is_ready(&mut timer).await;

            assert_not_ready(&mut timer).await;
            runtime.advance(Duration::from_millis(1001)).await;
            // Should go off 1ms ago, fine
            assert_is_ready(&mut timer).await;

            // ---------- various resets ----------

            runtime.advance(Duration::from_millis(500)).await;
            timer.note_cell_sent();
            assert_eq! { timer.as_mut().trigger_at, None };

            // This ought not to cause us to actually calculate the expiry time
            let () = select_biased! {
                _ = ready(()) => { },
                _ = timer.as_mut().next() => panic!(),
            };
            assert_eq! { timer.as_mut().trigger_at, None };

            // ---------- disable/enable ----------

            timer.disable();
            runtime.advance(Duration::from_millis(2000)).await;
            assert_eq! { timer.as_mut().selected_timeout, None };
            assert_eq! { false, timer.is_enabled() }
            assert_not_ready(&mut timer).await;

            timer.enable();
            runtime.advance(Duration::from_millis(3000)).await;
            assert_eq! { true, timer.is_enabled() }
            // Shouldn't be already ready, since we haven't polled yet
            assert_not_ready(&mut timer).await;

            runtime.advance(Duration::from_millis(1000)).await;
            // *Now*
            assert_is_ready(&mut timer).await;
        });

        let () = runtime.block_on(async {
            let timer = Timer::new(runtime.clone(), parameters);
            pin!(timer);

            assert! { timer.as_mut().selected_timeout.is_some() };
            assert! { timer.as_mut().trigger_at.is_none() };
            // Force an overflow by guddling
            *timer.as_mut().project().selected_timeout = Some(Duration::MAX);

            assert_not_ready(&mut timer).await;
            dbg!(timer.as_mut().project().trigger_at);
            assert_eq! { false, timer.is_enabled() }
        });
    }
}
