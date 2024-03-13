//! Channel padding
//!
//! Tor spec `padding-spec.txt` section 2.
//!
//! # Overview of channel padding control arrangements
//!
//!  1. `tor_chanmgr::mgr::map` collates information about dormancy, netdir,
//!     and overall client configuration, to maintain a
//!     [`ChannelPaddingInstructions`](crate::channel::ChannelPaddingInstructions)
//!     which is to be used for all relevant[^relevant] channels.
//!     This is distributed to channel frontends (`Channel`s)
//!     by calling `Channel::reparameterize`.
//!
//!  2. Circuit and channel `get_or_launch` methods all take a `ChannelUsage`.
//!     This is plumbed through the layers to `AbstractChanMgr::get_or_launch`,
//!     which passes it to the channel frontend via `Channel::note_usage`.
//!
//!  3. The `Channel` collates this information, and maintains an idea
//!     of whether padding is relevant for this channel (`PaddingControlState`).
//!     For channels where it *is* relevant, it sends `CtrlMsg::ConfigUpdate`
//!     to the reactor.
//!
//!  4. The reactor handles `CtrlMsg::ConfigUpdate` by reconfiguring is padding timer;
//!     and by sending PADDING_NEGOTIATE cell(s).
//!
//! [^relevant]: A "relevant" channel is one which is not excluded by the rules about
//! padding in padding-spec 2.2.  Arti does not currently support acting as a relay,
//! so all our channels are client-to-guard or client-to-directory.

use std::pin::Pin;
// TODO, coarsetime maybe?  But see arti#496 and also we want to use the mockable SleepProvider
use std::time::{Duration, Instant};

use derive_builder::Builder;
use educe::Educe;
use futures::future::{self, FusedFuture};
use futures::FutureExt;
use pin_project::pin_project;
use rand::distributions::Distribution;
use tracing::error;

use tor_cell::chancell::msg::{Padding, PaddingNegotiate};
use tor_config::impl_standard_builder;
use tor_error::into_internal;
use tor_rtcompat::SleepProvider;
use tor_units::IntegerMilliseconds;

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
    ///
    /// Can be `None` to mean the timing parameters are set to infinity.
    parameters: Option<PreparedParameters>,

    /// Gap that we intend to leave between last sent cell, and the padding
    ///
    /// We only resample this (calculating a new random delay) after the previous
    /// timeout actually expired.
    ///
    /// `None` if the timer is disabled.
    /// (This can be done explicitly, but also occurs on time calculation overflow.)
    ///
    /// Invariants: this field may be `Some` or `None` regardless of the values
    /// of other fields.  If this field is `None` then the values in `trigger_at`
    /// and `waker` are unspecified.
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
    ///
    /// Invariants: the value in this field is meaningful only if `selected_timeout`
    /// is `Some`.
    ///
    /// If `selected_timeout` is `Some`, and `trigger_at` is therefore valid,
    /// it is (obviously) no later than `selected_timeout` from now.
    ///
    /// See also `waker`.
    trigger_at: Option<Instant>,

    /// Actual waker from the `SleepProvider`
    ///
    /// This is created and updated lazily, because we suspect that with some runtimes
    /// setting timeouts may be slow.
    /// Lazy updating means that with intermittent data traffic, we do not keep scheduling,
    /// descheduling, and adjusting, a wakeup time.
    ///
    /// Invariants:
    ///
    /// If `selected_timeout` is `Some`,
    /// the time at which this waker will trigger here is never *later* than `trigger_at`,
    /// and never *later* than `selected_timeout` from now.
    ///
    /// The wakeup time here may well be earlier than `trigger_at`,
    /// and sooner than `selected_timeout` from now.  It may even be in the past.
    /// When we wake up and discover this situation, we reschedule a new waker.
    ///
    /// If `selected_timeout` is `None`, the value is unspecified.
    /// We may retain a `Some` in this case so that if `SleepProvider` is enhanced to
    /// support rescheduling, we can do that without making a new `SleepFuture`
    /// (and without completely reorganising this the `Timer` state structure.)
    #[pin]
    waker: Option<R::SleepFuture>,
}

/// Timing parameters, as described in `padding-spec.txt`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Builder)]
#[builder(build_fn(error = "tor_error::Bug"))]
pub struct Parameters {
    /// Low end of the distribution of `X`
    #[builder(default = "1500.into()")]
    pub(crate) low: IntegerMilliseconds<u32>,
    /// High end of the distribution of `X` (inclusive)
    #[builder(default = "9500.into()")]
    pub(crate) high: IntegerMilliseconds<u32>,
}

impl_standard_builder! { Parameters: !Deserialize + !Builder + !Default }

impl Parameters {
    /// Return a `PADDING_NEGOTIATE START` cell specifying precisely these parameters
    ///
    /// This function does not take account of the need to avoid sending particular
    /// parameters, and instead sending zeroes, if the requested padding is the consensus
    /// default.  The caller must take care of that.
    pub fn padding_negotiate_cell(&self) -> Result<PaddingNegotiate, tor_error::Bug> {
        let get = |input: IntegerMilliseconds<u32>| {
            input
                .try_map(TryFrom::try_from)
                .map_err(into_internal!("padding negotiate out of range"))
        };
        Ok(PaddingNegotiate::start(get(self.low)?, get(self.high)?))
    }

    /// Make a Parameters containing the specification-defined default parameters
    pub fn default_padding() -> Self {
        Parameters::builder().build().expect("build succeeded")
    }

    /// Make a Parameters sentinel value, with both fields set to zero, which means "no padding"
    pub fn disabled() -> Self {
        Parameters {
            low: 0.into(),
            high: 0.into(),
        }
    }
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
        let parameters = parameters.prepare();
        let selected_timeout = parameters.select_timeout();
        // Too different to new_disabled to share its code, sadly.
        Timer {
            sleep_prov,
            parameters: Some(parameters),
            selected_timeout: Some(selected_timeout),
            trigger_at: None,
            waker: None,
        }
    }

    /// Create a new `Timer` which starts out disabled
    pub(crate) fn new_disabled(sleep_prov: R, parameters: Option<Parameters>) -> Self {
        Timer {
            sleep_prov,
            parameters: parameters.map(|p| p.prepare()),
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

    /// Set this `Timer`'s parameters
    ///
    /// Will not enable or disable the timer; that must be done separately if desired.
    ///
    /// The effect may not be immediate: if we are already in a gap between cells,
    /// that existing gap may not be adjusted.
    /// (We don't *restart* the timer since that would very likely result in a gap
    /// longer than either of the configured values.)
    ///
    /// Idempotent.
    pub(crate) fn reconfigure(self: &mut Pin<&mut Self>, parameters: &Parameters) {
        *self.as_mut().project().parameters = Some(parameters.prepare());
    }

    /// Enquire whether this `Timer` is currently enabled
    pub(crate) fn is_enabled(&self) -> bool {
        self.selected_timeout.is_some()
    }

    /// Select a fresh timeout (and enable, if possible)
    fn select_fresh_timeout(self: Pin<&mut Self>) {
        let mut self_ = self.project();
        let timeout = self_.parameters.as_ref().map(|p| p.select_timeout());
        *self_.selected_timeout = timeout;
        // This is no longer valid; recalculate it on next poll
        *self_.trigger_at = None;
        // Timeout might be earlier, so we will need a new waker too.
        self_.waker.set(None);
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
    ///
    /// (`next()` has to be selected on, along with other possible events, in the
    /// main loop, so that the padding timer runs concurrently with other processing;
    /// and it should be in a low-priority branch of `select_biased!` as an optimisation:
    /// that avoids calculating timeouts etc. until necessary,
    /// i.e. it calculates them only when the main loop would otherwise block.)
    ///
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
                self.low.as_millis(),
                self.high.as_millis(),
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
    use futures::future::ready;
    use futures::select_biased;
    use itertools::{izip, Itertools};
    use statrs::distribution::ContinuousCDF;
    use tokio::pin;
    use tokio_crate as tokio;
    use tor_rtcompat::*;

    async fn assert_not_ready<R: Runtime>(timer: &mut Pin<&mut Timer<R>>) {
        select_biased! {
            _ = timer.as_mut().next() => panic!("unexpectedly ready"),
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
            low: 1000.into(),
            high: 1000.into(),
        };

        let () = runtime.block_on(async {
            let timer = Timer::new(runtime.clone(), parameters);
            pin!(timer);
            assert_eq! { true, timer.is_enabled() }

            // expiry time not yet calculated
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

        let () = runtime.block_on(async {
            let timer = Timer::new_disabled(runtime.clone(), None);
            assert! { timer.parameters.is_none() };
            pin!(timer);
            assert_not_ready(&mut timer).await;
            assert! { timer.as_mut().selected_timeout.is_none() };
            assert! { timer.as_mut().trigger_at.is_none() };
        });

        let () = runtime.block_on(async {
            let timer = Timer::new_disabled(runtime.clone(), Some(parameters));
            assert! { timer.parameters.is_some() };
            pin!(timer);
            assert_not_ready(&mut timer).await;
            runtime.advance(Duration::from_millis(3000)).await;
            assert_not_ready(&mut timer).await;
            timer.as_mut().enable();
            assert_not_ready(&mut timer).await;
            runtime.advance(Duration::from_millis(3000)).await;
            assert_is_ready(&mut timer).await;
        });
    }

    #[test]
    #[allow(clippy::print_stderr)]
    fn timeout_distribution() {
        // Test that the distribution of padding intervals is as we expect.  This is not so
        // straightforward.  We need to deal with true randomness (since we can't plumb a
        // testing RNG into the padding timer, and perhaps don't even *want* to make that a
        // mockable interface).  Measuring a distribution of random variables involves some
        // statistics.

        // The overall approach is:
        //    Use a fixed (but nontrivial) low to high range
        //    Sample N times into n equal sized buckets
        //    Calculate the expected number of samples in each bucket
        //    Do a chi^2 test.  If it doesn't spot a potential difference, declare OK.
        //    If the chi^2 test does definitely declare a difference, declare failure.
        //    Otherwise increase N and go round again.
        //
        // This allows most runs to be fast without having an appreciable possibility of a
        // false test failure and while being able to detect even quite small deviations.

        // Notation from
        // https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test#Calculating_the_test-statistic
        // I haven't done a formal power calculation but empirically
        // this detects the following most of the time:
        //  deviation of the CDF power from B^2 to B^1.98
        //  wrong minimum value by 25ms out of 12s, low_ms = min + 25
        //  wrong maximum value by 10ms out of 12s, high_ms = max -1 - 10

        #[allow(non_snake_case)]
        let mut N = 100_0000;

        #[allow(non_upper_case_globals)]
        const n: usize = 100;

        const P_GOOD: f64 = 0.05; // Investigate further 5% of times (if all is actually well)
        const P_BAD: f64 = 1e-12;

        loop {
            eprintln!("padding distribution test, n={} N={}", n, N);

            let min = 5000;
            let max = 17000; // Exclusive
            assert_eq!(0, (max - min) % (n as u32)); // buckets must match up to integer boundaries

            let cdf = (0..=n)
                .map(|bi| {
                    let b = (bi as f64) / (n as f64);
                    // expected distribution:
                    // with B = bi / n
                    //   P(X) < B == B
                    //   P(max(X1,X1)) < B = B^2
                    b.powi(2)
                })
                .collect_vec();

            let pdf = cdf
                .iter()
                .cloned()
                .tuple_windows()
                .map(|(p, q)| q - p)
                .collect_vec();
            let exp = pdf.iter().cloned().map(|p| p * f64::from(N)).collect_vec();

            // chi-squared test only valid if every cell expects at least 5
            assert!(exp.iter().cloned().all(|ei| ei >= 5.));

            let mut obs = [0_u32; n];

            let params = Parameters {
                low: min.into(),
                high: (max - 1).into(), // convert exclusive to inclusive
            }
            .prepare();

            for _ in 0..N {
                let xx = params.select_timeout();
                let ms = xx.as_millis();
                let ms = u32::try_from(ms).unwrap();
                assert!(ms >= min);
                assert!(ms < max);
                // Integer arithmetic ensures that we classify exactly
                let bi = ((ms - min) * (n as u32)) / (max - min);
                obs[bi as usize] += 1;
            }

            let chi2 = izip!(&obs, &exp)
                .map(|(&oi, &ei)| (f64::from(oi) - ei).powi(2) / ei)
                .sum::<f64>();

            // n degrees of freedom, one-tailed test
            // (since distro parameters are all fixed, not estimated from the sample)
            let chi2_distr = statrs::distribution::ChiSquared::new(n as _).unwrap();

            // probability of good code generating a result at least this bad
            let p = 1. - chi2_distr.cdf(chi2);

            eprintln!(
                "padding distribution test, n={} N={} chi2={} p={}",
                n, N, chi2, p
            );

            if p >= P_GOOD {
                break;
            }

            for (i, (&oi, &ei)) in izip!(&obs, &exp).enumerate() {
                eprintln!("bi={:4} OI={:4} EI={}", i, oi, ei);
            }

            if p < P_BAD {
                panic!("distribution is wrong (p < {:e})", P_BAD);
            }

            // This is statistically rather cheaty: we keep trying until we get a definite
            // answer!  But we radically increase the power of the test each time.
            // If the distribution is really wrong, this test ought to find it soon enough,
            // especially since we run this repeatedly in CI.
            N *= 10;
        }
    }
}
