//! Simple provider of simulated time
//!
//! See [`SimpleMockTimeProvider`]

use std::cmp::Reverse;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime};

use derive_more::AsMut;
use priority_queue::priority_queue::PriorityQueue;
use slotmap::DenseSlotMap;

use tor_rtcompat::SleepProvider;

/// Simple provider of simulated time
///
/// Maintains a mocked view of the current [`Instant`] and [`SystemTime`].
///
/// The simulated time advances only when explicitly instructed,
/// by calling [`.advance()`](Provider::advance).
///
/// The wallclock time can be warped with
/// [`.jump_wallclock()`](Provider::jump_wallclock),
/// allowing simulation of wall clock non-monotonicity.
///
/// # Panics and aborts
///
/// Panics on time under/overflow.
///
/// May cause an abort if the [`SimpleMockTimeProvider`] implementation contains bugs.
#[derive(Clone, Debug)]
pub struct SimpleMockTimeProvider {
    /// The actual state
    state: Arc<Mutex<State>>,
}

/// Convenience abbreviation
pub(crate) use SimpleMockTimeProvider as Provider;

/// Identifier of a [`SleepFuture`]
type Id = slotmap::DefaultKey;

/// Future for `sleep`
///
/// Iff this struct exists, there is an entry for `id` in `prov.wakers`.
/// (It might contain `None`.)
pub struct SleepFuture {
    /// Reference to our state
    prov: Provider,

    /// Which `SleepFuture` are we
    id: Id,
}

/// Mutable state for a [`Provider`]
#[derive(Debug, AsMut)]
pub struct State {
    /// Current time
    now: Instant,

    /// Current wallclock time
    wallclock: SystemTime,

    /// Wakers; record of every existing [`SleepFuture`]
    ///
    /// Entry exists iff `SleepFuture` exists.
    ///
    /// Contains `None` if we haven't polled the future;
    /// `Some` if we have.
    ///
    /// We could use a `Vec` or `TiVec`
    /// but using a slotmap is more robust against bugs here.
    wakers: DenseSlotMap<Id, Option<Waker>>,

    /// Priority queue
    ///
    /// Subset of `wakers`.
    ///
    /// An entry is present iff the `Instant` is *strictly* less than `State.now`,
    /// in which case that's when the future should be woken.
    ///
    /// `PriorityQueue` is a max-heap but we want earliest times, hence `Reverse`
    pq: PriorityQueue<Id, Reverse<Instant>>,
}

/// `Default` makes a `Provider` which starts at whatever the current real time is
impl Default for Provider {
    fn default() -> Self {
        Self::from_real()
    }
}

impl Provider {
    /// Return a new mock time provider starting at a specified point in time
    pub fn new(now: Instant, wallclock: SystemTime) -> Self {
        let state = State {
            now,
            wallclock,
            wakers: Default::default(),
            pq: Default::default(),
        };
        Provider {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Return a new mock time provider starting at the current actual (non-mock) time
    ///
    /// Like any [`SimpleMockTimeProvider`], the time is frozen and only changes
    /// due to calls to `advance`.
    pub fn from_real() -> Self {
        Provider::new(Instant::now(), SystemTime::now())
    }
    /// Return a new mock time provider starting at a specified wallclock time
    ///
    /// The monotonic time ([`Instant`]) starts at the current actual (non-mock) time.
    /// (Absolute values of the real monotonic time are not readily
    /// observable or distinguishable from Rust,
    /// nor can a fixed `Instant` be constructed,
    /// so this is usually sufficient for a reproducible test.)
    pub fn from_wallclock(wallclock: SystemTime) -> Self {
        Provider::new(Instant::now(), wallclock)
    }

    /// Advance the simulated time by `d`
    ///
    /// This advances both the `Instant` (monotonic time)
    /// and `SystemTime` (wallclock time)
    /// by the same amount.
    ///
    /// Will wake sleeping [`SleepFuture`]s, as appropriate,
    /// but does not yield to the executor.
    pub fn advance(&self, d: Duration) {
        let mut state = self.lock();
        state.now += d;
        state.wallclock += d;
        state.wake_any();
    }

    /// Warp the wallclock time
    ///
    /// This has no effect on any sleeping futures.
    /// It only affects the return value from [`.wallclock()`](Provider::wallclock).
    pub fn jump_wallclock(&self, new_wallclock: SystemTime) {
        let mut state = self.lock();
        state.wallclock = new_wallclock;
        // Really we ought to wake people up, here.
        // But absolutely every Rust API is wrong: none offer a way to sleep until a SystemTime.
        // (There might be some less-portable non-Rust APIs for that.)
    }

    /// When will the next timeout occur?
    ///
    /// Returns the duration until the next [`SleepFuture`] should wake up.
    ///
    /// Advancing time by at least this amount will wake up that future,
    /// and any others with the same wakeup time.
    pub fn time_until_next_timeout(&self) -> Option<Duration> {
        let state = self.lock();
        let Reverse(until) = state.pq.peek()?.1;
        let d = until.duration_since(state.now);
        Some(d)
    }

    /// Convenience function to lock the state
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("simple time state poisoned")
    }
}

impl SleepProvider for Provider {
    type SleepFuture = SleepFuture;

    fn sleep(&self, d: Duration) -> SleepFuture {
        let mut state = self.lock();
        let until = state.now + d;

        let id = state.wakers.insert(None);
        state.pq.push(id, Reverse(until));

        // Possibly, `until` isn't *strictly* greater than `state.now`, since d might be 0.
        // If so, .wake_any() will restore the invariant by immediately waking.
        state.wake_any();

        SleepFuture {
            id,
            prov: self.clone(),
        }
    }

    fn now(&self) -> Instant {
        self.lock().now
    }
    fn wallclock(&self) -> SystemTime {
        self.lock().wallclock
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.prov.lock();
        if let Some((_, Reverse(scheduled))) = state.pq.get(&self.id) {
            // Presence of this entry implies scheduled > now
            assert!(*scheduled > state.now);
            let waker = Some(cx.waker().clone());
            *state.wakers.get_mut(self.id).expect("polling wakers entry") = waker;
            Poll::Pending
        } else {
            // Absence implies scheduled (no longer stored) <= now
            Poll::Ready(())
        }
    }
}

impl State {
    /// Restore the invariant for `pq` after `now` has been increased
    fn wake_any(&mut self) {
        loop {
            match self.pq.peek() {
                // Keep picking off entries with scheduled <= now
                Some((_, Reverse(scheduled))) if *scheduled <= self.now => {
                    let (id, _) = self.pq.pop().expect("vanished");
                    if let Some(waker) = self.wakers.get(id).expect("stale pq entry") {
                        waker.wake_by_ref();
                    }
                }
                _ => break,
            }
        }
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        let mut state = self.prov.lock();
        let _: Option<Waker> = state.wakers.remove(self.id).expect("entry vanished");
        let _: Option<(Id, Reverse<Instant>)> = state.pq.remove(&self.id);
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::task::MockExecutor;
    use futures::poll;
    use humantime::parse_rfc3339;
    use tor_rtcompat::BlockOn as _;
    use Poll::*;

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn run_test<FUT>(f: impl FnOnce(Provider, MockExecutor) -> FUT)
    where
        FUT: Future<Output = ()>,
    {
        let sp = Provider::new(
            Instant::now(), // it would have been nice to make this fixed for the test
            parse_rfc3339("2000-01-01T00:00:00Z").unwrap(),
        );
        let exec = MockExecutor::new();
        exec.block_on(f(sp, exec.clone()));
    }

    #[test]
    fn simple() {
        run_test(|sp, _exec| async move {
            let n1 = sp.now();
            let w1 = sp.wallclock();
            let mut f1 = sp.sleep(ms(500));
            let mut f2 = sp.sleep(ms(1500));
            assert_eq!(poll!(&mut f1), Pending);
            sp.advance(ms(200));
            assert_eq!(n1 + ms(200), sp.now());
            assert_eq!(w1 + ms(200), sp.wallclock());
            assert_eq!(poll!(&mut f1), Pending);
            assert_eq!(poll!(&mut f2), Pending);
            drop(f2);
            sp.jump_wallclock(w1 + ms(10_000));
            sp.advance(ms(300));
            assert_eq!(n1 + ms(500), sp.now());
            assert_eq!(w1 + ms(10_300), sp.wallclock());
            assert_eq!(poll!(&mut f1), Ready(()));
            let mut f0 = sp.sleep(ms(0));
            assert_eq!(poll!(&mut f0), Ready(()));
        });
    }

    #[test]
    fn task() {
        run_test(|sp, exec| async move {
            let st = Arc::new(Mutex::new(0_i8));

            exec.spawn_identified("test task", {
                let st = st.clone();
                let sp = sp.clone();
                async move {
                    *st.lock().unwrap() = 1;
                    sp.sleep(ms(500)).await;
                    *st.lock().unwrap() = 2;
                    sp.sleep(ms(300)).await;
                    *st.lock().unwrap() = 3;
                }
            });

            let st = move || *st.lock().unwrap();

            assert_eq!(st(), 0);
            exec.progress_until_stalled().await;
            assert_eq!(st(), 1);
            assert_eq!(sp.time_until_next_timeout(), Some(ms(500)));

            sp.advance(ms(500));

            assert_eq!(st(), 1);
            assert_eq!(sp.time_until_next_timeout(), None);
            exec.progress_until_stalled().await;
            assert_eq!(st(), 2);
            assert_eq!(sp.time_until_next_timeout(), Some(ms(300)));

            sp.advance(ms(500));
            assert_eq!(st(), 2);
            assert_eq!(sp.time_until_next_timeout(), None);
            exec.progress_until_stalled().await;
            assert_eq!(sp.time_until_next_timeout(), None);
            assert_eq!(st(), 3);
        });
    }
}
