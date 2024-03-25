//! Functionality for simulating the passage of time in unit tests.
//!
//! We do this by providing [`MockSleepProvider`], a "SleepProvider"
//! instance that can simulate timeouts and retries without requiring
//! the actual system clock to advance.
//!
//! ### Deprecated
//!
//! This mock time facility has some limitations.
//! See [`MockSleepProvider`] for more information.
//! Use [`MockRuntime`](crate::MockRuntime) for new tests.

#![allow(clippy::missing_docs_in_private_items)]

use std::{
    cmp::{Eq, Ordering, PartialEq, PartialOrd},
    collections::BinaryHeap,
    fmt,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

use futures::Future;
use tracing::trace;

use std::collections::HashSet;
use std::fmt::Formatter;
use tor_rtcompat::{CoarseInstant, CoarseTimeProvider, SleepProvider};

use crate::time_core::MockCoarseTimeProvider;

/// A dummy [`SleepProvider`] instance for testing.
///
/// The MockSleepProvider ignores the current time, and instead keeps
/// its own view of the current `Instant` and `SystemTime`.  You
/// can advance them in-step by calling `advance()`, and you can simulate
/// jumps in the system clock by calling `jump()`.
///
/// This is *not* for production use.
///
/// ### Deprecated
///
/// This mock time facility has some limitations, notably lack of support for tasks,
/// and a confusing API for controlling the mock time.
///
/// New test cases should probably use `MockRuntime`
/// which incorporates `MockSimpletimeProvider`.
///
/// Comparison of `MockSleepProvider` with `SimpleMockTimeProvider`:
///
///  * `SimpleMockTimeProvider` does not support, or expect the use of,
///    `block_advance` et al.
///    Instead, the advancement of simulated time is typically done automatically
///    in cooperation with the executor,
///    using `MockRuntime`'s `advance_*` methods.
///
///  * Consequently, `SimpleMockTimeProvider` can be used in test cases that
///    spawn tasks and perform sleeps in them.
///
///  * And, consequently, `SimpleMockTimeProvider` does not need non-test code to
///    contain calls which are solely related to getting the time mocking to work right.
///
///  * `SimpleMockTimeProvider` gives correct sleeping locations
///    with `MockExecutor`'s dump of sleeping tasks' stack traces.
///
///  * Conversely, to use `SimpleMockTimeProvider` in all but the most simple test cases,
///    coordination with the executor is required.
///    This coordination is provided by the integrated `MockRuntime`;
///    `SimpleMockTimeProvider` is of limited usefulness by itself.
//
// TODO: at some point we should add #[deprecated] to this type
// and to the block_advance etc. methods in SleepProvider.
// But right now that would involve rewriting a whole bunch of tests,
// or generous sprinklings of #[allow].
///
/// ### Examples
///
/// Suppose you've written a function that relies on making a
/// connection to the network and possibly timing out:
///
/// ```rust
/// use tor_rtcompat::{Runtime,SleepProviderExt};
/// use std::{net::SocketAddr, io::Result, time::Duration, io::Error};
/// use futures::io::AsyncWriteExt;
///
/// async fn say_hi(runtime: impl Runtime, addr: &SocketAddr) -> Result<()> {
///    let delay = Duration::new(5,0);
///    runtime.timeout(delay, async {
///       let mut conn = runtime.connect(addr).await?;
///       conn.write_all(b"Hello world!\r\n").await?;
///       conn.close().await?;
///       Ok::<_,Error>(())
///    }).await??;
///    Ok(())
/// }
/// ```
///
/// But how should you test this function?
///
/// You might try connecting to a well-known website to test the
/// connection case, and to a well-known black hole to test the
/// timeout case... but that's a bit undesirable.  Your tests might be
/// running in a container with no internet access; and even if they
/// aren't, it isn't so great for your tests to rely on the actual
/// state of the internet.  Similarly, if you make your timeout too long,
/// your tests might block for a long time; but if your timeout is too short,
/// the tests might fail on a slow machine or on a slow network.
///
/// Or, you could solve both of these problems by using `tor-rtmock`
/// to replace the internet _and_ the passage of time.  (Here we're only
/// replacing the internet.)
///
/// ```rust,no_run
/// # async fn say_hi<R,A>(runtime: R, addr: A) -> Result<(), ()> { Ok(()) }
/// # // TODO this test hangs for some reason?  Fix it and remove no_run above
/// use tor_rtmock::{MockSleepRuntime,MockNetRuntime,net::MockNetwork};
/// use tor_rtcompat::{TcpProvider,TcpListener};
/// use futures::io::AsyncReadExt;
///
/// tor_rtcompat::test_with_all_runtimes!(|rt| async move {
///
///    let addr1 = "198.51.100.7".parse().unwrap();
///    let addr2 = "198.51.100.99".parse().unwrap();
///    let sockaddr = "198.51.100.99:101".parse().unwrap();
///
///    // Make a runtime that pretends that we are at the first address...
///    let fake_internet = MockNetwork::new();
///    let rt1 = fake_internet.builder().add_address(addr1).runtime(rt.clone());
///    // ...and one that pretends we're listening at the second address.
///    let rt2 = fake_internet.builder().add_address(addr2).runtime(rt);
///    let listener = rt2.listen(&sockaddr).await.unwrap();
///
///    // Now we can test our function!
///    let (result1,output) = futures::join!(
///           say_hi(rt1, &sockaddr),
///           async {
///               let (mut conn,addr) = listener.accept().await.unwrap();
///               assert_eq!(addr.ip(), addr1);
///               let mut output = Vec::new();
///               conn.read_to_end(&mut output).await.unwrap();
///               output
///           });
///
///    assert!(result1.is_ok());
///    assert_eq!(&output[..], b"Hello world!\r\n");
/// });
/// ```
#[derive(Clone)]
pub struct MockSleepProvider {
    /// The shared backend for this MockSleepProvider and its futures.
    state: Arc<Mutex<SleepSchedule>>,
}

impl fmt::Debug for MockSleepProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockSleepProvider").finish_non_exhaustive()
    }
}

/// Shared backend for sleep provider and Sleeping futures.
struct SleepSchedule {
    /// What time do we pretend it is (monotonic)?  This value only
    /// moves forward.
    instant: Instant,
    /// Coarse time tracker
    coarse: MockCoarseTimeProvider,
    /// What time do we pretend it is (wall clock)? This value can move
    /// in any way, but usually moves in step with `instant`.
    wallclock: SystemTime,
    /// Priority queue of events, in the order that we should wake them.
    sleepers: BinaryHeap<SleepEntry>,
    /// If the mock time system is being driven by a `WaitFor`, holds a `Waker` to wake up that
    /// `WaitFor` in order for it to make more progress.
    waitfor_waker: Option<Waker>,
    /// Number of sleepers instantiated.
    sleepers_made: usize,
    /// Number of sleepers polled.
    sleepers_polled: usize,
    /// Whether an advance is needed.
    should_advance: bool,
    /// A set of reasons why advances shouldn't be allowed right now.
    blocked_advance: HashSet<String>,
    /// A time up to which advances are allowed, irrespective of them being blocked.
    allowed_advance: Duration,
}

/// An entry telling us when to wake which future up.
struct SleepEntry {
    /// The time at which this entry should wake
    when: Instant,
    /// The Waker to call when the instant has passed.
    waker: Waker,
}

/// A future returned by [`MockSleepProvider::sleep()`].
pub struct Sleeping {
    /// The instant when we should become ready.
    when: Instant,
    /// True if we have pushed this into the queue.
    inserted: bool,
    /// The schedule to queue ourselves in if we're polled before we're ready.
    provider: Weak<Mutex<SleepSchedule>>,
}

impl Default for MockSleepProvider {
    fn default() -> Self {
        let wallclock = humantime::parse_rfc3339("2023-07-05T11:25:56Z").expect("parse");
        MockSleepProvider::new(wallclock)
    }
}

impl MockSleepProvider {
    /// Create a new MockSleepProvider, starting at a given wall-clock time.
    pub fn new(wallclock: SystemTime) -> Self {
        let instant = Instant::now();
        let sleepers = BinaryHeap::new();
        let state = SleepSchedule {
            instant,
            coarse: MockCoarseTimeProvider::new(),
            wallclock,
            sleepers,
            waitfor_waker: None,
            sleepers_made: 0,
            sleepers_polled: 0,
            should_advance: false,
            blocked_advance: HashSet::new(),
            allowed_advance: Duration::from_nanos(0),
        };
        MockSleepProvider {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Advance the simulated timeline forward by `dur`.
    ///
    /// Calling this function will wake any pending futures as
    /// appropriate, and yield to the scheduler so they get a chance
    /// to run.
    ///
    /// # Limitations
    ///
    /// This function advances time in one big step.  We might instead
    /// want to advance in small steps and make sure that each step's
    /// futures can get run before the ones scheduled to run after it.
    pub async fn advance(&self, dur: Duration) {
        self.advance_noyield(dur);
        tor_rtcompat::task::yield_now().await;
    }

    /// Advance the simulated timeline forward by `dur`.
    ///
    /// Calling this function will wake any pending futures as
    /// appropriate, but not yield to the scheduler.  Mostly you
    /// should call [`advance`](Self::advance) instead.
    pub(crate) fn advance_noyield(&self, dur: Duration) {
        // It's not so great to unwrap here in general, but since this is
        // only testing code we don't really care.
        let mut state = self.state.lock().expect("Poisoned lock for state");
        state.wallclock += dur;
        state.instant += dur;
        state.coarse.advance(dur);
        state.fire();
    }

    /// Simulate a discontinuity in the system clock, by jumping to
    /// `new_wallclock`.
    ///
    /// # Panics
    ///
    /// Panics if we have already panicked while holding the lock on
    /// the internal timer state, and the lock is poisoned.
    pub fn jump_to(&self, new_wallclock: SystemTime) {
        let mut state = self.state.lock().expect("Poisoned lock for state");
        state.wallclock = new_wallclock;
    }

    /// Return the amount of virtual time until the next timeout
    /// should elapse.
    ///
    /// If there are no more timeouts, return None.  If the next
    /// timeout should elapse right now, return Some(0).
    pub(crate) fn time_until_next_timeout(&self) -> Option<Duration> {
        let state = self.state.lock().expect("Poisoned lock for state");
        let now = state.instant;
        state
            .sleepers
            .peek()
            .map(|sleepent| sleepent.when.saturating_duration_since(now))
    }

    /// Return true if a `WaitFor` driving this sleep provider should advance time in order for
    /// futures blocked on sleeping to make progress.
    ///
    /// NOTE: This function has side-effects; if it returns true, the caller is expected to do an
    /// advance before calling it again.
    #[allow(clippy::cognitive_complexity)]
    pub(crate) fn should_advance(&mut self) -> bool {
        let mut state = self.state.lock().expect("Poisoned lock for state");
        if !state.blocked_advance.is_empty() && state.allowed_advance == Duration::from_nanos(0) {
            // We've had advances blocked, and don't have any quota for doing allowances while
            // blocked left.
            trace!(
                "should_advance = false: blocked by {:?}",
                state.blocked_advance
            );
            return false;
        }
        if !state.should_advance {
            // The advance flag wasn't set.
            trace!("should_advance = false; bit not previously set");
            return false;
        }
        // Clear the advance flag; we'll either return true and cause an advance to happen,
        // or the reasons to return false below also imply that the advance flag will be set again
        // later on.
        state.should_advance = false;
        if state.sleepers_polled < state.sleepers_made {
            // Something did set the advance flag before, but it's not valid any more now because
            // more unpolled sleepers were created.
            trace!("should_advance = false; advancing no longer valid");
            return false;
        }
        if !state.blocked_advance.is_empty() && state.allowed_advance > Duration::from_nanos(0) {
            // If we're here, we would've returned earlier due to having advances blocked, but
            // we have quota to advance up to a certain time while advances are blocked.
            // Let's see when the next timeout is, and whether it falls within that quota.
            let next_timeout = {
                let now = state.instant;
                state
                    .sleepers
                    .peek()
                    .map(|sleepent| sleepent.when.saturating_duration_since(now))
            };
            let next_timeout = match next_timeout {
                Some(x) => x,
                None => {
                    // There's no timeout set, so we really shouldn't be here anyway.
                    trace!("should_advance = false; allow_one set but no timeout yet");
                    return false;
                }
            };
            if next_timeout <= state.allowed_advance {
                // We can advance up to the next timeout, since it's in our quota.
                // Subtract the amount we're going to advance by from said quota.
                state.allowed_advance -= next_timeout;
                trace!(
                    "WARNING: allowing advance due to allow_one; new allowed is {:?}",
                    state.allowed_advance
                );
            } else {
                // The next timeout is too far in the future.
                trace!(
                    "should_advance = false; allow_one set but only up to {:?}, next is {:?}",
                    state.allowed_advance,
                    next_timeout
                );
                return false;
            }
        }
        true
    }

    /// Register a `Waker` to be woken up when an advance in time is required to make progress.
    ///
    /// This is used by `WaitFor`.
    pub(crate) fn register_waitfor_waker(&mut self, waker: Waker) {
        let mut state = self.state.lock().expect("Poisoned lock for state");
        state.waitfor_waker = Some(waker);
    }

    /// Remove a previously registered `Waker` registered with `register_waitfor_waker()`.
    pub(crate) fn clear_waitfor_waker(&mut self) {
        let mut state = self.state.lock().expect("Poisoned lock for state");
        state.waitfor_waker = None;
    }

    /// Returns true if a `Waker` has been registered with `register_waitfor_waker()`.
    ///
    /// This is used to ensure that you don't have two concurrent `WaitFor`s running.
    pub(crate) fn has_waitfor_waker(&self) -> bool {
        let state = self.state.lock().expect("Poisoned lock for state");
        state.waitfor_waker.is_some()
    }
}

impl SleepSchedule {
    /// Wake any pending events that are ready according to the
    /// current simulated time.
    fn fire(&mut self) {
        use std::collections::binary_heap::PeekMut;

        let now = self.instant;
        while let Some(top) = self.sleepers.peek_mut() {
            if now < top.when {
                return;
            }

            PeekMut::pop(top).waker.wake();
        }
    }

    /// Add a new SleepEntry to this schedule.
    fn push(&mut self, ent: SleepEntry) {
        self.sleepers.push(ent);
    }

    /// If all sleepers made have been polled, set the advance flag and wake up any `WaitFor` that
    /// might be waiting.
    fn maybe_advance(&mut self) {
        if self.sleepers_polled >= self.sleepers_made {
            if let Some(ref waker) = self.waitfor_waker {
                trace!("setting advance flag");
                self.should_advance = true;
                waker.wake_by_ref();
            } else {
                trace!("would advance, but no waker");
            }
        }
    }

    /// Register a sleeper as having been polled, and advance if necessary.
    fn increment_poll_count(&mut self) {
        self.sleepers_polled += 1;
        trace!(
            "sleeper polled, {}/{}",
            self.sleepers_polled,
            self.sleepers_made
        );
        self.maybe_advance();
    }
}

impl SleepProvider for MockSleepProvider {
    type SleepFuture = Sleeping;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        let mut provider = self.state.lock().expect("Poisoned lock for state");
        let when = provider.instant + duration;
        // We're making a new sleeper, so register this in the state.
        provider.sleepers_made += 1;
        trace!(
            "sleeper made for {:?}, {}/{}",
            duration,
            provider.sleepers_polled,
            provider.sleepers_made
        );

        Sleeping {
            when,
            inserted: false,
            provider: Arc::downgrade(&self.state),
        }
    }

    fn block_advance<T: Into<String>>(&self, reason: T) {
        let mut provider = self.state.lock().expect("Poisoned lock for state");
        let reason = reason.into();
        trace!("advancing blocked: {}", reason);
        provider.blocked_advance.insert(reason);
    }

    fn release_advance<T: Into<String>>(&self, reason: T) {
        let mut provider = self.state.lock().expect("Poisoned lock for state");
        let reason = reason.into();
        trace!("advancing released: {}", reason);
        provider.blocked_advance.remove(&reason);
        if provider.blocked_advance.is_empty() {
            provider.maybe_advance();
        }
    }

    fn allow_one_advance(&self, dur: Duration) {
        let mut provider = self.state.lock().expect("Poisoned lock for state");
        provider.allowed_advance = Duration::max(provider.allowed_advance, dur);
        trace!(
            "** allow_one_advance fired; may advance up to {:?} **",
            provider.allowed_advance
        );
        provider.maybe_advance();
    }

    fn now(&self) -> Instant {
        self.state.lock().expect("Poisoned lock for state").instant
    }

    fn wallclock(&self) -> SystemTime {
        self.state
            .lock()
            .expect("Poisoned lock for state")
            .wallclock
    }
}

impl CoarseTimeProvider for MockSleepProvider {
    fn now_coarse(&self) -> CoarseInstant {
        self.state.lock().expect("poisoned").coarse.now_coarse()
    }
}

impl PartialEq for SleepEntry {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when
    }
}
impl Eq for SleepEntry {}
impl PartialOrd for SleepEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SleepEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.when.cmp(&other.when).reverse()
    }
}

impl Drop for Sleeping {
    fn drop(&mut self) {
        if let Some(provider) = Weak::upgrade(&self.provider) {
            let mut provider = provider.lock().expect("Poisoned lock for provider");
            if !self.inserted {
                // A sleeper being dropped will never be polled, so there's no point waiting;
                // act as if it's been polled in order to avoid waiting forever.
                trace!("sleeper dropped, incrementing count");
                provider.increment_poll_count();
                self.inserted = true;
            }
        }
    }
}

impl Future for Sleeping {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(provider) = Weak::upgrade(&self.provider) {
            let mut provider = provider.lock().expect("Poisoned lock for provider");
            let now = provider.instant;

            if now >= self.when {
                // The sleep time's elapsed.
                if !self.inserted {
                    // If we never registered this sleeper as being polled, do so now.
                    provider.increment_poll_count();
                    self.inserted = true;
                }
                if !provider.should_advance {
                    // The first advance during a `WaitFor` gets triggered by all sleepers that
                    // have been created being polled.
                    // However, this only happens once.
                    // What we do to get around this is have sleepers that return Ready kick off
                    // another advance, in order to wake the next waiting sleeper.
                    provider.maybe_advance();
                }
                return Poll::Ready(());
            }
            // dbg!("sleep check with", self.when-now);

            if !self.inserted {
                let entry = SleepEntry {
                    when: self.when,
                    waker: cx.waker().clone(),
                };

                provider.push(entry);
                self.inserted = true;
                // Register this sleeper as having been polled.
                provider.increment_poll_count();
            }
            // dbg!(provider.sleepers.len());
        }
        Poll::Pending
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
    use tor_rtcompat::test_with_all_runtimes;

    #[test]
    fn basics_of_time_travel() {
        let w1 = SystemTime::now();
        let sp = MockSleepProvider::new(w1);
        let i1 = sp.now();
        assert_eq!(sp.wallclock(), w1);

        let interval = Duration::new(4 * 3600 + 13 * 60, 0);
        sp.advance_noyield(interval);
        assert_eq!(sp.now(), i1 + interval);
        assert_eq!(sp.wallclock(), w1 + interval);

        sp.jump_to(w1 + interval * 3);
        assert_eq!(sp.now(), i1 + interval);
        assert_eq!(sp.wallclock(), w1 + interval * 3);
    }

    #[test]
    fn time_moves_on() {
        test_with_all_runtimes!(|_| async {
            use std::sync::atomic::AtomicBool;
            use std::sync::atomic::Ordering;
            use tor_async_utils::oneshot;

            let sp = MockSleepProvider::new(SystemTime::now());
            let one_hour = Duration::new(3600, 0);

            let (s1, r1) = oneshot::channel();
            let (s2, r2) = oneshot::channel();
            let (s3, r3) = oneshot::channel();

            let b1 = AtomicBool::new(false);
            let b2 = AtomicBool::new(false);
            let b3 = AtomicBool::new(false);

            let real_start = Instant::now();

            futures::join!(
                async {
                    sp.sleep(one_hour).await;
                    b1.store(true, Ordering::SeqCst);
                    s1.send(()).unwrap();
                },
                async {
                    sp.sleep(one_hour * 3).await;
                    b2.store(true, Ordering::SeqCst);
                    s2.send(()).unwrap();
                },
                async {
                    sp.sleep(one_hour * 5).await;
                    b3.store(true, Ordering::SeqCst);
                    s3.send(()).unwrap();
                },
                async {
                    sp.advance(one_hour * 2).await;
                    r1.await.unwrap();
                    assert!(b1.load(Ordering::SeqCst));
                    assert!(!b2.load(Ordering::SeqCst));
                    assert!(!b3.load(Ordering::SeqCst));

                    sp.advance(one_hour * 2).await;
                    r2.await.unwrap();
                    assert!(b1.load(Ordering::SeqCst));
                    assert!(b2.load(Ordering::SeqCst));
                    assert!(!b3.load(Ordering::SeqCst));

                    sp.advance(one_hour * 2).await;
                    r3.await.unwrap();
                    assert!(b1.load(Ordering::SeqCst));
                    assert!(b2.load(Ordering::SeqCst));
                    assert!(b3.load(Ordering::SeqCst));
                    let real_end = Instant::now();

                    assert!(real_end - real_start < one_hour);
                }
            );
            std::io::Result::Ok(())
        });
    }
}
