//! Completely mock runtime

use std::fmt::{Debug, Display};
use std::ops::ControlFlow;

use amplify::Getters;
use futures::FutureExt as _;
use itertools::chain;
use strum::IntoEnumIterator as _;
use void::{ResultVoidExt as _, Void};

use crate::util::impl_runtime_prelude::*;

use crate::net::MockNetProvider;
use crate::simple_time::SimpleMockTimeProvider;
use crate::task::{MockExecutor, SchedulingPolicy};

/// Completely mock runtime
///
/// Suitable for test cases that wish to completely control
/// the environment experienced by the code under test.
///
/// ### Restrictions
///
/// The test case must advance the mock time explicitly as desired,
/// typically by calling one of the `MockRuntime::advance_*` methods.
///
/// Tests that use this runtime *must not* interact with the outside world;
/// everything must go through this runtime (and its pieces).
///
/// #### Allowed
///
///  * Inter-future communication facilities from `futures`
///    or other runtime-agnostic crates.
///
///  * Fast synchronous operations that will complete "immediately" or "quickly".
///    E.g.: filesystem calls.
///
///  * `std::sync::Mutex` (assuming the use is deadlock-free in a single-threaded
///    executor, as it should be in all of Arti).
///
///  * Slower operations that are run synchronously (without futures `await`)
///    provided their completion doesn't depend on any of the futures we're running.
///    (These kind of operations are often discouraged in async contexts,
///    because they block the async runtime or its worker threads.
///    But they are often OK in tests.)
///
///  * All facilities provided by this `MockExecutor` and its trait impls.
///
/// #### Not allowed
///
///  * Direct access to the real-world clock (`SystemTime::now`, `Instant::now`),
///    including direct use of `coarsetime`.
///    Instead, use [`SleepProvider`] and [`CoarseTimeProvider`] methods on the runtime.
///    Exception: CPU use measurements.
///
///  * Anything that spawns threads and then communicates with those threads
///    using async Rust facilities (futures).
///
///  * Async sockets, or async use of other kernel-based IPC or network mechanisms.
///
///  * Anything provided by a Rust runtime/executor project (eg anything from Tokio),
///    unless it is definitively established that it's runtime-agnostic.
#[derive(Debug, Default, Clone, Getters, Deftly)]
#[derive_deftly(SomeMockRuntime)]
#[getter(prefix = "mock_")]
pub struct MockRuntime {
    /// Tasks
    #[deftly(mock(task))]
    task: MockExecutor,
    /// Time provider
    #[deftly(mock(sleep))]
    sleep: SimpleMockTimeProvider,
    /// Net provider
    #[deftly(mock(net))]
    net: MockNetProvider,
}

/// Builder for a manually-configured `MockRuntime`
#[derive(Debug, Default, Clone)]
pub struct MockRuntimeBuilder {
    /// scheduling policy
    scheduling: SchedulingPolicy,
    /// sleep provider
    sleep: Option<SimpleMockTimeProvider>,
    /// starting wall clock time
    starting_wallclock: Option<SystemTime>,
}

impl MockRuntime {
    /// Create a new `MockRuntime` with default parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a builder, for creating a `MockRuntime` with some parameters manually configured
    pub fn builder() -> MockRuntimeBuilder {
        Default::default()
    }

    /// Run a test case with a variety of runtime parameters, to try to find bugs
    ///
    /// `test_case` is an async closure which receives a `MockRuntime`.
    /// It will be run with a number of differently configured executors.
    ///
    /// Each run will be preceded by an [`eprintln!`] showing the runtime configuration.
    ///
    /// ### Variations
    ///
    /// The only variation currently implemented is this:
    ///
    /// Both FIFO and LIFO scheduling policies are tested,
    /// in the hope that this will help discover ordering-dependent bugs.
    pub fn test_with_various<TC, FUT>(mut test_case: TC)
    where
        TC: FnMut(MockRuntime) -> FUT,
        FUT: Future<Output = ()>,
    {
        Self::try_test_with_various(|runtime| test_case(runtime).map(|()| Ok::<_, Void>(())))
            .void_unwrap();
    }

    /// Run a faillible test case with a variety of runtime parameters, to try to find bugs
    ///
    /// `test_case` is an async closure which receives a `MockRuntime`.
    /// It will be run with a number of differently configured executors.
    ///
    /// This function accepts a fallible closure,
    /// and returns the first `Err` to the caller.
    ///
    /// See [`test_with_various()`](MockRuntime::test_with_various) for more details.
    #[allow(clippy::print_stderr)]
    pub fn try_test_with_various<TC, FUT, E>(mut test_case: TC) -> Result<(), E>
    where
        TC: FnMut(MockRuntime) -> FUT,
        FUT: Future<Output = Result<(), E>>,
    {
        for scheduling in SchedulingPolicy::iter() {
            let config = MockRuntime::builder().scheduling(scheduling);
            eprintln!("running test with MockRuntime configuration {config:?}");
            let runtime = config.build();
            runtime.block_on(test_case(runtime.clone()))?;
        }
        Ok(())
    }

    /// Spawn a task and return something to identify it
    ///
    /// See [`MockExecutor::spawn_identified()`]
    pub fn spawn_identified(
        &self,
        desc: impl Display,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> impl Debug + Clone + Send + 'static {
        self.task.spawn_identified(desc, fut)
    }

    /// Spawn a task and return its output for further usage
    ///
    /// See [`MockExecutor::spawn_join()`]
    pub fn spawn_join<T: Debug + Send + 'static>(
        &self,
        desc: impl Display,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = T> {
        self.task.spawn_join(desc, fut)
    }

    /// Run tasks and advance time, until every task except this one is waiting
    ///
    /// On return the other tasks won't be waiting on timeouts,
    /// since time will be advanced as needed.
    ///
    /// Therefore the other tasks (if any) will be waiting for something
    /// that won't happen by itself,
    /// such as a provocation via their APIs from this task.
    ///
    /// # Panics
    ///
    /// See [`progress_until_stalled`](MockRuntime::progress_until_stalled)
    pub async fn advance_until_stalled(&self) {
        self.advance_inner(|| {
            let Some(timeout) = self.time_until_next_timeout() else {
                // Nothing is waiting on timeouts
                return ControlFlow::Break(());
            };
            assert_ne!(timeout, Duration::ZERO);
            ControlFlow::Continue(timeout)
        })
        .await;
    }

    /// Run tasks in the current executor until every task except this one is waiting
    ///
    /// Calls [`MockExecutor::progress_until_stalled()`].
    ///
    /// # Restriction - no automatic time advance
    ///
    /// The mocked time will *not* be automatically advanced.
    ///
    /// Usually
    /// (and especially if the tasks under test are waiting for timeouts or periodic events)
    /// you must use
    /// [`advance_by()`](MockRuntime::advance_by)
    /// or
    /// [`advance_until()`](MockRuntime::advance_until)
    /// to ensure the simulated time progresses as required.
    ///
    /// # Panics
    ///
    /// Might malfunction or panic if more than one such call is running at once.
    ///
    /// (Ie, you must `.await` or drop the returned `Future`
    /// before calling this method again.)
    ///
    /// Must be called and awaited within a future being run by `self`.
    pub async fn progress_until_stalled(&self) {
        self.task.progress_until_stalled().await;
    }

    /// Run tasks and advance time up to at most `limit`
    ///
    /// Will return when all other tasks are either:
    ///  * Waiting on a timeout that will fire strictly after `limit`,
    ///    (return value is the time until the earliest such)
    ///  * Waiting for something else that won't happen by itself.
    ///    (return value is `None`)
    ///
    /// Like [`advance_until_stalled`](MockRuntime::advance_until_stalled)
    /// but stops when the mock time reaches `limit`.
    ///
    /// # Panics
    ///
    /// Panics if the time somehow advances beyond `limit`.
    /// (This function won't do that, but maybe it was beyond `limit` on entry,
    /// or another task advanced the clock.)
    ///
    /// And, see [`progress_until_stalled`](MockRuntime::progress_until_stalled)
    pub async fn advance_until(&self, limit: Instant) -> Option<Duration> {
        self.advance_inner(|| {
            let timeout = self.time_until_next_timeout();

            let limit = limit
                .checked_duration_since(self.now())
                .expect("MockRuntime::advance_until: time advanced beyond `limit`!");

            if limit == Duration::ZERO {
                // Time has reached `limit`
                return ControlFlow::Break(timeout);
            }

            let advance = chain!(timeout, [limit]).min().expect("empty!");
            assert_ne!(advance, Duration::ZERO);

            ControlFlow::Continue(advance)
        })
        .await
    }

    /// Advance time, firing events and other tasks - internal implementation
    ///
    /// Common code for `advance_*`.
    ///
    /// `body` will called after `progress_until_stalled`.
    /// It should examine the simulated time, and the next timeout,
    /// and decide what to do - returning
    /// `Break` to break the loop, or
    /// `Continue` giving the `Duration` by which to advance time and go round again.
    #[allow(clippy::print_stderr)]
    async fn advance_inner<B>(&self, mut body: impl FnMut() -> ControlFlow<B, Duration>) -> B {
        /// Warn when we loop more than this many times per call
        const WARN_AT: u32 = 1000;
        let mut counter = Some(WARN_AT);

        loop {
            self.task.progress_until_stalled().await;

            match body() {
                ControlFlow::Break(v) => break v,
                ControlFlow::Continue(advance) => {
                    counter = match counter.map(|v| v.checked_sub(1)) {
                        None => None,
                        Some(Some(v)) => Some(v),
                        Some(None) => {
                            eprintln!(
 "warning: MockRuntime advance_* looped >{WARN_AT} (next sleep: {}ms)\n{:?}",
                                advance.as_millis(),
                                self.mock_task().as_debug_dump(),
                            );
                            None
                        }
                    };

                    self.sleep.advance(advance);
                }
            }
        }
    }

    /// Advances time by `dur`, firing time events and other tasks in order
    ///
    /// Prefer this to [`SimpleMockTimeProvider::advance()`];
    /// it works more faithfully.
    ///
    /// Specifically, it advances time in successive stages,
    /// so that timeouts occur sequentially, in the right order.
    ///
    /// # Panics
    ///
    /// Can panic if the mock time is advanced by other tasks.
    ///
    /// And, see [`progress_until_stalled`](MockRuntime::progress_until_stalled)
    pub async fn advance_by(&self, dur: Duration) -> Option<Duration> {
        let limit = self
            .now()
            .checked_add(dur)
            .expect("MockRuntime::advance: time overflow");

        self.advance_until(limit).await
    }

    /// See [`SimpleMockTimeProvider::jump_wallclock()`]
    pub fn jump_wallclock(&self, new_wallclock: SystemTime) {
        self.sleep.jump_wallclock(new_wallclock);
    }

    /// Return the amount of virtual time until the next timeout
    /// should elapse.
    ///
    /// If there are no more timeouts, return None.
    ///
    /// If the next
    /// timeout should elapse right now, return Some(0).
    /// However, if other tasks are proceeding,
    /// typically in that situation those other tasks will wake,
    /// so a `Some(0)` return won't be visible.
    /// In test cases, detect immediate timeouts by detecting
    /// what your task does after the timeout occurs.
    ///
    /// Likewise whether this function returns `None` or `Some(...)`
    /// can depend on whether tasks have actually yet polled various futures.
    /// The answer should be correct after
    /// [`progress_until_stalled`](Self::progress_until_stalled).
    pub fn time_until_next_timeout(&self) -> Option<Duration> {
        self.sleep.time_until_next_timeout()
    }
}

impl MockRuntimeBuilder {
    /// Set the scheduling policy
    pub fn scheduling(mut self, scheduling: SchedulingPolicy) -> Self {
        self.scheduling = scheduling;
        self
    }

    /// Provide a non-`Default` [`SimpleMockTimeProvider`]
    pub fn sleep_provider(mut self, sleep: SimpleMockTimeProvider) -> Self {
        self.sleep = Some(sleep);
        self
    }

    /// Set the starting wall clock time
    pub fn starting_wallclock(mut self, starting_wallclock: SystemTime) -> Self {
        self.starting_wallclock = Some(starting_wallclock);
        self
    }

    /// Build the runtime
    pub fn build(self) -> MockRuntime {
        let MockRuntimeBuilder {
            scheduling,
            sleep,
            starting_wallclock,
        } = self;

        let sleep = sleep.unwrap_or_default();
        if let Some(starting_wallclock) = starting_wallclock {
            sleep.jump_wallclock(starting_wallclock);
        };

        let task = MockExecutor::with_scheduling(scheduling);

        MockRuntime {
            sleep,
            task,
            ..Default::default()
        }
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
    use futures::channel::mpsc;
    use futures::{SinkExt as _, StreamExt as _};
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;
    use tracing::trace;
    use tracing_test::traced_test;

    //---------- helper alias ----------

    fn ms(i: u64) -> Duration {
        Duration::from_millis(i)
    }

    //---------- set up some test tasks ----------

    struct TestTasks {
        runtime: MockRuntime,
        start: Instant,
        tx: mpsc::Sender<()>,
        signals: Vec<Arc<AtomicBool>>,
    }
    impl TestTasks {
        fn spawn(runtime: &MockRuntime) -> TestTasks {
            let start = runtime.now();
            let mut signals = vec![];

            let mut new_signal = || {
                let signal = Arc::new(AtomicBool::new(false));
                signals.push(signal.clone());
                signal
            };

            let (tx, mut rx) = mpsc::channel(0);
            runtime.spawn_identified("rx", {
                let signal = new_signal();
                async move {
                    trace!("task rx starting...");
                    let _: Option<()> = rx.next().await;
                    signal.store(true, SeqCst);
                    trace!("task rx finished.");
                }
            });

            for i in 1..=3 {
                let signal = new_signal();
                runtime.spawn_identified(i, {
                    let runtime = runtime.clone();
                    async move {
                        trace!("task {i} starting...");
                        runtime.sleep(ms(i * 1000)).await;
                        signal.store(true, SeqCst);
                        trace!("task {i} finished.");
                    }
                });
            }
            let runtime = runtime.clone();

            TestTasks {
                runtime,
                start,
                tx,
                signals,
            }
        }

        fn signals_list(&self) -> String {
            self.signals
                .iter()
                .map(|s| if s.load(SeqCst) { 't' } else { 'f' })
                .collect()
        }
    }

    //---------- test advance_until_stalled ----------

    impl TestTasks {
        async fn advance_until_stalled(&self, exp_offset_from_start: Duration, exp_signals: &str) {
            self.runtime.advance_until_stalled().await;
            assert_eq!(self.runtime.now() - self.start, exp_offset_from_start);
            assert_eq!(self.signals_list(), exp_signals);
        }
    }

    #[traced_test]
    #[test]
    fn advance_until_stalled() {
        MockRuntime::test_with_various(|runtime| async move {
            let mut tt = TestTasks::spawn(&runtime);

            tt.advance_until_stalled(ms(3000), "fttt").await;
            tt.tx.send(()).await.unwrap();
            tt.advance_until_stalled(ms(3000), "tttt").await;
        });
    }

    //---------- test advance_until ----------

    impl TestTasks {
        async fn advance_until(
            &self,
            offset_from_start: Duration,
            exp_signals: &str,
            exp_got: Option<Duration>,
        ) {
            let limit = self.start + offset_from_start;
            eprintln!("===> advance_until {}ms", offset_from_start.as_millis());
            let got = self.runtime.advance_until(limit).await;
            assert_eq!(self.runtime.now() - self.start, offset_from_start);
            assert_eq!(self.signals_list(), exp_signals);
            assert_eq!(got, exp_got);
        }
    }

    #[traced_test]
    #[test]
    fn advance_until() {
        MockRuntime::test_with_various(|runtime| async move {
            let mut tt = TestTasks::spawn(&runtime);

            tt.advance_until(ms(1100), "ftff", Some(ms(900))).await;
            tt.advance_until(ms(2000), "fttf", Some(ms(1000))).await;
            tt.tx.send(()).await.unwrap();
            tt.advance_until(ms(2000), "tttf", Some(ms(1000))).await;
            tt.advance_until(ms(3300), "tttt", None).await;
        });
    }

    //---------- test advance_by ----------

    impl TestTasks {
        async fn advance_by(
            &self,
            advance: Duration,
            exp_offset_from_start: Duration,
            exp_signals: &str,
            exp_got: Option<Duration>,
        ) {
            eprintln!("===> advance {}ms", advance.as_millis());
            let got = self.runtime.advance_by(advance).await;
            assert_eq!(self.runtime.now() - self.start, exp_offset_from_start);
            assert_eq!(self.signals_list(), exp_signals);
            assert_eq!(got, exp_got);
        }
    }

    #[traced_test]
    #[test]
    fn advance_by() {
        MockRuntime::test_with_various(|runtime| async move {
            let mut tt = TestTasks::spawn(&runtime);

            tt.advance_by(ms(1100), ms(1100), "ftff", Some(ms(900)))
                .await;
            tt.advance_by(ms(900), ms(2000), "fttf", Some(ms(1000)))
                .await;
            tt.tx.send(()).await.unwrap();
            tt.advance_by(ms(1300), ms(3300), "tttt", None).await;
        });
    }
}
