//! Completely mock runtime

use amplify::Getters;
use futures::FutureExt as _;
use strum::IntoEnumIterator as _;
use void::{ResultVoidExt as _, Void};

use crate::util::impl_runtime_prelude::*;

use crate::net::MockNetProvider;
use crate::task::{MockExecutor, SchedulingPolicy};
use crate::time::MockSleepProvider;

/// Completely mock runtime
///
/// Suitable for test cases that wish to completely control
/// the environment experienced by the code under test.
///
/// ### Restrictions
///
/// The test case must advance the mock time explicitly as desired.
/// There is not currently any facility for automatically
/// making progress by advancing the mock time by the right amounts
/// for the timeouts set by the futures under test.
// ^ I think such a facility could be provided.  `MockSleepProvider` would have to
//   provide a method to identify the next interesting time event.
//   The waitfor machinery in MockSleepProvider and MockSleepRuntime doesn't seem suitable.
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
///  * Direct access to the real-world clock (`SystemTime::now`, `Instant::now`).
///    Including `coarsetime`, which is not mocked.
///    Exception: CPU use measurements.
///
///  * Anything that spawns threads and then communicates with those threads
///    using async Rust facilities (futures).
///
///  * Async sockets, or async use of other kernel-based IPC or network mechanisms.
///
///  * Anything provided by a Rust runtime/executor project (eg anything from Tokio),
///    unless it is definitively established that it's runtime-agnostic.
#[derive(Debug, Default, Clone, Getters)]
#[getter(prefix = "mock_")]
pub struct MockRuntime {
    /// Tasks
    task: MockExecutor,
    /// Time provider
    sleep: MockSleepProvider,
    /// Net provider
    net: MockNetProvider,
}

/// Builder for a manually-configured `MockRuntime`
#[derive(Debug, Default, Clone)]
pub struct MockRuntimeBuilder {
    /// scheduling policy
    scheduling: SchedulingPolicy,
    /// starting wall clock time
    starting_wallclock: Option<SystemTime>,
}

impl_runtime! {
    [ ] MockRuntime,
    task: task,
    sleep: sleep: MockSleepProvider,
    net: net: MockNetProvider,
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
    pub fn try_test_with_various<TC, FUT, E>(mut test_case: TC) -> Result<(), E>
    where
        TC: FnMut(MockRuntime) -> FUT,
        FUT: Future<Output = Result<(), E>>,
    {
        for scheduling in SchedulingPolicy::iter() {
            let runtime = MockRuntime::builder().scheduling(scheduling).build();
            runtime.block_on(test_case(runtime.clone()))?;
        }
        Ok(())
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
    /// [`advance()`](MockRuntime::advance)
    /// or
    /// [`jump_to()`](MockRuntime::jump_to)
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

    /// See [`MockSleepProvider::advance()`]
    pub async fn advance(&self, dur: Duration) {
        self.sleep.advance(dur).await;
    }
    /// See [`MockSleepProvider::jump_to()`]
    pub fn jump_to(&self, new_wallclock: SystemTime) {
        self.sleep.jump_to(new_wallclock);
    }
}

impl MockRuntimeBuilder {
    /// Set the scheduling policy
    pub fn scheduling(mut self, scheduling: SchedulingPolicy) -> Self {
        self.scheduling = scheduling;
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
            starting_wallclock,
        } = self;

        let sleep = if let Some(starting_wallclock) = starting_wallclock {
            MockSleepProvider::new(starting_wallclock)
        } else {
            MockSleepProvider::default()
        };

        let task = MockExecutor::with_scheduling(scheduling);

        MockRuntime {
            sleep,
            task,
            ..Default::default()
        }
    }
}
