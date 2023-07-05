//! Completely mock runtime

use amplify::Getters;
use strum::IntoEnumIterator as _;

use crate::util::impl_runtime_prelude::*;

use crate::net::MockNetProvider;
use crate::task::{MockExecutor, SchedulingPolicy};
use crate::time::MockSleepProvider;

/// Completely mock runtime
///
/// Suitable for test cases that wish to completely control
/// the environment experienced by the code under test.
///
/// # Restrictions
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
/// Use of inter-future communication facilities from `futures`
/// or other runtime-agnostic crates is permitted.
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
    spawn: task,
    block: task,
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
