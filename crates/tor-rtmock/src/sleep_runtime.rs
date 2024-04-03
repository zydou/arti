//! Declare MockSleepRuntime.

use pin_project::pin_project;
use tracing::trace;

use crate::time::MockSleepProvider;

use crate::util::impl_runtime_prelude::*;

/// A deprecated wrapper Runtime that overrides SleepProvider for the
/// underlying runtime.
///
/// ### Deprecated
///
/// The [`MockSleepProvider`] used here has some limitations.
/// See its documentation for more information.
/// Use [`MockRuntime`](crate::MockRuntime) for new tests.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(SomeMockRuntime)]
pub struct MockSleepRuntime<R: Runtime> {
    /// The underlying runtime. Most calls get delegated here.
    #[deftly(mock(task, net))]
    runtime: R,
    /// A MockSleepProvider.  Time-related calls get delegated here.
    #[deftly(mock(sleep))]
    sleep: MockSleepProvider,
}

impl<R: Runtime> MockSleepRuntime<R> {
    /// Create a new runtime that wraps `runtime`, but overrides
    /// its view of time with a [`MockSleepProvider`].
    pub fn new(runtime: R) -> Self {
        let sleep = MockSleepProvider::new(SystemTime::now());
        MockSleepRuntime { runtime, sleep }
    }

    /// Return a reference to the underlying runtime.
    pub fn inner(&self) -> &R {
        &self.runtime
    }

    /// Return a reference to the [`MockSleepProvider`]
    pub fn mock_sleep(&self) -> &MockSleepProvider {
        &self.sleep
    }

    /// See [`MockSleepProvider::advance()`]
    pub async fn advance(&self, dur: Duration) {
        self.sleep.advance(dur).await;
    }
    /// See [`MockSleepProvider::jump_to()`]
    pub fn jump_to(&self, new_wallclock: SystemTime) {
        self.sleep.jump_to(new_wallclock);
    }
    /// Run a future under mock time, advancing time forward where necessary until it completes.
    /// Users of this function should read the whole of this documentation before using!
    ///
    /// **NOTE** Instead of using this, consider [`MockRuntime`](crate::MockRuntime),
    /// which will fully isolate the test case
    /// (albeit at the cost of demanding manual management of the simulated time).
    ///
    /// The returned future will run `fut`, expecting it to create `Sleeping` futures (as returned
    /// by `MockSleepProvider::sleep()` and similar functions). When all such created futures have
    /// been polled (indicating the future is waiting on them), time will be advanced in order that
    /// the first (or only) of said futures returns `Ready`. This process then repeats until `fut`
    /// returns `Ready` itself (as in, the returned wrapper future will wait for all created
    /// `Sleeping` futures to be polled, and advance time again).
    ///
    /// **Note:** The above described algorithm interacts poorly with futures that spawn
    /// asynchronous background tasks, or otherwise expect work to complete in the background
    /// before time is advanced. These futures will need to make use of the
    /// `SleepProvider::block_advance` (and similar) APIs in order to prevent time advancing while
    /// said tasks complete; see the documentation for those APIs for more detail.
    ///
    /// # Panics
    ///
    /// Panics if another `WaitFor` future is already running. (If two ran simultaneously, they
    /// would both try and advance the same mock time clock, which would be bad.)
    pub fn wait_for<F: futures::Future>(&self, fut: F) -> WaitFor<F> {
        assert!(
            !self.sleep.has_waitfor_waker(),
            "attempted to call MockSleepRuntime::wait_for while another WaitFor is active"
        );
        WaitFor {
            sleep: self.sleep.clone(),
            fut,
        }
    }
}

/// A future that advances time until another future is ready to complete.
#[pin_project]
pub struct WaitFor<F> {
    /// A reference to the sleep provider that's simulating time for us.
    #[pin]
    sleep: MockSleepProvider,
    /// The future that we're waiting for.
    #[pin]
    fut: F,
}

use std::pin::Pin;
use std::task::{Context, Poll};

impl<F: Future> Future for WaitFor<F> {
    type Output = F::Output;

    #[allow(clippy::cognitive_complexity)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        trace!("waitfor poll");
        let mut this = self.project();
        this.sleep.register_waitfor_waker(cx.waker().clone());

        if let Poll::Ready(r) = this.fut.poll(cx) {
            trace!("waitfor done!");
            this.sleep.clear_waitfor_waker();
            return Poll::Ready(r);
        }
        trace!("waitfor poll complete");

        if this.sleep.should_advance() {
            if let Some(duration) = this.sleep.time_until_next_timeout() {
                trace!("Advancing by {:?}", duration);
                this.sleep.advance_noyield(duration);
            } else {
                // If we get here, something's probably wedged and the test isn't going to complete
                // anyway: we were expecting to advance in order to make progress, but we can't.
                // If we don't panic, the test will just run forever, which is really annoying, so
                // just panic and fail quickly.
                panic!("WaitFor told to advance, but didn't have any duration to advance by");
            }
        } else {
            trace!("waiting for sleepers to advance");
        }
        Poll::Pending
    }
}
