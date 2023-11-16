//! Implement half of log rate-limiting: the ability to cause the state of a
//! Loggable to get flushed at appropriate intervals.

use super::{Activity, Loggable};
use futures::task::SpawnExt as _;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tor_error::ErrorReport;

/// Declare a dyn-safe trait for the parts of an asynchronous runtime so that we
/// can install it globally.
pub(crate) mod rt {
    use futures::{future::BoxFuture, task::Spawn};
    use once_cell::sync::OnceCell;
    use std::time::{Duration, Instant};

    /// A dyn-safe view of the parts of an async runtime that we need for rate-limiting.
    pub trait RuntimeSupport: Spawn + 'static + Sync + Send {
        /// Return a future that will yield () after `duration` has passed.
        fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()>;

        /// Return the current time as an Instant.
        fn now(&self) -> Instant;
    }

    impl<R: tor_rtcompat::Runtime> RuntimeSupport for R {
        fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()> {
            Box::pin(tor_rtcompat::SleepProvider::sleep(self, duration))
        }
        fn now(&self) -> Instant {
            tor_rtcompat::SleepProvider::now(self)
        }
    }

    /// A global view of our runtime, used for rate-limited logging.
    // TODO MSRV 1.70: We could use OnceSync instead.
    static RUNTIME_SUPPORT: OnceCell<Box<dyn RuntimeSupport>> = OnceCell::new();

    /// Try to install `runtime` as a global runtime to be used for rate-limited logging.
    ///
    /// Return an error (and make no changes) if there there was already a runtime installed.
    pub fn install_runtime<R: tor_rtcompat::Runtime>(
        runtime: R,
    ) -> Result<(), InstallRuntimeError> {
        let rt = Box::new(runtime);
        RUNTIME_SUPPORT
            .set(rt)
            .map_err(|_| InstallRuntimeError::DuplicateCall)
    }

    /// An error that occurs while installing a runtime.
    #[derive(Clone, Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum InstallRuntimeError {
        /// Tried to install a runtime when there was already one installed.
        #[error("Called tor_log_ratelim::install_runtime() more than once")]
        DuplicateCall,
    }

    /// Return the installed runtime, if there is one.
    pub fn rt_support() -> Option<&'static dyn RuntimeSupport> {
        RUNTIME_SUPPORT.get().map(Box::as_ref)
    }
}

/// A rate-limited wrapper around a [`Loggable`]` that ensures its events are
/// flushed from time to time.
pub struct RateLim<T> {
    /// The Loggable itself.
    inner: Mutex<Inner<T>>,
}

/// The mutable state of a [`RateLim`].
struct Inner<T> {
    /// The loggable state whose reports are rate-limited
    loggable: T,
    /// True if we have a running task that is collating reports for `loggable`.
    task_running: bool,
}

impl<T: Loggable> RateLim<T> {
    /// Create a new `RateLim` to flush events for `loggable`.
    pub fn new(loggable: T) -> Arc<Self> {
        Arc::new(RateLim {
            inner: Mutex::new(Inner {
                loggable,
                task_running: false,
            }),
        })
    }

    /// Adjust the status of this reporter's `Loggable` by calling `f` on it,
    /// but only if it is already scheduled to report itself.  Otherwise, do nothing.
    ///
    /// This is the appropriate function to use for tracking successes.f
    pub fn nonevent<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut inner = self.inner.lock().expect("lock poisoned");
        if inner.task_running {
            f(&mut inner.loggable);
        }
    }

    /// Add an event to this rate-limited reporter by calling `f` on it, and
    /// schedule it to be reported after an appropriate time.
    ///
    /// NOTE: This API is a big ugly. If we ever decide to make it non-hidden,
    /// we may want to make it call rt_support() directly again, as it did in
    /// earlier visions.
    pub fn event<F>(self: &Arc<Self>, rt: &'static dyn rt::RuntimeSupport, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut inner = self.inner.lock().expect("poisoned lock");
        f(&mut inner.loggable);

        if !inner.task_running {
            // Launch a task to make periodic reports on the state of our Loggable.
            inner.task_running = true;
            if let Err(e) = rt.spawn(Box::pin(run(rt, Arc::clone(self)))) {
                // We couldn't spawn a task; we have to flush the state
                // immediately.
                inner.loggable.flush(Duration::default());
                tracing::warn!("Also, unable to spawn a logging task: {}", e.report());
            }
        }
    }
}

/// After approximately this many seconds of not having anything to report, we
/// should reset our timeout schedule.
const RESET_AFTER_DORMANT_FOR: Duration = Duration::new(4 * 60 * 60, 0);

/// Return an iterator of reasonable amounts of time to summarize.
///
/// We summarize short intervals at first, and back off as the event keeps
/// happening.
fn timeout_sequence() -> impl Iterator<Item = Duration> {
    [5, 30, 30, 60, 60, 4 * 60, 4 * 60] // in minutes
        .into_iter()
        .chain(std::iter::repeat(24 * 60))
        .map(|n| Duration::new(n * 60, 0))
}

/// Helper: runs in a background task, and periodically flushes the `Loggable`
/// in `ratelim`.  Exits after [`Loggable::flush`] returns [`Activity::Dormant`]
/// for "long enough".
async fn run<T>(rt_support: &dyn rt::RuntimeSupport, ratelim: Arc<RateLim<T>>)
// TODO : Perhaps instead of taking an Arc<RateLim<T>> we want sometimes to take
// a `&'static RateLim<T>``, so we don't need to mess about with `Arc`s needlessly.
where
    T: Loggable,
{
    let mut dormant_since = None;
    for duration in timeout_sequence() {
        rt_support.sleep(duration).await;
        {
            let mut inner = ratelim.inner.lock().expect("Lock poisoned");
            debug_assert!(inner.task_running);
            if inner.loggable.flush(duration) == Activity::Dormant {
                // TODO: This can tell the user several times that the problem
                // did not occur! Perhaps we only want to flush once on dormant,
                // and then not report the dormant condition again until we are
                // no longer tracking it.  Or perhaps we should lower the
                // responsibility for deciding when to log and when to uninstall
                // to the Loggable?
                match dormant_since {
                    Some(when) => {
                        if let Some(dormant_for) = rt_support.now().checked_duration_since(when) {
                            if dormant_for >= RESET_AFTER_DORMANT_FOR {
                                inner.task_running = false;
                                return;
                            }
                        }
                    }
                    None => {
                        dormant_since = Some(rt_support.now());
                    }
                }
            } else {
                dormant_since = None;
            }
        }
    }

    unreachable!("timeout_sequence returned a finite sequence");
}

// TODO : Write some tests.
