//! Cancellable futures.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use futures::Future;
use pin_project::pin_project;

/// A cancellable future type, loosely influenced by `RemoteHandle`.
///
/// This type is useful for cases when we can't cancel a future simply by
/// dropping it, because the future is owned by some other object (like a
/// `FuturesUnordered`) that won't give it up.
//
// We could use `tokio_util`'s cancellable futures instead here, but I don't
// think we want an unconditional tokio_util dependency.
#[pin_project]
pub(crate) struct Cancel<F> {
    /// Shared state between the `Cancel` and the `CancelHandle`.
    //
    // It would be nice not to have to stick this behind a mutex, but that would
    // make it a bit tricky to manage the Waker.
    inner: Arc<Mutex<Inner>>,
    /// The inner future.
    #[pin]
    fut: F,
}

/// Possible status of `Cancel` future.
#[derive(Clone, Copy, Debug)]
enum Status {
    /// The future has neither finished, nor been cancelled.
    Pending,
    /// The future has finished; it can no longer be cancelled.
    Finished,
    /// The future has been cancelled; it should no longer be polled.
    Cancelled,
}

/// Inner state shared between `Cancel` and the `CancelHandle.
struct Inner {
    /// Current status of the future.
    status: Status,
    /// A waker to use in telling this future that it's cancelled.
    waker: Option<Waker>,
}

/// An object that can be used to cancel a future.
#[derive(Clone)]
pub(crate) struct CancelHandle {
    /// The shared state for the cancellable future between `Cancel` and
    /// `CancelHandle`.
    inner: Arc<Mutex<Inner>>,
}

impl<F> Cancel<F> {
    /// Wrap `fut` in a new future that can be cancelled.
    ///
    /// Returns a handle to cancel the future, and the cancellable future.
    pub(crate) fn new(fut: F) -> (CancelHandle, Cancel<F>) {
        let inner = Arc::new(Mutex::new(Inner {
            status: Status::Pending,
            waker: None,
        }));
        let handle = CancelHandle {
            inner: inner.clone(),
        };
        let future = Cancel { inner, fut };
        (handle, future)
    }
}

impl CancelHandle {
    /// Cancel the associated future, if it has not already finished.
    #[allow(dead_code)] // TODO RPC
    pub(crate) fn cancel(&self) -> Result<(), CannotCancel> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        match inner.status {
            Status::Pending => inner.status = Status::Cancelled,
            Status::Finished => return Err(CannotCancel::Finished),
            Status::Cancelled => return Err(CannotCancel::Cancelled),
        }
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

/// An error returned from a `Cancel` future if it is cancelled.
#[derive(thiserror::Error, Clone, Debug)]
#[error("Future was cancelled")]
pub(crate) struct Cancelled;

/// An error returned when we cannot cancel a future.
#[derive(thiserror::Error, Clone, Debug)]
pub(crate) enum CannotCancel {
    /// This future was already cancelled, and can't be cancelled again.
    #[error("Already cancelled")]
    Cancelled,

    /// This future has already completed, and can't be cancelled.
    #[error("Already finished")]
    Finished,
}

impl<F: Future> Future for Cancel<F> {
    type Output = Result<F::Output, Cancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let mut inner = this.inner.lock().expect("lock poisoned");
        match inner.status {
            Status::Pending => {}
            Status::Finished => {
                // Yes, we do intentionally allow a finished future to be polled again.
                // This does not violate our invariants.
                // If you want to prevent this, you need to use Fuse or a similar mechanism.
            }
            Status::Cancelled => return Poll::Ready(Err(Cancelled)),
        }
        // Note that we're holding the mutex here while we poll the future.
        // This guarantees that the future can't make _any_ progress after it has been
        // cancelled.  If we someday decide we don't care about that, we could release the mutex
        // while polling, and pick it up again after we're done polling.
        match this.fut.poll(cx) {
            Poll::Ready(val) => {
                inner.status = Status::Finished;
                Poll::Ready(Ok(val))
            }
            Poll::Pending => {
                if let Some(existing_waker) = &mut inner.waker {
                    // If we already have a waker, we use clone_from here,
                    // since that function knows to use will_wake
                    // to avoid a needless clone.
                    existing_waker.clone_from(cx.waker());
                } else {
                    // Otherwise, we need to clone cx.waker().
                    inner.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
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

    use std::{future, time::Duration};

    use super::*;
    use futures::{stream::FuturesUnordered, FutureExt as _, StreamExt as _};
    use futures_await_test::async_test;
    use oneshot_fused_workaround as oneshot;
    use tor_basic_utils::RngExt;
    use tor_rtcompat::SleepProvider as _;

    #[async_test]
    async fn not_cancelled() {
        let f = futures::future::ready("hello");
        let (_h, f) = Cancel::new(f);
        assert_eq!(f.await.unwrap(), "hello");
    }

    #[async_test]
    async fn cancelled() {
        let f = futures::future::pending::<()>();
        let (h, f) = Cancel::new(f);
        let (r, ()) = futures::join!(f, async {
            h.cancel().unwrap();
        });
        assert!(matches!(r, Err(Cancelled)));

        let (_tx, rx) = oneshot::channel::<()>();
        let (h, f) = Cancel::new(rx);
        let (r, ()) = futures::join!(f, async {
            h.cancel().unwrap();
        });
        assert!(matches!(r, Err(Cancelled)));
    }

    #[test]
    fn cancelled_or_not() {
        // This looks pretty complicated!  But really what we're doing is running a whole bunch
        // of tasks and cancelling them almost-immediately, to make sure that every task either
        // succeeds or fails.

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = tor_rtmock::MockSleepRuntime::new(rt);

            const N_TRIES: usize = 1024;
            // Time is virtual here, so the interval doesn't matter.
            const SLEEP_CEIL: Duration = Duration::from_millis(1);
            let work_succeeded = Arc::new(Mutex::new([None; N_TRIES]));
            let cancel_succeeded = Arc::new(Mutex::new([None; N_TRIES]));

            let mut futs = FuturesUnordered::new();
            for idx in 0..N_TRIES {
                let work_succeeded = Arc::clone(&work_succeeded);
                let cancel_succeeded = Arc::clone(&cancel_succeeded);
                let rt1 = rt.clone();
                let rt2 = rt.clone();
                let t1 = rand::thread_rng().gen_range_infallible(..=SLEEP_CEIL);
                let t2 = rand::thread_rng().gen_range_infallible(..=SLEEP_CEIL);

                let work = future::ready(());
                let (handle, work) = Cancel::new(work);
                let f1 = async move {
                    rt1.sleep(t1).await;
                    let r = handle.cancel();
                    cancel_succeeded.lock().unwrap()[idx] = Some(r.is_ok());
                };
                let f2 = async move {
                    rt2.sleep(t2).await;
                    let r = work.await;
                    work_succeeded.lock().unwrap()[idx] = Some(r.is_ok());
                };

                futs.push(f1.boxed());
                futs.push(f2.boxed());
            }

            rt.wait_for(async { while let Some(()) = futs.next().await {} })
                .await;
            for idx in 0..N_TRIES {
                let ws = work_succeeded.lock().unwrap()[idx];
                let cs = cancel_succeeded.lock().unwrap()[idx];
                match (ws, cs) {
                    (Some(true), Some(false)) => {}
                    (Some(false), Some(true)) => {}
                    _ => panic!("incorrect values {:?}", (idx, ws, cs)),
                }
            }
        });
    }
}
