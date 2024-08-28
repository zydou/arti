//! Cancellable futures.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use futures::{future::FusedFuture, Future};
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

/// Inner state shared between `Cancel` and the `CancelHandle.
struct Inner {
    /// True if this future has been cancelled.
    cancelled: bool,
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
            cancelled: false,
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
    pub(crate) fn cancel(&self) {
        let mut inner = self.inner.lock().expect("poisoned lock");
        inner.cancelled = true;
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
    }
}

/// An error returned from a `Cancel` future if it is cancelled.
#[derive(thiserror::Error, Clone, Debug)]
#[error("Future was cancelled")]
pub(crate) struct Cancelled;

impl<F: Future> Future for Cancel<F> {
    type Output = Result<F::Output, Cancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        {
            let mut inner = self.inner.lock().expect("lock poisoned");
            if inner.cancelled {
                return Poll::Ready(Err(Cancelled));
            }
            inner.waker = Some(cx.waker().clone());
        }
        let this = self.project();
        this.fut.poll(cx).map(Ok)
    }
}

impl<F: FusedFuture> FusedFuture for Cancel<F> {
    fn is_terminated(&self) -> bool {
        {
            let inner = self.inner.lock().expect("lock poisoned");
            if inner.cancelled {
                return true;
            }
        }
        self.fut.is_terminated()
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
    use futures_await_test::async_test;
    use oneshot_fused_workaround as oneshot;

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
            h.cancel();
        });
        assert!(matches!(r, Err(Cancelled)));

        let (_tx, rx) = oneshot::channel::<()>();
        let (h, f) = Cancel::new(rx);
        let (r, ()) = futures::join!(f, async {
            h.cancel();
        });
        assert!(matches!(r, Err(Cancelled)));
    }
}
