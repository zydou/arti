//! [`PollAll`]

use futures::FutureExt as _;
use smallvec::{SmallVec, smallvec};

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The future type in a [`PollAll`].
type BoxedFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Helper for driving multiple futures in lockstep.
///
/// When `.await`ed, a [`PollAll`] will unconditionally poll *all* of its
/// underlying futures, in the order they were [`push`](PollAll::push)ed,
/// until one or more of them resolves.
/// Any remaining unresolved futures will be dropped.
/// An empty `PollAll` will resolve immediately, yielding an empty list.
///
/// `PollAll` resolves to an *ordered* list of results, obtained from polling
/// the futures in insertion order. Because some of the futures may not
/// get a chance to resolve, the number of results will always
/// be less than or equal to the number of inserted futures.
///
/// Because `PollAll` drives the futures in lockstep,
/// if one future becomes ready, all of the futures will get polled,
/// even if they didn't generate a wakeup notification.
///
/// ### Invariants
///
/// All of the futures inserted into this set **must** be cancellation safe.
#[derive(Default)]
pub(crate) struct PollAll<'a, const N: usize, T> {
    /// The futures to drive in lockstep.
    inner: SmallVec<[BoxedFut<'a, T>; N]>,
}

impl<'a, const N: usize, T> PollAll<'a, N, T> {
    /// Create an empty [`PollAll`].
    pub(crate) fn new() -> Self {
        Self { inner: smallvec![] }
    }

    /// Add a future to this [`PollAll`].
    pub(crate) fn push<S: Future<Output = T> + Send + 'a>(&mut self, item: S) {
        self.inner.push(Box::pin(item));
    }
}

impl<'a, const N: usize, T> Future for PollAll<'a, N, T> {
    type Output = SmallVec<[T; N]>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut results = smallvec![];

        if self.inner.is_empty() {
            // Nothing to do.
            return Poll::Ready(results);
        }

        for fut in self.inner.iter_mut() {
            match fut.poll_unpin(cx) {
                Poll::Ready(res) => results.push(res),
                Poll::Pending => continue,
            }
        }

        if results.is_empty() {
            return Poll::Pending;
        }

        Poll::Ready(results)
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use tor_rtmock::MockRuntime;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Dummy smallvec capacity.
    const RES_COUNT: usize = 5;

    /// A wrapper over a future, that counts how many times it is polled.
    struct PollCounter<F> {
        /// The poll count, shared with the caller.
        count: Arc<AtomicUsize>,
        /// The underlying future.
        inner: F,
    }

    /// A future that resolves after a fixed number of calls to `poll()`.
    struct ResolveAfter {
        /// The number of poll() calls until this future resolves
        resolve_after: usize,
        /// The number of times poll() was called on this.
        poll_count: usize,
    }

    impl ResolveAfter {
        fn new(resolve_after: usize) -> Self {
            Self {
                resolve_after,
                poll_count: 0,
            }
        }
    }

    impl<F> PollCounter<F> {
        fn new(inner: F) -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            let poll_counter = Self {
                count: Arc::clone(&count),
                inner,
            };

            (poll_counter, count)
        }
    }

    impl<F: Future + Unpin> Future for PollCounter<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let _ = self.count.fetch_add(1, Ordering::Relaxed);
            self.inner.poll_unpin(cx)
        }
    }

    impl Future for ResolveAfter {
        type Output = usize;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.poll_count += 1;

            // TODO MSRV 1.87: Remove this allow.
            #[allow(
                clippy::comparison_chain,
                reason = "This is more readable than a match, and the lint is
                moved to clippy::pedantic in 1.87."
            )]
            if self.poll_count == self.resolve_after {
                Poll::Ready(self.resolve_after)
            } else if self.poll_count > self.resolve_after {
                panic!("future polled after completion?!");
            } else {
                // Immediately wake the waker
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn poll_none() {
        MockRuntime::test_with_various(|_| async move {
            assert!(PollAll::<RES_COUNT, ()>::new().await.is_empty());
        });
    }

    #[test]
    fn poll_multiple() {
        MockRuntime::test_with_various(|_| async move {
            let mut poll_all = PollAll::<RES_COUNT, usize>::new();

            let (never_fut, never_count) = PollCounter::new(futures::future::pending::<usize>());
            poll_all.push(never_fut);

            let (futures, counters): (Vec<_>, Vec<_>) = [
                PollCounter::new(ResolveAfter::new(5)),
                PollCounter::new(ResolveAfter::new(5)),
                // These won't get a chance to resolve
                PollCounter::new(ResolveAfter::new(8)),
                PollCounter::new(ResolveAfter::new(9)),
            ]
            .into_iter()
            .unzip();

            for fut in futures {
                poll_all.push(fut);
            }

            let res = poll_all.await;
            assert_eq!(&res[..], &[5, 5]);

            // All futures were polled 5 times.
            assert_eq!(never_count.load(Ordering::Relaxed), 5);
            for counter in counters {
                assert_eq!(counter.load(Ordering::Relaxed), 5);
            }
        });
    }
}
