//! Functions for task management that don't belong inside the Runtime
//! trait.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Yield execution back to the runtime temporarily, so that other
/// tasks can run.
#[must_use = "yield_now returns a future that must be .awaited on."]
pub fn yield_now() -> YieldFuture {
    // TODO: There are functions similar to this in tokio and
    // async_std and futures_lite.  It would be lovely if futures had
    // one too.  If it does, we should probably use it.
    YieldFuture { first_time: true }
}

/// A future returned by [`yield_now()`].
///
/// It returns `Poll::Pending` once, and `Poll::Ready` thereafter.
#[derive(Debug)]
#[must_use = "Futures do nothing unless .awaited on."]
pub struct YieldFuture {
    /// True if this future has not yet been polled.
    first_time: bool,
}

impl Future for YieldFuture {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.first_time {
            self.first_time = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

#[cfg(all(
    test,
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "tokio", feature = "async-std"),
    not(miri), // this typically results in use of a yield syscall
))]
mod test {
    use super::yield_now;
    use crate::test_with_all_runtimes;

    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_yield() {
        test_with_all_runtimes!(|_| async {
            let b = AtomicBool::new(false);
            use Ordering::SeqCst;

            // Both tasks here run in a loop, trying to set 'b' to their
            // favorite value, and returning once they've done it 10 times.
            //
            // Without 'yield_now', one task is likely to monopolize
            // the scheduler.
            futures::join!(
                async {
                    let mut n = 0_usize;
                    while n < 10 {
                        if b.compare_exchange(false, true, SeqCst, SeqCst).is_ok() {
                            n += 1;
                        }
                        yield_now().await;
                    }
                },
                async {
                    let mut n = 0_usize;
                    while n < 10 {
                        if b.compare_exchange(true, false, SeqCst, SeqCst).is_ok() {
                            n += 1;
                        }
                        yield_now().await;
                    }
                }
            );
            std::io::Result::Ok(())
        });
    }
}
