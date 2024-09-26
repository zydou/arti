//! [`SometimesUnboundedSink`]

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{ready, Context, Poll, Poll::*};

use futures::{future, Sink};

use pin_project::pin_project;

/// Wraps a [`Sink`], providing an only-sometimes-used unbounded buffer
///
/// For example, consider `SometimesUnboundedSink<T, mpsc::Receiver>`.
/// The `Receiver` is not always ready for writing:
/// if the capacity is exceeded, `send` will block.
///
/// `SometimesUnboundedSink`'s `Sink` implementation works the same way.
/// But there are also two methods
/// [`pollish_send_unbounded`](SometimesUnboundedSink::pollish_send_unbounded)
/// and
/// [`send_unbounded`](SometimesUnboundedSink::send_unbounded)
/// which will always succeed immediately.
/// Items which the underlying sink `S` is not ready to accept are queued,
/// and will be delivered to `S` when possible.
///
/// ### You must poll this type
///
/// For queued items to be delivered,
/// `SometimesUnboundedSink` must be polled,
/// even if you don't have an item to send.
///
/// You can use [`Sink::poll_ready`] for this.
/// Any [`Context`]-taking methods is suitable.
///
/// ### Error handling
///
/// Errors from the underlying sink may not be reported immediately,
/// due to the buffering in `SometimesUnboundedSink`.
///
/// However, if the sink reports errors from `poll_ready`
/// these will surface in a timely fashion.
///
/// After an error has been reported, there may still be buffered data,
/// which will only be delivered if `SometimesUnboundedSink` is polled again
/// (and the error in the underlying sink was transient).
#[pin_project]
pub(crate) struct SometimesUnboundedSink<T, S> {
    /// Things we couldn't send_unbounded right away
    ///
    /// Invariants:
    ///
    ///  * Everything here must be fed to `inner` before any further user data
    ///    (unbounded user data may be appended).
    ///
    ///  * If this is nonempty, the executor knows to wake this task.
    ///    This is achieved as follows:
    ///    If this is nonempty, `inner.poll_ready()` has been called.
    buf: VecDeque<T>,

    /// The actual sink
    ///
    /// This also has the relevant `Waker`.
    ///
    /// # Waker invariant
    ///
    /// Whenever either
    ///
    ///  * The last call to any of our public methods returned `Pending`, or
    ///  * `buf` is nonempty,
    ///
    /// the last method call `inner` *also* returned `Pending`.
    /// (Or, we have reported an error.)
    ///
    /// So, in those situations, this task has been recorded for wakeup
    /// by `inner` (specifically, its other end, if it's a channel)
    /// when `inner` becomes readable.
    ///
    /// Therefore this task will be woken up, and, if the caller actually
    /// polls us again (as is usual and is required by our docs),
    /// we'll drain any queued data.
    #[pin]
    inner: S,
}

impl<T, S: Sink<T>> SometimesUnboundedSink<T, S> {
    /// Wrap an inner `Sink` with a `SometimesUnboundedSink`
    //
    // There is no method for unwrapping.  If we make this type more public,
    // there should be, but that method will need `where S: Unpin`.
    pub(crate) fn new(inner: S) -> Self {
        SometimesUnboundedSink {
            buf: VecDeque::new(),
            inner,
        }
    }

    /// Hand `item` to the inner Sink if possible, or queue it otherwise
    ///
    /// Like a `poll_...` method in that it takes a `Context`.
    /// That's needed to make sure we get polled again
    /// when the underlying sink can accept items.
    ///
    /// But unlike a `poll_...` method in that it doesn't return `Poll`,
    /// since completion is always immediate.
    pub(crate) fn pollish_send_unbounded(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        item: T,
    ) -> Result<(), S::Error> {
        match self.as_mut().poll_ready(cx) {
            // Waker invariant: poll_ready only returns Ready(Ok(())) if `buf` is empty
            Ready(Ok(())) => self.as_mut().start_send(item),
            // Waker invariant: if we report an error, we're then allowed to expect polling again
            Ready(Err(e)) => Err(e),
            Pending => {
                // Waker invariant: poll_ready() returned Pending,
                // so the task has indeed already been recorded.
                self.as_mut().project().buf.push_back(item);
                Ok(())
            }
        }
    }

    /// Hand `item` to the inner Sink if possible, or queue it otherwise (async fn)
    ///
    /// You must `.await` this, but it will never block.
    /// (Its future is always `Ready`.)
    #[allow(dead_code)] // TODO #1397 consider removing this then if it remains unused
    async fn send_unbounded(mut self: Pin<&mut Self>, item: T) -> Result<(), S::Error> {
        // Waker invariant: this is just a wrapper around `pollish_send_unbounded`
        let mut item = Some(item);
        future::poll_fn(move |cx| {
            let item = item.take().expect("polled after Ready");
            Ready(self.as_mut().pollish_send_unbounded(cx, item))
        })
        .await
    }

    /// Flush the buffer.  On a `Ready(())` return, it's empty.
    ///
    /// This satisfies the Waker invariant as if it were a public method.
    fn flush_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        let mut self_ = self.as_mut().project();
        while !self_.buf.is_empty() {
            // Waker invariant:
            // if inner gave Pending, we give Pending too: ok
            // if inner gave Err, we're allowed to want polling again
            ready!(self_.inner.as_mut().poll_ready(cx))?;
            let item = self_.buf.pop_front().expect("suddenly empty!");
            // Waker invariant: returning Err
            self_.inner.as_mut().start_send(item)?;
        }
        // Waker invariant: buffer is empty, and we're not about to return Pending
        Ready(Ok(()))
    }

    /// Obtain a reference to the inner `Sink`, `S`
    ///
    /// This method should be used with a little care, since it bypasses the wrapper.
    /// For example, if `S` has interior mutability, and this method is used to
    /// modify it, the `SometimesUnboundedSink` may malfunction.
    #[allow(dead_code)] // TODO #351.  Or, if this type becomes pub, removes the allow
    pub(crate) fn as_inner(&self) -> &S {
        &self.inner
    }
}

// Waker invariant for all these impls:
// returning Err or Pending from flush_buf: OK, flush_buf ensures the condition holds
// returning from the inner method: trivially OK
impl<T, S: Sink<T>> Sink<T> for SometimesUnboundedSink<T, S> {
    type Error = S::Error;

    // Only returns `Ready(Ok(()))` if `buf` is empty
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), S::Error> {
        assert!(self.buf.is_empty(), "start_send without poll_ready");
        self.project().inner.start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_close(cx)
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
    use std::pin::pin;
    use tor_rtmock::MockRuntime;

    #[test]
    fn cases() {
        // `test_with_various` runs with both LIFO and FIFO scheduling policies,
        // so should interleave the sending and receiving tasks
        // in ways that exercise the corner cases we're interested in.
        MockRuntime::test_with_various(|runtime| async move {
            let (tx, rx) = mpsc::channel(1);
            let tx = SometimesUnboundedSink::new(tx);

            runtime.spawn_identified("sender", async move {
                let mut tx = pin!(tx);
                let mut n = 0..;
                let mut n = move || n.next().unwrap();

                // unbounded when we can send right away
                tx.as_mut().send_unbounded(n()).await.unwrap();
                tx.as_mut().send(n()).await.unwrap();
                tx.as_mut().send(n()).await.unwrap();
                tx.as_mut().send(n()).await.unwrap();
                // unbounded when we maybe can't and might queue
                tx.as_mut().send_unbounded(n()).await.unwrap();
                tx.as_mut().send_unbounded(n()).await.unwrap();
                tx.as_mut().send_unbounded(n()).await.unwrap();
                // some interleaving
                tx.as_mut().send(n()).await.unwrap();
                tx.as_mut().send_unbounded(n()).await.unwrap();
                // flush
                tx.as_mut().flush().await.unwrap();
                // close
                tx.as_mut().close().await.unwrap();
            });

            runtime.spawn_identified("receiver", async move {
                let mut rx = pin!(rx);
                let mut exp = 0..;

                while let Some(n) = rx.next().await {
                    assert_eq!(n, exp.next().unwrap());
                }
                assert_eq!(exp.next().unwrap(), 9);
            });

            runtime.progress_until_stalled().await;
        });
    }
}
