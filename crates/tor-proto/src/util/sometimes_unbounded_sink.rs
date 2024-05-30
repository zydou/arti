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
            Ready(Ok(())) => self.as_mut().start_send(item),
            Ready(Err(e)) => Err(e),
            Pending => {
                self.as_mut().project().buf.push_back(item);
                Ok(())
            }
        }
    }

    /// Hand `item` to the inner Sink if possible, or queue it otherwise (async fn)
    ///
    /// You must `.await` this, but it will never block.
    /// (Its future is always `Ready`.)
    #[allow(dead_code)] // TODO #1387 consider removing this then if it remains unused
    async fn send_unbounded(mut self: Pin<&mut Self>, item: T) -> Result<(), S::Error> {
        let mut item = Some(item);
        future::poll_fn(move |cx| {
            let item = item.take().expect("polled after Ready");
            Ready(self.as_mut().pollish_send_unbounded(cx, item))
        })
        .await
    }

    /// Flush the buffer.  On a `Ready(())` return, it's empty.
    fn flush_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        let mut self_ = self.as_mut().project();
        while !self_.buf.is_empty() {
            ready!(self_.inner.as_mut().poll_ready(cx))?;
            let item = self_.buf.pop_front().expect("suddenly empty!");
            self_.inner.as_mut().start_send(item)?;
        }
        Ready(Ok(()))
    }
}

impl<T, S: Sink<T>> Sink<T> for SometimesUnboundedSink<T, S> {
    type Error = S::Error;

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
