//! Helper implementation for a type wrapping an AsyncBufReader
//! and making its poll_fill_buf() method fused with respect to errors and EOF.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use futures::{AsyncBufRead, AsyncWrite};
use pin_project::pin_project;

use crate::arc_io_result::ArcIoResult;

/// A wrapper around a [`AsyncBufRead`] that provides fuse-like behavior
/// for terminal states (EOF and Err).
///
/// Only uses the [`consume`] and [`poll_fill_buf`] methods from the inner
/// `AsyncBufRead`.  Once `poll_fill_buf` has returned Ok(&[]) or Err(),
/// it won't be called again, and only the last returned value will be
/// returned.
///
/// Because we need the ability to return multiple copies of the same error,
/// and `io::Error` doesn't support Clone, we have to return a new `io::Error`
/// wrapping the original `io::Error` in an `Arc`.
///
/// [`consume`]: AsyncBufRead::consume
/// [`poll_fill_buf`]: AsyncBufRead::poll_fill_buf
#[derive(Debug)]
#[pin_project]
pub(crate) struct FuseBufReader<R> {
    /// The inner reader that we're wraping.
    #[pin]
    inner: R,

    /// The fused outcome of this reader, if any.
    outcome: Option<ArcIoResult<()>>,
}

impl<R> FuseBufReader<R> {
    /// Construct a new FuseBufReader.
    pub(crate) fn new(reader: R) -> Self {
        Self {
            inner: reader,
            outcome: None,
        }
    }

    /// Return a pinned pointer to the inner object.
    pub(crate) fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
        self.project().inner
    }

    /// Consume this `FuseBufReader` and return its underlying reader.
    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncBufRead> FuseBufReader<R> {
    /// As [`AsyncBufRead::consume`].
    pub(crate) fn consume(self: Pin<&mut Self>, n_written: usize) {
        self.project().inner.consume(n_written);
    }

    /// As [`AsyncBufRead::poll_fill_buf`], except as noted in the type documentation.
    pub(crate) fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<ArcIoResult<&[u8]>> {
        let this = self.project();
        if let Some(outcome) = this.outcome {
            return Poll::Ready(outcome.clone().map(|()| &[][..]));
        }

        match ready!(this.inner.poll_fill_buf(cx)) {
            Ok(empty @ &[]) => {
                *this.outcome = Some(Ok(()));
                Poll::Ready(Ok(empty))
            }
            Ok(buf) => Poll::Ready(Ok(buf)),

            Err(e) => {
                let outcome = Err(Arc::new(e));
                let result = outcome.clone().map(|()| &[][..]);
                *this.outcome = Some(outcome);
                Poll::Ready(result)
            }
        }
    }
}

impl<W> AsyncWrite for FuseBufReader<W>
where
    W: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}
