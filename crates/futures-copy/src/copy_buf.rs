//! Functionality to copy from an `AsyncBufRead` to an `AsyncWrite`.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use crate::{
    arc_io_result::{ArcIoResult, ArcIoResultExt},
    fuse_buf_reader::FuseBufReader,
};
use futures::{AsyncBufRead, AsyncWrite};
use pin_project::pin_project;

/// Return a future to copy all bytes interactively from `reader` to `writer`.
///
/// Unlike [`futures::io::copy`], this future makes sure that
/// if `reader` pauses (returns `Pending`),
/// all as-yet-received bytes are still flushed to `writer`.
///
/// The future continues copying data until either an error occurs
/// (in which case it yields an error),
/// or the reader returns an EOF
/// (in which case it flushes any pending data,
/// and returns the number of bytes copied).
///
/// # Limitations
///
/// See the crate-level documentation for
/// [discussion of this function's limitations](crate#Limitations).
pub fn copy_buf<R, W>(reader: R, writer: W) -> CopyBuf<R, W>
where
    R: AsyncBufRead,
    W: AsyncWrite,
{
    CopyBuf {
        reader: FuseBufReader::new(reader),
        writer,
        copied: 0,
    }
}

/// A future returned by [`copy_buf`].
#[derive(Debug)]
#[pin_project]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct CopyBuf<R, W> {
    /// The reader that we're taking data from.
    ///
    /// This is `FuseBufReader` to make our logic simpler.
    #[pin]
    reader: FuseBufReader<R>,

    /// The writer that we're pushing
    #[pin]
    writer: W,

    /// The number of bytes written to the writer so far.
    copied: u64,
}

impl<R, W> CopyBuf<R, W> {
    /// Consume this CopyBuf future, and return the underlying reader and writer.
    pub fn into_inner(self) -> (R, W) {
        (self.reader.into_inner(), self.writer)
    }
}

impl<R, W> Future for CopyBuf<R, W>
where
    R: AsyncBufRead,
    W: AsyncWrite,
{
    type Output = std::io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let () = ready!(poll_copy_r_to_w(
            cx,
            this.reader,
            this.writer,
            this.copied,
            false
        ))
        .io_result()?;
        Poll::Ready(Ok(*this.copied))
    }
}

/// Core implementation function:
/// Try to make progress copying bytes from `reader` to `writer`,
/// and add the number of bytes written to `*total_copied`.
///
/// Returns `Ready` when an error has occurred,
/// or when the reader has reached EOF and the writer has been flushed.
/// Otherwise, returns `Pending`, and registers itself with `cx`.
///
/// (This is a separate function so we can use it to implement CopyBuf and CopyBufBidirectional.)
pub(crate) fn poll_copy_r_to_w<R, W>(
    cx: &mut Context<'_>,
    mut reader: Pin<&mut FuseBufReader<R>>,
    mut writer: Pin<&mut W>,
    total_copied: &mut u64,
    flush_on_err: bool,
) -> Poll<ArcIoResult<()>>
where
    R: AsyncBufRead,
    W: AsyncWrite,
{
    // TODO: Instead of using poll_fill_buf() unconditionally,
    // it might be a neat idea to use the buffer by reference and just keep writing
    // if the buffer is already "full enough".  The futures::io AsyncBufRead API
    // doesn't really make that possible, though.  If specialization is ever stabilized,
    // we could have a special implementation for BufReader, I guess.

    // TODO: We assume that 'flush' is pretty fast when it has nothing to do.
    // If that's wrong, we may need to remember whether we've written data but not flushed it.

    loop {
        match reader.as_mut().poll_fill_buf(cx) {
            Poll::Pending => {
                // If there's nothing to read now, we may need to make sure that the writer
                // is flushed.
                let () = ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                //  On error, flush, and propagate the error.
                if flush_on_err {
                    let _ignore_flush_error = ready!(writer.as_mut().poll_flush(cx));
                }
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(&[])) => {
                // On EOF, we have already written all the data; make sure we flush it,
                // and then return the amount that we copied.
                let () = ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Ok(data)) => {
                // If there is pending data, we copy as much as we can.
                // We return "pending" if we can't write any.
                let n_written: usize = ready!(writer.as_mut().poll_write(cx, data))?;
                // Remove the data from the reader.
                reader.as_mut().consume(n_written);
                *total_copied += n_written as u64;
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::test::{ErrorRW, PausedRead};

    use futures::{
        AsyncReadExt as _,
        future::poll_fn,
        io::{BufReader, Cursor},
    };
    use std::io;
    use tor_rtcompat::SpawnExt as _;
    use tor_rtmock::{MockRuntime, io::stream_pair};

    async fn test_copy_cursor(data: &[u8]) {
        let mut out: Vec<u8> = Vec::new();
        let r = Cursor::new(data);
        let mut w = Cursor::new(&mut out);

        let n_copied = copy_buf(&mut BufReader::new(r), &mut w).await.unwrap();
        assert_eq!(n_copied, data.len() as u64);
        assert_eq!(&out[..], data);
    }

    async fn test_copy_stream(rt: &MockRuntime, data: &[u8]) {
        let out: Vec<u8> = Vec::new();
        let r1 = Cursor::new(data.to_vec());
        let (w1, r2) = stream_pair();
        let mut w2 = Cursor::new(out);
        let r1 = BufReader::new(r1);
        let r2 = BufReader::new(r2);
        let task1 = rt.spawn_with_handle(copy_buf(r1, w1)).unwrap();
        let task2 = rt
            .spawn_with_handle(async move {
                let copy_result = copy_buf(r2, &mut w2).await;
                (copy_result, w2)
            })
            .unwrap();

        let copy_result_1 = task1.await;
        let (copy_result_2, output) = task2.await;

        assert_eq!(copy_result_1.unwrap(), data.len() as u64);
        assert_eq!(copy_result_2.unwrap(), data.len() as u64);
        assert_eq!(&output.into_inner()[..], data);
    }

    async fn test_copy_stream_paused(rt: &MockRuntime, data: &[u8]) {
        let n = data.len();
        let r1 = BufReader::new(Cursor::new(data.to_vec()).chain(PausedRead));
        let (w1, mut r2) = stream_pair();
        let mut task1 = rt.spawn_with_handle(copy_buf(r1, w1)).unwrap();
        let mut buf = vec![0_u8; n];
        r2.read_exact(&mut buf[..]).await.unwrap();
        assert_eq!(&buf[..], data);

        // Should not be able to ever end.
        let task1_status = poll_fn(|cx| Poll::Ready(Pin::new(&mut task1).poll(cx))).await;
        assert!(task1_status.is_pending());
    }

    async fn test_copy_stream_error(rt: &MockRuntime, data: &[u8]) {
        let out: Vec<u8> = Vec::new();
        let r1 = Cursor::new(data.to_vec()).chain(ErrorRW(io::ErrorKind::ResourceBusy));
        let (w1, r2) = stream_pair();
        let mut w2 = Cursor::new(out);
        let r1 = BufReader::new(r1);
        let r2 = BufReader::new(r2);
        let task1 = rt.spawn_with_handle(copy_buf(r1, w1)).unwrap();
        let task2 = rt
            .spawn_with_handle(async move {
                let copy_result = copy_buf(r2, &mut w2).await;
                (copy_result, w2)
            })
            .unwrap();

        let copy_result_1 = task1.await;
        let (copy_result_2, output) = task2.await;

        assert_eq!(
            copy_result_1.unwrap_err().kind(),
            io::ErrorKind::ResourceBusy
        );
        assert_eq!(copy_result_2.unwrap(), data.len() as u64);
        assert_eq!(&output.into_inner()[..], data);
    }

    fn test_copy(data: &[u8]) {
        MockRuntime::test_with_various(async |rt| {
            test_copy_cursor(data).await;
            test_copy_stream(&rt, data).await;
            test_copy_stream_paused(&rt, data).await;
            test_copy_stream_error(&rt, data).await;
        });
    }

    #[test]
    fn copy_nothing() {
        test_copy(&[]);
    }

    #[test]
    fn copy_small() {
        test_copy(b"hEllo world");
    }

    #[test]
    fn copy_huge() {
        let huge: Vec<u8> = (0..=77).cycle().take(1_500_000).collect();
        test_copy(&huge[..]);
    }
}
