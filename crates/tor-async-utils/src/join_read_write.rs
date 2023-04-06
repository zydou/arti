//! Join a readable and writeable into a single `AsyncRead` + `AsyncWrite`

use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{AsyncRead, AsyncWrite};
use pin_project::pin_project;

/// Async readable/writeable that dispatches reads to `R` and writes to `W`
///
/// `AsyncRead` is forwarded to `R`.
/// `AsyncWrite` is forwarded to `W`.
///
/// [`JoinReadWrite::new()`] is the converse of
/// [`AsyncReadExt::split()`](futures::AsyncReadExt::split).
/// But, if `R` and `W` came from splitting a single `AsyncRead + AsyncWrite`,
/// you probably want the `reunite` or `unsplit` method, instead of `JoinReadWrite`.
///
/// Does *not* implement any kind of flushing behaviour when switching between reading and writing.
///
/// # Example
///
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// use tor_async_utils::JoinReadWrite;
/// use futures::{AsyncReadExt as _, AsyncWriteExt as _};
///
/// let read = b"hello\n";
/// let mut read = &read[..];
/// let mut write = Vec::<u8>::new();
///
/// let mut joined = JoinReadWrite::new(read, write);
///
/// let mut got = String::new();
/// let _: usize = joined.read_to_string(&mut got).await.unwrap();
/// assert_eq!(got, "hello\n");
///
/// let () = joined.write_all(b"some data").await.unwrap();
///
/// let (r, w) = joined.into_parts();
/// assert_eq!(w, b"some data");
/// # }
/// ```
#[pin_project]
pub struct JoinReadWrite<R: AsyncRead, W: AsyncWrite> {
    /// readable
    #[pin]
    r: R,
    /// writeable
    #[pin]
    w: W,
}

impl<R: AsyncRead, W: AsyncWrite> JoinReadWrite<R, W> {
    /// Join an `AsyncRead` and an `AsyncWrite` into a single `impl AsyncRead + AsyncWrite`
    pub fn new(r: R, w: W) -> Self {
        JoinReadWrite { r, w }
    }

    /// Dismantle a `JoinReadWrite` into its constituent `AsyncRead` and `AsyncWrite`
    pub fn into_parts(self) -> (R, W) {
        let JoinReadWrite { r, w } = self;
        (r, w)
    }
}

impl<R: AsyncRead, W: AsyncWrite> AsyncRead for JoinReadWrite<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        c: &mut Context,
        out: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().r.poll_read(c, out)
    }
}

impl<R: AsyncRead, W: AsyncWrite> AsyncWrite for JoinReadWrite<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        c: &mut Context,
        data: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().w.poll_write(c, data)
    }

    fn poll_flush(self: Pin<&mut Self>, c: &mut Context) -> Poll<Result<(), Error>> {
        self.project().w.poll_flush(c)
    }

    fn poll_close(self: Pin<&mut Self>, c: &mut Context) -> Poll<Result<(), Error>> {
        self.project().w.poll_close(c)
    }
}
