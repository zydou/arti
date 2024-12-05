//! Mocking helpers for testing with futures::io types.
//!
//! Note that some of this code might be of general use, but for now
//! we're only trying it for testing.

#![forbid(unsafe_code)] // if you remove this, enable (or write) miri tests (git grep miri)

use crate::util::mpsc_channel;
use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use futures::sink::{Sink, SinkExt};
use futures::stream::Stream;
use std::io::{self, Error as IoError, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};
use tor_error::bad_api_usage;
use tor_rtcompat::StreamOps;

/// Channel capacity for our internal MPSC channels.
///
/// We keep this intentionally low to make sure that some blocking
/// will occur occur.
const CAPACITY: usize = 4;

/// Maximum size for a queued buffer on a local chunk.
///
/// This size is deliberately weird, to try to find errors.
const CHUNKSZ: usize = 213;

/// Construct a new pair of linked LocalStream objects.
///
/// Any bytes written to one will be readable on the other, and vice
/// versa.  These streams will behave more or less like a socketpair,
/// except without actually going through the operating system.
///
/// Note that this implementation is intended for testing only, and
/// isn't optimized.
pub fn stream_pair() -> (LocalStream, LocalStream) {
    let (w1, r2) = mpsc_channel(CAPACITY);
    let (w2, r1) = mpsc_channel(CAPACITY);
    let s1 = LocalStream {
        w: w1,
        r: r1,
        pending_bytes: Vec::new(),
        tls_cert: None,
    };
    let s2 = LocalStream {
        w: w2,
        r: r2,
        pending_bytes: Vec::new(),
        tls_cert: None,
    };
    (s1, s2)
}

/// One half of a pair of linked streams returned by [`stream_pair`].
//
// Implementation notes: linked streams are made out a pair of mpsc
// channels.  There's one channel for sending bytes in each direction.
// Bytes are sent as IoResult<Vec<u8>>: sending an error causes an error
// to occur on the other side.
pub struct LocalStream {
    /// The writing side of the channel that we use to implement this
    /// stream.
    ///
    /// The reading side is held by the other linked stream.
    w: mpsc::Sender<IoResult<Vec<u8>>>,
    /// The reading side of the channel that we use to implement this
    /// stream.
    ///
    /// The writing side is held by the other linked stream.
    r: mpsc::Receiver<IoResult<Vec<u8>>>,
    /// Bytes that we have read from `r` but not yet delivered.
    pending_bytes: Vec<u8>,
    /// Data about the other side of this stream's fake TLS certificate, if any.
    /// If this is present, I/O operations will fail with an error.
    ///
    /// How this is intended to work: things that return `LocalStream`s that could potentially
    /// be connected to a fake TLS listener should set this field. Then, a fake TLS wrapper
    /// type would clear this field (after checking its contents are as expected).
    ///
    /// FIXME(eta): this is a bit of a layering violation, but it's hard to do otherwise
    pub(crate) tls_cert: Option<Vec<u8>>,
}

/// Helper: pull bytes off the front of `pending_bytes` and put them
/// onto `buf.  Return the number of bytes moved.
fn drain_helper(buf: &mut [u8], pending_bytes: &mut Vec<u8>) -> usize {
    let n_to_drain = std::cmp::min(buf.len(), pending_bytes.len());
    buf[..n_to_drain].copy_from_slice(&pending_bytes[..n_to_drain]);
    pending_bytes.drain(..n_to_drain);
    n_to_drain
}

impl AsyncRead for LocalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.tls_cert.is_some() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "attempted to treat a TLS stream as non-TLS!",
            )));
        }
        if !self.pending_bytes.is_empty() {
            return Poll::Ready(Ok(drain_helper(buf, &mut self.pending_bytes)));
        }

        match futures::ready!(Pin::new(&mut self.r).poll_next(cx)) {
            Some(Err(e)) => Poll::Ready(Err(e)),
            Some(Ok(bytes)) => {
                self.pending_bytes = bytes;
                let n = drain_helper(buf, &mut self.pending_bytes);
                Poll::Ready(Ok(n))
            }
            None => Poll::Ready(Ok(0)), // This is an EOF
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if self.tls_cert.is_some() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "attempted to treat a TLS stream as non-TLS!",
            )));
        }

        match futures::ready!(Pin::new(&mut self.w).poll_ready(cx)) {
            Ok(()) => (),
            Err(e) => return Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, e))),
        }

        let buf = if buf.len() > CHUNKSZ {
            &buf[..CHUNKSZ]
        } else {
            buf
        };
        let len = buf.len();
        match Pin::new(&mut self.w).start_send(Ok(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(e) => Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, e))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.w)
            .poll_flush(cx)
            .map_err(|e| IoError::new(ErrorKind::BrokenPipe, e))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.w)
            .poll_close(cx)
            .map_err(|e| IoError::new(ErrorKind::Other, e))
    }
}

impl StreamOps for LocalStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            bad_api_usage!("set_tcp_notsent_lowat not supported on local streams"),
        ))
    }
}

/// An error generated by [`LocalStream::send_err`].
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct SyntheticError;
impl std::error::Error for SyntheticError {}
impl std::fmt::Display for SyntheticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Synthetic error")
    }
}

impl LocalStream {
    /// Send an error to the other linked local stream.
    ///
    /// When the other stream reads this message, it will generate a
    /// [`std::io::Error`] with the provided `ErrorKind`.
    pub async fn send_err(&mut self, kind: ErrorKind) {
        let _ignore = self.w.send(Err(IoError::new(kind, SyntheticError))).await;
    }
}

#[cfg(all(test, not(miri)))] // These tests are very slow under miri
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

    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures_await_test::async_test;
    use rand::Rng;
    use tor_basic_utils::test_rng::testing_rng;

    #[async_test]
    async fn basic_rw() {
        let (mut s1, mut s2) = stream_pair();
        let mut text1 = vec![0_u8; 9999];
        testing_rng().fill(&mut text1[..]);

        let (v1, v2): (IoResult<()>, IoResult<()>) = futures::join!(
            async {
                for _ in 0_u8..10 {
                    s1.write_all(&text1[..]).await?;
                }
                s1.close().await?;
                Ok(())
            },
            async {
                let mut text2: Vec<u8> = Vec::new();
                let mut buf = [0_u8; 33];
                loop {
                    let n = s2.read(&mut buf[..]).await?;
                    if n == 0 {
                        break;
                    }
                    text2.extend(&buf[..n]);
                }
                for ch in text2[..].chunks(text1.len()) {
                    assert_eq!(ch, &text1[..]);
                }
                Ok(())
            }
        );

        v1.unwrap();
        v2.unwrap();
    }

    #[async_test]
    async fn send_error() {
        let (mut s1, mut s2) = stream_pair();

        let (v1, v2): (IoResult<()>, IoResult<()>) = futures::join!(
            async {
                s1.write_all(b"hello world").await?;
                s1.send_err(ErrorKind::PermissionDenied).await;
                Ok(())
            },
            async {
                let mut buf = [0_u8; 33];
                loop {
                    let n = s2.read(&mut buf[..]).await?;
                    if n == 0 {
                        break;
                    }
                }
                Ok(())
            }
        );

        v1.unwrap();
        let e = v2.err().unwrap();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        let synth = e.into_inner().unwrap();
        assert_eq!(synth.to_string(), "Synthetic error");
    }

    #[async_test]
    async fn drop_reader() {
        let (mut s1, s2) = stream_pair();

        let (v1, v2): (IoResult<()>, IoResult<()>) = futures::join!(
            async {
                for _ in 0_u16..1000 {
                    s1.write_all(&[9_u8; 9999]).await?;
                }
                Ok(())
            },
            async {
                drop(s2);
                Ok(())
            }
        );

        v2.unwrap();
        let e = v1.err().unwrap();
        assert_eq!(e.kind(), ErrorKind::BrokenPipe);
    }
}
