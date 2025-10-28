//! Support for defining behavior when encountering an EOF during
//! a bidirectional copy.
//!
//! When performing a bidirectional copy
//! with [`copy_bidirectional`](crate::copy_bidirectional)
//! or [`copy_buf_bidirectional`](crate::copy_buf_bidirectional),
//! it's sometimes the case that one side is done transmitting before the other is.
//! In this case, the caller needs to specify what will happen upon receiving an EOF
//! from each of the two streams.
//!
//! Typically, the caller wants to _propagate_ the EOF from the stream that has
//! given it to the other stream, by calling an operation like
//! [shutdown](std::net::TcpStream::shutdown) or
//! [close](futures::io::AsyncWriteExt::close).
//! But since multiple operations can be appropriate depending on the circumstances,
//! we define a [`EofStrategy`] trait that tells the bidirectional `copy` function
//! how to react.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncWrite, io::BufReader};
use pin_project::pin_project;

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket};

/// Propagate an EOF during a bidirectional copy.
///
/// Each `EofStrategy<W>` implementation responds to an EOF on a reader by
/// doing "something" to a writer of type `W`.
/// It might do this by close the `W`,
/// by doing nothing at all,
/// or by invoking some more type-specific operation.
pub trait EofStrategy<W> {
    /// Try to transmit an EOF to `w`.
    ///
    /// On success, return Ok.  On failure, return an error.
    /// If we must try again, register this task with `cx`,
    /// and return [`Poll::Pending`].
    fn poll_send_eof(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        w: Pin<&mut W>,
    ) -> Poll<io::Result<()>>;
}

/// "Handle" an EOF by doing nothing.
#[derive(Default, Debug, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct Noop;

impl<W> EofStrategy<W> for Noop {
    fn poll_send_eof(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _w: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Handle an EOF by closing the stream.
///
/// Note that using this strategy can result in prematurely closed connections:
/// As soon as one stream reaches EOF, the other one will be closed,
/// even if it still had something to say.
/// For protocols like TCP that support half-open connections,
/// it's better to use [`FdShutdown`] or [`SocketShutdown`] if possible.
#[derive(Default, Debug, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct Close;

impl<W: AsyncWrite> EofStrategy<W> for Close {
    fn poll_send_eof(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        w: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        w.poll_close(cx)
    }
}

/// Handle an EOF by calling the unix `shutdown(2)` function.
///
/// This object uses [`shutdown(2)`] to tell the socket that we are done writing,
/// but not done reading.
///
/// On unix-like systems, this object is generally the best choice for production usage.
/// It works on any time that implements [`AsFd`].
///
/// On Windows, see [`SocketShutdown`].
///
/// # Availability
///
/// This type is only available on unix-like systems.
///
/// [`shutdown(2)`]: https://manpages.debian.org/trixie/finit-sysv/shutdown.8.en.html
#[cfg(any(doc, unix))]
#[derive(Default, Debug, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct FdShutdown;

#[cfg(unix)]
impl<W: AsFd> EofStrategy<W> for FdShutdown {
    fn poll_send_eof(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        w: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        let fd = w.as_fd();
        Poll::Ready(
            match unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR) } {
                -1 => Err(io::Error::last_os_error()),
                _ => Ok(()),
            },
        )
    }
}

/// Handle an EOF by calling the Windows `shutdown` function.
///
/// This object uses [`shutdown`] to tell the socket that we are done writing,
/// but not done reading.
///
/// On unix-like systems, this object is generally the best choice for production usage.
/// It works on any time that implements [`AsSocket`].
///
/// On Unix, see [`FdShutdown`].
///
/// # Availability
///
/// This type is only available on unix-like systems.#[derive(Default, Debug, Clone)]
///
/// [`AsSocket`]: https://doc.rust-lang.org/std/os/windows/io/trait.AsSocket.html
/// [`shutdown`]: https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-shutdown
#[allow(clippy::exhaustive_structs)]
#[cfg(any(doc, windows))]
pub struct SocketShutdown;

#[cfg(windows)]
impl<W: AsSocket> EofStrategy<W> for SocketShutdown {
    fn poll_send_eof(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        w: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        use windows_sys::Win32::Networking::WinSock::{SD_SEND, SOCKET, shutdown};
        let socket = w.as_socket();
        Poll::Ready(
            match unsafe { shutdown(socket.as_raw_socket() as SOCKET, SD_SEND) } {
                -1 => Err(io::Error::last_os_error()),
                _ => Ok(()),
            },
        )
    }
}

/// Internal helper: Wrap a `EofStrategy<W>` to implement `EofStrategy<BufReader<W>>`.
#[derive(Default, Debug, Clone)]
#[pin_project]
pub(crate) struct BufReaderEofWrapper<E>(#[pin] pub(crate) E);

impl<W, E: EofStrategy<W>> EofStrategy<BufReader<W>> for BufReaderEofWrapper<E> {
    fn poll_send_eof(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        w: Pin<&mut BufReader<W>>,
    ) -> Poll<io::Result<()>> {
        self.project().0.poll_send_eof(cx, w.get_pin_mut())
    }
}
