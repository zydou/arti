//! Low-level connection implementations.
//!
//! This module defines two main types: [`NonblockingConnection`].
//! (a low-level type for use with external tools
//! that want to implement their own nonblocking IO),
//! and [`BlockingConnection`] (a slightly higher-level type
//! that we use internally when we are asked to provide
//! our own nonblocking IO loop(s)).
//!
//! This module also defines several traits for use by these types.
//!
//! Treats messages as unrelated strings, and validates outgoing messages for correctness.

mod blocking;
mod nonblocking;

use std::io;

#[cfg(unix)]
use std::os::fd::{AsFd as _, BorrowedFd as BorrowedOsHandle};
#[cfg(windows)]
use std::os::windows::io::{AsSocket as _, BorrowedSocket as BorrowedOsHandle};

pub(crate) use blocking::BlockingConnection;
pub(crate) use nonblocking::{NonblockingConnection, PollStatus, WriteHandle};

pub use nonblocking::{EventLoop, SendRequestError};

/// Retry `f` until it returns Ok() or an error whose kind is not `Interrupted`
fn retry_eintr<F, T>(mut f: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    loop {
        let r = f();
        match r {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return r,
        }
    }
}

/// Any type we can use as a target for [`NonblockingConnection`].
pub(crate) trait Stream: io::Read + io::Write + Send {
    /// If this Stream object is a [`MioStream`], return it as a `mio::event::Source`.
    ///
    /// Otherwise return None.
    fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source>;

    /// Discard any mio-specific wrappers on this stream.
    fn remove_mio(self: Box<Self>) -> Box<dyn Stream>;

    /// Return an os-specific handle for using this stream type within a nonblocking event loop.
    ///
    /// (This will be an fd on unix and a SOCKET on windows.)
    fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>>;
}

/// A [`Stream`] that we can use inside a [`BlockingConnection`].
pub(crate) trait MioStream: Stream + mio::event::Source {}

/// Implement Stream and MioStream for a related pair of types.
macro_rules! impl_traits {
    { $stream:ty => $mio_stream:ty } => {
        impl Stream for $stream {
            fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source> {
                None
            }
            fn remove_mio(self: Box<Self>) -> Box<dyn Stream> {
                self
            }
            fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>> {
                cfg_if::cfg_if!{
                    if #[cfg(unix)] {
                        Ok(self.as_fd())
                    } else if #[cfg(windows)] {
                        Ok(self.as_socket())
                    }
                }
            }
        }
        impl Stream for $mio_stream {
            fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source> {
                Some(self as _)
            }
            fn remove_mio(self: Box<Self>) -> Box<dyn Stream> {
                Box::new(<$stream>::from(*self))
            }
            fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>> {
                cfg_if::cfg_if!{
                    if #[cfg(unix)] {
                        Ok(self.as_fd())
                    } else if #[cfg(windows)] {
                        Ok(self.as_socket())
                    }
                }
            }
        }
        impl MioStream for $mio_stream {
        }
    }
}

impl_traits! { std::net::TcpStream => mio::net::TcpStream }
#[cfg(unix)]
impl_traits! { std::os::unix::net::UnixStream => mio::net::UnixStream }

// We implement "Stream" for Empty so that we can use it to temporarily swap it in
// as a placeholder for a Box<dyn Stream>.
impl Stream for std::io::Empty {
    fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source> {
        None
    }

    fn remove_mio(self: Box<Self>) -> Box<dyn Stream> {
        self
    }

    fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
