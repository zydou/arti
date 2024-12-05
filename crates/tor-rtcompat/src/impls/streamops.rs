//! Helpers for implementing [`StreamOps`](crate::StreamOps).

use std::io;

#[cfg(target_os = "linux")]
use {std::mem, std::os::fd::AsRawFd};

#[cfg(not(target_os = "linux"))]
use tor_error::bad_api_usage;

/// Helper for implementing [`set_tcp_notsent_lowat`](crate::StreamOps::set_tcp_notsent_lowat).
///
/// Only implemented on Linux. Returns an error on all other platforms.
#[cfg(target_os = "linux")]
pub(crate) fn set_tcp_notsent_lowat<S: AsRawFd>(sock: &S, notsent_lowat: u32) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_NOTSENT_LOWAT,
            &notsent_lowat as *const _ as *const libc::c_void,
            mem::size_of_val(&notsent_lowat) as libc::socklen_t,
        )
    };

    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Helper for implementing [`set_tcp_notsent_lowat`](crate::StreamOps::set_tcp_notsent_lowat).
///
/// Only implemented on Linux. Returns an error on all other platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_tcp_notsent_lowat<S>(sock: &S, notsent_lowat: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        bad_api_usage!("set_tcp_notsent_lowat not supported on non-Linux platforms"),
    ))
}
