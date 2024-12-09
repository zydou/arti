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

#[cfg(test)]
mod tests {
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
    use std::net::TcpListener;

    #[cfg(target_os = "linux")]
    pub(crate) fn get_tcp_notsent_lowat<S: AsRawFd>(sock: &S) -> io::Result<u32> {
        let fd = sock.as_raw_fd();
        let mut notsent_lowat = 0;
        let mut socklen: u32 = mem::size_of_val(&notsent_lowat) as libc::socklen_t;
        let res = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_NOTSENT_LOWAT,
                &mut notsent_lowat as *mut _ as *mut libc::c_void,
                &mut socklen as *mut _,
            )
        };

        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(notsent_lowat)
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore)] // sockets are unsupported https://github.com/rust-lang/miri/issues/3449
    fn tcp_notsent_lowat() {
        let sock = TcpListener::bind("127.0.0.1:0").unwrap();
        set_tcp_notsent_lowat(&sock, 1337).unwrap();
        let notsent_lowat = get_tcp_notsent_lowat(&sock).unwrap();
        assert_eq!(1337, notsent_lowat);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    #[cfg_attr(miri, ignore)] // sockets are unsupported https://github.com/rust-lang/miri/issues/3449
    fn tcp_notsent_lowat() {
        let sock = TcpListener::bind("127.0.0.1:0").unwrap();
        // Currently not supported on non-linux platforms
        assert!(set_tcp_notsent_lowat(&sock, 1337).is_err());
    }
}
