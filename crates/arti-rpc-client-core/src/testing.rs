//! Functions to help test this crate.

use std::io;

use crate::nb_stream::MioStream;

/// The type of blocking stream returned by `construct_socketpair`.
#[cfg(not(windows))]
pub(crate) type SocketpairStream = socketpair::SocketpairStream;
#[cfg(windows)]
pub(crate) type SocketpairStream = std::net::TcpStream;

/// Test helper: construct a socketpair.
fn construct_socketpair_inner() -> io::Result<(SocketpairStream, SocketpairStream)> {
    #[cfg(not(windows))]
    {
        socketpair::socketpair_stream()
    }
    #[cfg(windows)]
    {
        // Alas, we can't use the socketpair crate on Windows!  It creates a Windows
        // "named pipe".  Windows "named pipe"s are not named pipes.  They are strange
        // things which a bit like an unholy cross between a Unix named pipe (aka a FIFO)
        // and an AF_UNIX socket.  This makes them bizarre and awkward.  They are best
        // avoided if possible.
        //
        // We have to use this nonsense instead.  It will cause these tests to fail on
        // some absurdly restrictive windows firewalls; that's a price we can afford.
        //
        // For details see
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2758#note_3155460
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let s1 = std::net::TcpStream::connect(addr)?;
        let (s2, s2_addr) = listener.accept()?;
        assert_eq!(s1.local_addr().unwrap(), s2_addr);
        Ok((s1, s2))
    }
}

/// Test helper: Construct a socketpair,
/// wrapping the first element in a MIO wrapper and making it nonblocking.
pub(crate) fn construct_socketpair() -> io::Result<(Box<dyn MioStream>, SocketpairStream)> {
    let (s1, s2) = construct_socketpair_inner()?;

    #[cfg(not(windows))]
    let s1 = {
        use std::os::fd::OwnedFd;

        let owned_fd = OwnedFd::from(s1);
        std::os::unix::net::UnixStream::from(owned_fd)
    };

    s1.set_nonblocking(true)?;

    #[cfg(not(windows))]
    let s1 = mio::net::UnixStream::from_std(s1);
    #[cfg(windows)]
    let s1 = mio::net::TcpStream::from_std(s1);

    Ok((Box::new(s1), s2))
}
