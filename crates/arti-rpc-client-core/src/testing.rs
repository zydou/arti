//! Functions to help test this crate.

use std::io;

/// The type of stream returned by `construct_socketpair`.
#[cfg(not(windows))]
pub(crate) type SocketpairStream = socketpair::SocketpairStream;
#[cfg(windows)]
pub(crate) type SocketpairStream = std::net::TcpStream;

/// Test helper: construct a socketpair.
pub(crate) fn construct_socketpair() -> io::Result<(SocketpairStream, SocketpairStream)> {
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
