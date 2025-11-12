//! Different implementations of a common async API for use in arti
//!
//! Currently only async_std, tokio and smol are provided.

#[cfg(feature = "async-std")]
pub(crate) mod async_std;

#[cfg(feature = "tokio")]
pub(crate) mod tokio;

#[cfg(feature = "smol")]
pub(crate) mod smol;

#[cfg(feature = "rustls")]
pub(crate) mod rustls;

#[cfg(feature = "native-tls")]
pub(crate) mod native_tls;

pub(crate) mod streamops;

use tor_error::warn_report;

/// Connection backlog size to use for `listen()` calls on IP sockets.
//
// How this was chosen:
//
// 1. The rust standard library uses a backlog of 128 for TCP sockets. This matches `SOMAXCONN` on
//    most systems.
//
// 2. Mio (backend for tokio) previously used 1024. But they recently (confusingly) copied the logic
//    from the standard library's unix socket implementation, which uses different values on
//    different platforms. These values were tuned for unix sockets, so I think we should ignore
//    them and mio's implementation here.
//    https://github.com/tokio-rs/mio/pull/1896
//
// 3. Tor first tries using `INT_MAX`, and if that fails falls back to `SOMAXCONN` (using a global
//    to remember if it did the fallback for future listen() calls; see `tor_listen`).
//
// 4. On supported platforms, if you use a backlog that is too large, the system will supposedly
//    silently cap the value instead of failing.
//
//     Linux:
//     listen(2)
//     > If the backlog argument is greater than the value in /proc/sys/net/core/somaxconn, then it
//     > is silently capped to that value.
//
//     FreeBSD:
//     listen(2)
//     > The sysctl(3) MIB variable kern.ipc.soacceptqueue specifies a hard limit on backlog; if a
//     > value greater than kern.ipc.soacceptqueue or less than zero is specified, backlog is
//     > silently forced to kern.ipc.soacceptqueue.
//
//     OpenBSD:
//     listen(2)
//     > [BUGS] The backlog is currently limited (silently) to the value of the kern.somaxconn
//     > sysctl, which defaults to 128.
//
//     Windows:
//     https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen
//     > The backlog parameter is limited (silently) to a reasonable value as determined by the
//     > underlying service provider. Illegal values are replaced by the nearest legal value.
//
//     Mac OS:
//     Archived listen(2) docs
//     https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/listen.2.html
//     > [BUGS] The backlog is currently limited (silently) to 128.
//
// 5. While the rust APIs take a `u32`, the libc API uses `int`. So we shouldn't use a value larger
//    than `c_int::MAX`.
//
// 6. We should be careful not to set this too large, as supposedly some systems will truncate this to
//    16 bits. So for example a value of `65536` would cause a backlog of 1. But maybe they are just
//    referring to systems where `int` is 16 bits?
//    https://bugs.python.org/issue38699#msg357957
//
// Here we use `u16::MAX`. We assume that this will succeed on all supported platforms. Unlike tor,
// we do not try again with a smaller value since this doesn't seem to be needed on modern systems.
// We can add it if we find that it's needed.
//
// A value of `u16::MAX` is arguably too high, since a smaller value like 4096 would be large enough
// for legitimate traffic, and illegitimate traffic would be better handled by the kernel with
// something like SYN cookies. But it's easier for users to reduce the max using
// `/proc/sys/net/core/somaxconn` than to increase this max by recompiling arti.
const LISTEN_BACKLOG: i32 = u16::MAX as i32;

/// Open a listening TCP socket.
///
/// The socket will be non-blocking, and the socket handle will be close-on-exec/non-inheritable.
/// Other socket options may also be set depending on the socket type and platform.
///
/// Historically we relied on the runtime to create a listening socket, but we need some specific
/// socket options set, and not all runtimes will behave the same. It's better for us to create the
/// socket with the options we need and with consistent behaviour across all runtimes. For example
/// if each runtime were using a different `listen()` backlog size, it might be difficult to debug
/// related issues.
pub(crate) fn tcp_listen(addr: &std::net::SocketAddr) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, Type};

    // `socket2::Socket::new()`:
    // > This function corresponds to `socket(2)` on Unix and `WSASocketW` on Windows.
    // >
    // > On Unix-like systems, the close-on-exec flag is set on the new socket. Additionally, on
    // > Apple platforms `SOCK_NOSIGPIPE` is set. On Windows, the socket is made non-inheritable.
    let socket = match addr {
        std::net::SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, None)?,
        std::net::SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;

            // On `cfg(unix)` systems, set `IPV6_V6ONLY` so that we can bind AF_INET and
            // AF_INET6 sockets to the same port.
            // This is `cfg(unix)` as I'm not sure what the socket option does (if anything) on
            // non-unix platforms.
            #[cfg(unix)]
            if let Err(e) = socket.set_only_v6(true) {
                // If we see this, we should exclude more platforms.
                warn_report!(
                    e,
                    "Failed to set `IPV6_V6ONLY` on `AF_INET6` socket. \
                    Please report this bug at https://gitlab.torproject.org/tpo/core/arti/-/issues",
                );
            }

            socket
        }
    };

    // Below we try to match what a `tokio::net::TcpListener::bind()` would do. This is a bit tricky
    // since tokio documents "Calling TcpListener::bind("127.0.0.1:8080") is equivalent to:" with
    // some provided example code, but this logic actually appears to happen in the mio crate, and
    // doesn't match exactly with tokio's documentation. So here we acknowledge that we likely do
    // deviate from `tokio::net::TcpListener::bind()` a bit.

    socket.set_nonblocking(true)?;

    // The docs for `tokio::net::TcpSocket` say:
    //
    // > // On platforms with Berkeley-derived sockets, this allows to quickly
    // > // rebind a socket, without needing to wait for the OS to clean up the
    // > // previous one.
    // >
    // > // On Windows, this allows rebinding sockets which are actively in use,
    // > // which allows "socket hijacking", so we explicitly don't set it here.
    // > // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
    //
    // This appears to be a comment that tokio copied from mio.
    //
    // So here we only set SO_REUSEADDR for `cfg(unix)` to match tokio.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;

    socket.bind(&(*addr).into())?;

    socket.listen(LISTEN_BACKLOG)?;

    Ok(socket.into())
}

/// Helper: Implement an unreachable NetProvider<unix::SocketAddr> for a given runtime.
#[cfg(not(unix))]
macro_rules! impl_unix_non_provider {
    { $for_type:ty } => {

        #[async_trait]
        impl crate::traits::NetStreamProvider<tor_general_addr::unix::SocketAddr> for $for_type {
            type Stream = crate::unimpl::FakeStream;
            type Listener = crate::unimpl::FakeListener<tor_general_addr::unix::SocketAddr>;
            async fn connect(&self, _a: &tor_general_addr::unix::SocketAddr) -> IoResult<Self::Stream> {
                Err(tor_general_addr::unix::NoAfUnixSocketSupport::default().into())

            }
            async fn listen(&self, _a: &tor_general_addr::unix::SocketAddr) -> IoResult<Self::Listener> {
                Err(tor_general_addr::unix::NoAfUnixSocketSupport::default().into())
            }
        }
    }
}
#[cfg(not(unix))]
pub(crate) use impl_unix_non_provider;
