//! Re-exports of the tokio runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Types used for networking (tokio implementation)
pub(crate) mod net {
    use crate::{impls, traits};
    use async_trait::async_trait;
    use tor_general_addr::unix;

    pub(crate) use tokio_crate::net::{
        TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
    };
    #[cfg(unix)]
    pub(crate) use tokio_crate::net::{
        UnixListener as TokioUnixListener, UnixStream as TokioUnixStream,
    };

    use futures::io::{AsyncRead, AsyncWrite};
    use paste::paste;
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Provide a set of network stream wrappers for a single stream type.
    macro_rules! stream_impl {
        {
            $kind:ident,
            $addr:ty,
            $cvt_addr:ident
        } => {paste!{
            /// Wrapper for Tokio's
            #[doc = stringify!($kind)]
            /// streams,
            /// that implements the standard
            /// AsyncRead and AsyncWrite.
            pub struct [<$kind Stream>] {
                /// Underlying tokio_util::compat::Compat wrapper.
                s: Compat<[<Tokio $kind Stream>]>,
            }
            impl From<[<Tokio $kind Stream>]> for [<$kind Stream>] {
                fn from(s: [<Tokio $kind Stream>]) ->  [<$kind Stream>] {
                    let s = s.compat();
                    [<$kind Stream>] { s }
                }
            }
            impl AsyncRead for  [<$kind Stream>] {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<IoResult<usize>> {
                    Pin::new(&mut self.s).poll_read(cx, buf)
                }
            }
            impl AsyncWrite for  [<$kind Stream>] {
                fn poll_write(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<IoResult<usize>> {
                    Pin::new(&mut self.s).poll_write(cx, buf)
                }
                fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
                    Pin::new(&mut self.s).poll_flush(cx)
                }
                fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
                    Pin::new(&mut self.s).poll_close(cx)
                }
            }

            /// Wrap a Tokio
            #[doc = stringify!($kind)]
            /// Listener to behave as a futures::io::TcpListener.
            pub struct [<$kind Listener>] {
                /// The underlying listener.
                pub(super) lis: [<Tokio $kind Listener>],
            }

            /// Asynchronous stream that yields incoming connections from a
            #[doc = stringify!($kind)]
            /// Listener.
            ///
            /// This is analogous to async_std::net::Incoming.
            pub struct [<Incoming $kind Streams>] {
                /// Reference to the underlying listener.
                pub(super) lis: [<Tokio $kind Listener>],
            }

            impl futures::stream::Stream for [<Incoming $kind Streams>] {
                type Item = IoResult<([<$kind Stream>], $addr)>;

                fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                    match self.lis.poll_accept(cx) {
                        Poll::Ready(Ok((s, a))) => Poll::Ready(Some(Ok((s.into(), $cvt_addr(a)? )))),
                        Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                        Poll::Pending => Poll::Pending,
                    }
                }
            }
            impl traits::NetStreamListener<$addr> for [<$kind Listener>] {
                type Stream = [<$kind Stream>];
                type Incoming = [<Incoming $kind Streams>];
                fn incoming(self) -> Self::Incoming {
                    [<Incoming $kind Streams>] { lis: self.lis }
                }
                fn local_addr(&self) -> IoResult<$addr> {
                    $cvt_addr(self.lis.local_addr()?)
                }
            }
        }}
    }

    /// Try to convert a tokio unix SocketAddr into a crate::SocketAddr.
    ///
    /// Frustratingly, this information is _right there_: Tokio's SocketAddr has a
    /// std::unix::net::SocketAddr internally, but there appears to be no way to get it out.
    #[cfg(unix)]
    #[allow(clippy::needless_pass_by_value)]
    fn try_cvt_tokio_unix_addr(
        addr: tokio_crate::net::unix::SocketAddr,
    ) -> IoResult<unix::SocketAddr> {
        if addr.is_unnamed() {
            crate::unix::new_unnamed_socketaddr()
        } else if let Some(p) = addr.as_pathname() {
            unix::SocketAddr::from_pathname(p)
        } else {
            Err(crate::unix::UnsupportedUnixAddressType.into())
        }
    }

    /// Wrapper for (not) converting std::net::SocketAddr to itself.
    #[allow(clippy::unnecessary_wraps)]
    fn identity_fn_socketaddr(addr: std::net::SocketAddr) -> IoResult<std::net::SocketAddr> {
        Ok(addr)
    }

    stream_impl! { Tcp, std::net::SocketAddr, identity_fn_socketaddr }
    #[cfg(unix)]
    stream_impl! { Unix, unix::SocketAddr, try_cvt_tokio_unix_addr }

    /// Wrap a Tokio UdpSocket
    pub struct UdpSocket {
        /// The underelying UdpSocket
        socket: TokioUdpSocket,
    }

    impl UdpSocket {
        /// Bind a UdpSocket
        pub async fn bind(addr: SocketAddr) -> IoResult<Self> {
            TokioUdpSocket::bind(addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
    }

    #[async_trait]
    impl traits::UdpSocket for UdpSocket {
        async fn recv(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
            self.socket.recv_from(buf).await
        }

        async fn send(&self, buf: &[u8], target: &SocketAddr) -> IoResult<usize> {
            self.socket.send_to(buf, target).await
        }

        fn local_addr(&self) -> IoResult<SocketAddr> {
            self.socket.local_addr()
        }
    }

    impl traits::StreamOps for TcpStream {
        fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
            impls::streamops::set_tcp_notsent_lowat(&self.s, notsent_lowat)
        }
    }

    #[cfg(unix)]
    impl traits::StreamOps for UnixStream {
        fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
            Err(traits::UnsupportedStreamOp::new(
                "set_tcp_notsent_lowat",
                "unsupported on Unix streams",
            )
            .into())
        }
    }
}

// ==============================

use crate::traits::*;
use async_trait::async_trait;
use futures::Future;
use std::io::Result as IoResult;
use std::time::Duration;
use tor_general_addr::unix;

impl SleepProvider for TokioRuntimeHandle {
    type SleepFuture = tokio_crate::time::Sleep;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        tokio_crate::time::sleep(duration)
    }
}

#[async_trait]
impl crate::traits::NetStreamProvider for TokioRuntimeHandle {
    type Stream = net::TcpStream;
    type Listener = net::TcpListener;

    async fn connect(&self, addr: &std::net::SocketAddr) -> IoResult<Self::Stream> {
        let s = net::TokioTcpStream::connect(addr).await?;
        Ok(s.into())
    }
    async fn listen(&self, addr: &std::net::SocketAddr) -> IoResult<Self::Listener> {
        let lis = net::TokioTcpListener::bind(*addr).await?;
        Ok(net::TcpListener { lis })
    }
}

#[cfg(unix)]
#[async_trait]
impl crate::traits::NetStreamProvider<unix::SocketAddr> for TokioRuntimeHandle {
    type Stream = net::UnixStream;
    type Listener = net::UnixListener;

    async fn connect(&self, addr: &unix::SocketAddr) -> IoResult<Self::Stream> {
        let path = addr
            .as_pathname()
            .ok_or(crate::unix::UnsupportedUnixAddressType)?;
        let s = net::TokioUnixStream::connect(path).await?;
        Ok(s.into())
    }
    async fn listen(&self, addr: &unix::SocketAddr) -> IoResult<Self::Listener> {
        let path = addr
            .as_pathname()
            .ok_or(crate::unix::UnsupportedUnixAddressType)?;
        let lis = net::TokioUnixListener::bind(path)?;
        Ok(net::UnixListener { lis })
    }
}

#[cfg(not(unix))]
crate::impls::impl_unix_non_provider! { TokioRuntimeHandle }

#[async_trait]
impl crate::traits::UdpProvider for TokioRuntimeHandle {
    type UdpSocket = net::UdpSocket;

    async fn bind(&self, addr: &std::net::SocketAddr) -> IoResult<Self::UdpSocket> {
        net::UdpSocket::bind(*addr).await
    }
}

/// Create and return a new Tokio multithreaded runtime.
pub(crate) fn create_runtime() -> IoResult<TokioRuntimeHandle> {
    let runtime = async_executors::exec::TokioTp::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(runtime.into())
}

/// Wrapper around a Handle to a tokio runtime.
///
/// Ideally, this type would go away, and we would just use
/// `tokio::runtime::Handle` directly.  Unfortunately, we can't implement
/// `futures::Spawn` on it ourselves because of Rust's orphan rules, so we need
/// to define a new type here.
///
/// # Limitations
///
/// Note that Arti requires that the runtime should have working implementations
/// for Tokio's time, net, and io facilities, but we have no good way to check
/// that when creating this object.
#[derive(Clone, Debug)]
pub struct TokioRuntimeHandle {
    /// If present, the tokio executor that we've created (and which we own).
    ///
    /// We never access this directly; only through `handle`.  We keep it here
    /// so that our Runtime types can be agnostic about whether they own the
    /// executor.
    owned: Option<async_executors::TokioTp>,
    /// The underlying Handle.
    handle: tokio_crate::runtime::Handle,
}

impl TokioRuntimeHandle {
    /// Wrap a tokio runtime handle into a format that Arti can use.
    ///
    /// # Limitations
    ///
    /// Note that Arti requires that the runtime should have working
    /// implementations for Tokio's time, net, and io facilities, but we have
    /// no good way to check that when creating this object.
    pub(crate) fn new(handle: tokio_crate::runtime::Handle) -> Self {
        handle.into()
    }

    /// Return true if this handle owns the executor that it points to.
    pub fn is_owned(&self) -> bool {
        self.owned.is_some()
    }
}

impl From<tokio_crate::runtime::Handle> for TokioRuntimeHandle {
    fn from(handle: tokio_crate::runtime::Handle) -> Self {
        Self {
            owned: None,
            handle,
        }
    }
}

impl From<async_executors::TokioTp> for TokioRuntimeHandle {
    fn from(owner: async_executors::TokioTp) -> TokioRuntimeHandle {
        let handle = owner.block_on(async { tokio_crate::runtime::Handle::current() });
        Self {
            owned: Some(owner),
            handle,
        }
    }
}

impl BlockOn for TokioRuntimeHandle {
    #[track_caller]
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.handle.block_on(f)
    }
}

impl SpawnBlocking for TokioRuntimeHandle {
    #[track_caller]
    fn spawn_blocking<F, T>(&self, f: F) -> impl Future<Output = T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async_executors::BlockingHandle::tokio(self.handle.spawn_blocking(f))
    }
}

impl futures::task::Spawn for TokioRuntimeHandle {
    #[track_caller]
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> Result<(), futures::task::SpawnError> {
        let join_handle = self.handle.spawn(future);
        drop(join_handle); // this makes the task detached.
        Ok(())
    }
}
