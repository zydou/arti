//! Re-exports of the tokio runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.

/// Types used for networking (tokio implementation)
pub(crate) mod net {
    use crate::traits;
    use async_trait::async_trait;

    pub(crate) use tokio_crate::net::{
        TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
    };

    use futures::io::{AsyncRead, AsyncWrite};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Provide a set of network stream wrappers for a single stream type.
    macro_rules! stream_impl {
        {} => {
            /// Wrapper for Tokio's TcpStream that implements the standard
            /// AsyncRead and AsyncWrite.
            pub struct TcpStream {
                /// Underlying tokio_util::compat::Compat wrapper.
                s: Compat<TokioTcpStream>,
            }
            impl From<TokioTcpStream> for TcpStream {
                fn from(s: TokioTcpStream) -> TcpStream {
                    let s = s.compat();
                    TcpStream { s }
                }
            }
            impl AsyncRead for TcpStream {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<IoResult<usize>> {
                    Pin::new(&mut self.s).poll_read(cx, buf)
                }
            }
            impl AsyncWrite for TcpStream {
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

            /// Wrap a Tokio TcpListener to behave as a futures::io::TcpListener.
            pub struct TcpListener {
                /// The underlying listener.
                pub(super) lis: TokioTcpListener,
            }

            /// Asynchronous stream that yields incoming connections from a
            /// TcpListener.
            ///
            /// This is analogous to async_std::net::Incoming.
            pub struct IncomingTcpStreams {
                /// Reference to the underlying listener.
                pub(super) lis: TokioTcpListener,
            }

            impl futures::stream::Stream for IncomingTcpStreams {
                type Item = IoResult<(TcpStream, SocketAddr)>;

                fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                    match self.lis.poll_accept(cx) {
                        Poll::Ready(Ok((s, a))) => Poll::Ready(Some(Ok((s.into(), a)))),
                        Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                        Poll::Pending => Poll::Pending,
                    }
                }
            }
            #[async_trait]
            impl traits::NetStreamListener for TcpListener {
                type Stream = TcpStream;
                type Incoming = IncomingTcpStreams;
                fn incoming(self) -> Self::Incoming {
                    IncomingTcpStreams { lis: self.lis }
                }
                fn local_addr(&self) -> IoResult<SocketAddr> {
                    self.lis.local_addr()
                }
            }
        }
    }

    stream_impl! {}

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
}

// ==============================

use crate::traits::*;
use async_trait::async_trait;
use futures::Future;
use std::io::Result as IoResult;
use std::time::Duration;

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
