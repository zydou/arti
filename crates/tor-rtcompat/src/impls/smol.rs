//! Re-exports of the smol runtime for use with arti.
//! This crate defines a slim API around our async runtime so that we
//! can swap it out easily.

/// Types used for networking (smol implementation).
pub(crate) mod net {
    use super::SmolRuntime;
    use crate::network::{TcpConnectOptions, TcpListenOptions};
    #[cfg(unix)]
    use crate::network::{UnixConnectOptions, UnixListenOptions};
    use crate::{impls, traits};
    use async_trait::async_trait;
    use futures::stream::{self, Stream};
    use paste::paste;
    use smol::Async;
    #[cfg(unix)]
    use smol::net::unix::{UnixListener, UnixStream};
    use smol::net::{TcpListener, TcpStream, UdpSocket as SmolUdpSocket};
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tor_general_addr::unix;
    use tracing::instrument;

    /// Provide wrapper for different stream types
    /// (e.g async_net::TcpStream and async_net::unix::UnixStream).
    macro_rules! impl_stream {
        { $kind:ident, $addr:ty } => { paste! {

            /// A `Stream` of incoming streams.
            pub struct [<Incoming $kind Streams>] {
                /// Underlying stream of incoming connections.
                inner: Pin<Box<dyn Stream<Item = IoResult<([<$kind Stream>], $addr)>> + Send + Sync>>,
            }

            impl [<Incoming $kind Streams>] {
                /// Create a new `Incoming*Streams` from a listener.
                pub fn from_listener(lis: [<$kind Listener>]) -> Self {
                    let stream = stream::unfold(lis, |lis| async move {
                        let result = lis.accept().await;
                        Some((result, lis))
                    });
                    Self {
                        inner: Box::pin(stream),
                    }
                }
            }

            impl Stream for [<Incoming $kind Streams>] {
                type Item = IoResult<([<$kind Stream>], $addr)>;

                fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
                    self.inner.as_mut().poll_next(cx)
                }
            }

            impl traits::NetStreamListener<$addr> for [<$kind Listener>] {
                type Stream = [<$kind Stream>];
                type Incoming = [<Incoming $kind Streams>];

                fn incoming(self) -> Self::Incoming {
                    [<Incoming $kind Streams>]::from_listener(self)
                }

                fn local_addr(&self) -> IoResult<$addr> {
                    [<$kind Listener>]::local_addr(self)
                }
            }
        }}
    }

    impl_stream! { Tcp, SocketAddr }
    #[cfg(unix)]
    impl_stream! { Unix, unix::SocketAddr }

    #[async_trait]
    impl traits::NetStreamProvider<SocketAddr> for SmolRuntime {
        type Stream = TcpStream;
        type Listener = TcpListener;
        type ConnectOptions = TcpConnectOptions;
        type ListenOptions = TcpListenOptions;

        #[instrument(skip_all, level = "trace")]
        async fn connect(
            &self,
            addr: &SocketAddr,
            options: &Self::ConnectOptions,
        ) -> IoResult<Self::Stream> {
            // The smol runtime uses async-io internally.
            let stream = impls::tcp_async_io_connect(addr, options).await?;

            // The socket is already non-blocking,
            // so `Async` doesn't need to set as non-blocking again.
            Ok(Async::new_nonblocking(stream)?.into())
        }

        async fn listen(
            &self,
            addr: &SocketAddr,
            options: &Self::ListenOptions,
        ) -> IoResult<Self::Listener> {
            // Use an implementation that's the same across all runtimes.
            // The socket is already non-blocking, so `Async` doesn't need to set as non-blocking
            // again. If it *were* to be blocking, then I/O operations would block in async
            // contexts, which would lead to deadlocks.
            Ok(Async::new_nonblocking(impls::tcp_listen(addr, options)?)?.into())
        }
    }

    #[cfg(unix)]
    #[async_trait]
    impl traits::NetStreamProvider<unix::SocketAddr> for SmolRuntime {
        type Stream = UnixStream;
        type Listener = UnixListener;
        type ConnectOptions = UnixConnectOptions;
        type ListenOptions = UnixListenOptions;

        #[instrument(skip_all, level = "trace")]
        async fn connect(
            &self,
            addr: &unix::SocketAddr,
            options: &Self::ConnectOptions,
        ) -> IoResult<Self::Stream> {
            // Will fail to compile if we add options without handling them here.
            let UnixConnectOptions {} = options;

            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedAfUnixAddressType)?;
            UnixStream::connect(path).await
        }

        async fn listen(
            &self,
            addr: &unix::SocketAddr,
            options: &Self::ListenOptions,
        ) -> IoResult<Self::Listener> {
            // Will fail to compile if we add options without handling them here.
            let UnixListenOptions {} = options;

            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedAfUnixAddressType)?;
            UnixListener::bind(path)
        }
    }

    #[cfg(not(unix))]
    crate::impls::impl_unix_non_provider! { SmolRuntime }

    #[async_trait]
    impl traits::UdpProvider for SmolRuntime {
        type UdpSocket = UdpSocket;

        async fn bind(&self, addr: &SocketAddr) -> IoResult<Self::UdpSocket> {
            SmolUdpSocket::bind(addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
    }

    /// Wrapper for `SmolUdpSocket`.
    // Required to implement `traits::UdpSocket`.
    pub struct UdpSocket {
        /// The underlying socket.
        socket: SmolUdpSocket,
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
        fn set_tcp_notsent_lowat(&self, lowat: u32) -> IoResult<()> {
            impls::streamops::set_tcp_notsent_lowat(self, lowat)
        }

        #[cfg(target_os = "linux")]
        fn new_handle(&self) -> Box<dyn traits::StreamOps + Send + Unpin> {
            Box::new(impls::streamops::TcpSockFd::from_fd(self))
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

use crate::join_set::FuturesJoinSet;
use crate::traits::*;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::{Future, FutureExt};
use std::pin::Pin;
use std::time::Duration;

/// Type to wrap `smol::Executor`.
#[derive(Clone)]
pub struct SmolRuntime {
    /// Instance of the smol executor we own.
    executor: std::sync::Arc<smol::Executor<'static>>,
}

/// Construct new instance of the smol runtime.
//
// TODO: Make SmolRuntime multi-threaded.
pub fn create_runtime() -> SmolRuntime {
    SmolRuntime {
        executor: std::sync::Arc::new(smol::Executor::new()),
    }
}

impl SleepProvider for SmolRuntime {
    type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        Box::pin(async_io::Timer::after(duration).map(|_| ()))
    }
}

impl ToplevelBlockOn for SmolRuntime {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        smol::block_on(self.executor.run(f))
    }
}

impl Blocking for SmolRuntime {
    type ThreadHandle<T: Send + 'static> = blocking::Task<T>;

    fn spawn_blocking<F, T>(&self, f: F) -> blocking::Task<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        smol::unblock(f)
    }

    fn reenter_block_on<F: Future>(&self, f: F) -> F::Output {
        smol::block_on(self.executor.run(f))
    }
}

impl Spawn for SmolRuntime {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        self.executor.spawn(future).detach();
        Ok(())
    }
}

impl JoinSetProvider for SmolRuntime {
    type JoinSet<T: Send + Sync + 'static> = FuturesJoinSet<T, Self>;

    fn new_join_set<T>(&self) -> Self::JoinSet<T>
    where
        T: Send + Sync + 'static,
    {
        FuturesJoinSet::new(self.clone())
    }
}
