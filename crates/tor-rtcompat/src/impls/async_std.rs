//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

/// Types used for networking (async_std implementation)
mod net {
    use crate::{impls, traits};

    use async_std_crate::net::{TcpListener, TcpStream, UdpSocket as StdUdpSocket};
    #[cfg(unix)]
    use async_std_crate::os::unix::net::{UnixListener, UnixStream};
    use async_trait::async_trait;
    use futures::future::Future;
    use futures::stream::Stream;
    use paste::paste;
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tor_general_addr::unix;

    /// Implement NetStreamProvider-related functionality for a single address type.
    macro_rules! impl_stream {
        { $kind:ident, $addr:ty } => {paste!{
            /// A `Stream` of incoming streams.
            ///
            /// Differs from the output of `*Listener::incoming` in that this
            /// struct is a real type, and that it returns a stream and an address
            /// for each input.
            pub struct [<Incoming $kind Streams>] {
                /// A state object, stored in an Option so we can take ownership of it
                /// while poll is being called.
                // TODO(nickm): I hate using this trick.  At some point in the
                // future, once Rust has nice support for async traits, maybe
                // we can refactor it.
                state: Option<[<Incoming $kind StreamsState>]>,
            }
            /// The result type returned by `take_and_poll_*`.
            ///
            /// It has to include the Listener, since take_and_poll() has
            /// ownership of the listener.
            type [<$kind FResult>] = (IoResult<([<$kind Stream>], $addr)>, [<$kind Listener>]);
            /// Helper to implement `Incoming*Streams`
            ///
            /// This function calls `Listener::accept` while owning the
            /// listener.  Thus, it returns a future that itself owns the listener,
            /// and we don't have lifetime troubles.
            async fn [<take_and_poll_ $kind:lower>](lis: [<$kind Listener>]) -> [<$kind FResult>] {
                let result = lis.accept().await;
                (result, lis)
            }
            /// The possible states for an `Incoming*Streams`.
            enum [<Incoming $kind StreamsState>] {
                /// We're ready to call `accept` on the listener again.
                Ready([<$kind Listener>]),
                /// We've called `accept` on the listener, and we're waiting
                /// for a future to complete.
                Accepting(Pin<Box<dyn Future<Output = [<$kind FResult>]> + Send + Sync>>),
            }
            impl [<Incoming $kind Streams>] {
                /// Create a new IncomingStreams from a Listener.
                pub fn from_listener(lis: [<$kind Listener>]) -> [<Incoming $kind Streams>] {
                    Self {
                        state: Some([<Incoming $kind StreamsState>]::Ready(lis)),
                    }
                }
            }
            impl Stream for [< Incoming $kind Streams >] {
                type Item = IoResult<([<$kind Stream>], $addr)>;

                fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
                    use [<Incoming $kind StreamsState>] as St;
                    let state = self.state.take().expect("No valid state!");
                    let mut future = match state {
                        St::Ready(lis) => Box::pin([<take_and_poll_ $kind:lower>](lis)),
                        St::Accepting(fut) => fut,
                    };
                    match future.as_mut().poll(cx) {
                        Poll::Ready((val, lis)) => {
                            self.state = Some(St::Ready(lis));
                            Poll::Ready(Some(val))
                        }
                        Poll::Pending => {
                            self.state = Some(St::Accepting(future));
                            Poll::Pending
                        }
                    }
                }
            }
            impl traits::NetStreamListener<$addr> for [<$kind Listener>] {
                type Stream = [<$kind Stream>];
                type Incoming = [<Incoming $kind Streams>];
                fn incoming(self) -> [<Incoming $kind Streams>] {
                    [<Incoming $kind Streams>]::from_listener(self)
                }
                fn local_addr(&self) -> IoResult<$addr> {
                    [<$kind Listener>]::local_addr(self)
                }
            }
        }}
    }

    impl_stream! { Tcp, std::net::SocketAddr }
    #[cfg(unix)]
    impl_stream! { Unix, unix::SocketAddr}

    #[async_trait]
    impl traits::NetStreamProvider<std::net::SocketAddr> for async_executors::AsyncStd {
        type Stream = TcpStream;
        type Listener = TcpListener;
        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::Stream> {
            TcpStream::connect(addr).await
        }
        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::Listener> {
            TcpListener::bind(*addr).await
        }
    }

    #[cfg(unix)]
    #[async_trait]
    impl traits::NetStreamProvider<unix::SocketAddr> for async_executors::AsyncStd {
        type Stream = UnixStream;
        type Listener = UnixListener;
        async fn connect(&self, addr: &unix::SocketAddr) -> IoResult<Self::Stream> {
            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedUnixAddressType)?;
            UnixStream::connect(path).await
        }
        async fn listen(&self, addr: &unix::SocketAddr) -> IoResult<Self::Listener> {
            let path = addr
                .as_pathname()
                .ok_or(crate::unix::UnsupportedUnixAddressType)?;
            UnixListener::bind(path).await
        }
    }

    #[cfg(not(unix))]
    crate::impls::impl_unix_non_provider! { async_executors::AsyncStd }

    #[async_trait]
    impl traits::UdpProvider for async_executors::AsyncStd {
        type UdpSocket = UdpSocket;

        async fn bind(&self, addr: &std::net::SocketAddr) -> IoResult<Self::UdpSocket> {
            StdUdpSocket::bind(*addr)
                .await
                .map(|socket| UdpSocket { socket })
        }
    }

    /// Wrap a AsyncStd UdpSocket
    pub struct UdpSocket {
        /// The underlying UdpSocket
        socket: StdUdpSocket,
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
            impls::streamops::set_tcp_notsent_lowat(self, notsent_lowat)
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

use futures::{Future, FutureExt};
use std::pin::Pin;
use std::time::Duration;

use crate::traits::*;

/// Create and return a new `async_std` runtime.
pub fn create_runtime() -> async_executors::AsyncStd {
    async_executors::AsyncStd::new()
}

impl SleepProvider for async_executors::AsyncStd {
    type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        Box::pin(async_io::Timer::after(duration).map(|_| ()))
    }
}

impl BlockOn for async_executors::AsyncStd {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        async_executors::AsyncStd::block_on(f)
    }
}

impl SpawnBlocking for async_executors::AsyncStd {
    type Handle<T: Send + 'static> = async_executors::BlockingHandle<T>;

    fn spawn_blocking<F, T>(&self, f: F) -> async_executors::BlockingHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        async_executors::SpawnBlocking::spawn_blocking(&self, f)
    }
}
