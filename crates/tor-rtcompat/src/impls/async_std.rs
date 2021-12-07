//! Re-exports of the async_std runtime for use with arti.
//!
//! This crate helps define a slim API around our async runtime so that we
//! can easily swap it out.
//!
//! We'll probably want to support tokio as well in the future.

use std::convert::TryInto;

/// Types used for networking (async_std implementation)
mod net {
    use crate::traits;

    use async_std_crate::net::{TcpListener, TcpStream};
    use async_trait::async_trait;
    use futures::future::Future;
    use futures::stream::Stream;
    use std::io::Result as IoResult;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A `Stream` of incoming TCP streams.
    ///
    /// Differs from the output of [`TcpListener::incoming`] in that this
    /// struct is a real type, and that it returns a TCP stream and an address
    /// for each input.
    pub struct IncomingStreams {
        /// A state object, stored in an Option so we can take ownership of it
        /// while poll is being called.
        // TODO(nickm): I hate using this trick.  At some point in the
        // future, once Rust has nice support for async traits, maybe
        // we can refactor it.
        state: Option<IncomingStreamsState>,
    }
    /// The result type returned by [`take_and_poll`].
    ///
    /// It has to include the TcpListener, since take_and_poll() has
    /// ownership of the listener.
    type FResult = (IoResult<(TcpStream, SocketAddr)>, TcpListener);
    /// Helper to implement [`IncomingStreams`]
    ///
    /// This function calls [`TcpListener::accept`] while owning the
    /// listener.  Thus, it returns a future that itself owns the listener,
    /// and we don't have lifetime troubles.
    async fn take_and_poll(lis: TcpListener) -> FResult {
        let result = lis.accept().await;
        (result, lis)
    }
    /// The possible states for an [`IncomingStreams`].
    enum IncomingStreamsState {
        /// We're ready to call `accept` on the listener again.
        Ready(TcpListener),
        /// We've called `accept` on the listener, and we're waiting
        /// for a future to complete.
        Accepting(Pin<Box<dyn Future<Output = FResult>>>),
    }
    impl IncomingStreams {
        /// Create a new IncomingStreams from a TcpListener.
        pub fn from_listener(lis: TcpListener) -> IncomingStreams {
            IncomingStreams {
                state: Some(IncomingStreamsState::Ready(lis)),
            }
        }
    }
    impl Stream for IncomingStreams {
        type Item = IoResult<(TcpStream, SocketAddr)>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            use IncomingStreamsState as St;
            let state = self.state.take().expect("No valid state!");
            let mut future = match state {
                St::Ready(lis) => Box::pin(take_and_poll(lis)),
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
    #[async_trait]
    impl traits::TcpListener for TcpListener {
        type TcpStream = TcpStream;
        type Incoming = IncomingStreams;
        async fn accept(&self) -> IoResult<(Self::TcpStream, SocketAddr)> {
            TcpListener::accept(self).await
        }
        fn incoming(self) -> IncomingStreams {
            IncomingStreams::from_listener(self)
        }
        fn local_addr(&self) -> IoResult<SocketAddr> {
            TcpListener::local_addr(self)
        }
    }

    #[async_trait]
    impl traits::TcpProvider for async_executors::AsyncStd {
        type TcpStream = TcpStream;
        type TcpListener = TcpListener;
        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
            TcpStream::connect(addr).await
        }
        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
            TcpListener::bind(*addr).await
        }
    }
}

/// Implement TLS using async_std and async_native_tls.
mod tls {
    use async_std_crate::net::TcpStream;
    use async_trait::async_trait;
    use futures::io::{AsyncRead, AsyncWrite};

    use std::convert::TryFrom;
    use std::io::{Error as IoError, Result as IoResult};

    /// The TLS-over-TCP type returned by this module.
    #[allow(unreachable_pub)] // not actually unreachable; depends on features
    pub type TlsStream = async_native_tls::TlsStream<TcpStream>;

    /// A connection factory for use with async_std.
    pub struct TlsConnector {
        /// The internal connector that we're wrapping with a new API
        connector: async_native_tls::TlsConnector,
    }

    impl TryFrom<native_tls::TlsConnectorBuilder> for TlsConnector {
        type Error = std::convert::Infallible;
        fn try_from(builder: native_tls::TlsConnectorBuilder) -> Result<TlsConnector, Self::Error> {
            let connector = builder.into();
            Ok(TlsConnector { connector })
        }
    }

    #[async_trait]
    impl crate::traits::TlsConnector<TcpStream> for TlsConnector {
        type Conn = TlsStream;

        async fn negotiate_unvalidated(
            &self,
            stream: TcpStream,
            hostname: &str,
        ) -> IoResult<Self::Conn> {
            let conn = self
                .connector
                .connect(hostname, stream)
                .await
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            Ok(conn)
        }
    }

    impl<S> crate::traits::CertifiedConn for async_native_tls::TlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
            let cert = self.peer_certificate();
            match cert {
                Ok(Some(c)) => {
                    let der = c
                        .to_der()
                        .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
                    Ok(Some(der))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(IoError::new(std::io::ErrorKind::Other, e)),
            }
        }
    }
}

// ==============================

use async_std_crate::net::TcpStream;
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

impl SpawnBlocking for async_executors::AsyncStd {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        async_executors::AsyncStd::block_on(f)
    }
}

impl TlsProvider<TcpStream> for async_executors::AsyncStd {
    type TlsStream = tls::TlsStream;
    type Connector = tls::TlsConnector;

    fn tls_connector(&self) -> tls::TlsConnector {
        let mut builder = native_tls::TlsConnector::builder();
        // These function names are scary, but they just mean that we
        // aren't checking whether the signer of this cert
        // participates in the web PKI, and we aren't checking the
        // hostname in the cert.
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);

        builder.try_into().expect("Couldn't build a TLS connector!")
    }
}
