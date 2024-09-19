//! Support for generalized addresses.

// XXXX All the names here, including the name of this module, are temporary; we need to discuss how
// they work.

use async_trait::async_trait;
use futures::{stream, AsyncRead, AsyncWrite, StreamExt as _};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{unix, NetStreamListener, NetStreamProvider};
use std::{io::Result as IoResult, net};

/// Any address that Arti can listen on or connect to.
///
/// We use this type when we want to make streams
/// without being concerned whether they are AF_UNIX streams, TCP streams, or so forth.
#[derive(Clone, Debug, derive_more::From, derive_more::TryInto)]
#[non_exhaustive]
pub enum GeneralizedAddr {
    /// An IPv4 or IPv6 address on the internet.
    Inet(net::SocketAddr),
    /// A local AF_UNIX address.
    ///
    /// (Note that [`unix::SocketAddr`] is unconstructable on platforms where it is not supported.)
    Unix(unix::SocketAddr),
}

/// Helper trait to allow us to create a type-erased stream.
///
/// (Rust doesn't allow "dyn AsyncRead + AsyncWrite")
trait ReadAndWrite: AsyncRead + AsyncWrite + Send + Sync {}
impl<T> ReadAndWrite for T where T: AsyncRead + AsyncWrite + Send + Sync {}

/// A stream returned by a `NetStreamProvider<GeneralizedAddr>`
pub struct AbstractStream(Pin<Box<dyn ReadAndWrite>>);
impl AsyncRead for AbstractStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}
impl AsyncWrite for AbstractStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.0.as_mut().poll_close(cx)
    }
}

/// The type of the result from an `IncomingAbstractStream`.
type StreamItem = IoResult<(AbstractStream, GeneralizedAddr)>;

/// A stream of incoming connections on an [`AbstractListener`]
pub struct IncomingAbstractStreams(Pin<Box<dyn stream::Stream<Item = StreamItem> + Send + Sync>>);

impl stream::Stream for IncomingAbstractStreams {
    type Item = IoResult<(AbstractStream, GeneralizedAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

/// A listener returned by a NetStreamProvider<GeneralizedAddr>`
pub struct AbstractListener {
    /// The `futures::Stream` of incoming network streams.
    streams: IncomingAbstractStreams,
    /// The local address on which we're listening.
    local_addr: GeneralizedAddr,
}

#[async_trait]
impl NetStreamListener<GeneralizedAddr> for AbstractListener {
    type Stream = AbstractStream;
    type Incoming = IncomingAbstractStreams;

    fn incoming(self) -> IncomingAbstractStreams {
        self.streams
    }

    fn local_addr(&self) -> IoResult<GeneralizedAddr> {
        Ok(self.local_addr.clone())
    }
}

/// Use `provider` to launch a `NetStreamListener` at `address`, and wrap that listener
/// as an `AbstractListener`.
async fn abstract_listener_on<ADDR, P>(provider: &P, address: &ADDR) -> IoResult<AbstractListener>
where
    P: NetStreamProvider<ADDR>,
    GeneralizedAddr: From<ADDR>,
{
    let lis = provider.listen(address).await?;
    let local_addr = GeneralizedAddr::from(lis.local_addr()?);
    let streams = lis.incoming().map(|result| {
        result.map(|(socket, addr)| {
            (
                AbstractStream(Box::pin(socket)),
                GeneralizedAddr::from(addr),
            )
        })
    });
    let streams = IncomingAbstractStreams(Box::pin(streams));
    Ok(AbstractListener {
        streams,
        local_addr,
    })
}

#[async_trait]
impl<T> NetStreamProvider<GeneralizedAddr> for T
where
    T: NetStreamProvider<net::SocketAddr> + NetStreamProvider<unix::SocketAddr>,
{
    type Stream = AbstractStream;
    type Listener = AbstractListener;

    async fn connect(&self, addr: &GeneralizedAddr) -> IoResult<AbstractStream> {
        use GeneralizedAddr as G;
        match addr {
            G::Inet(a) => Ok(AbstractStream(Box::pin(self.connect(a).await?))),
            G::Unix(a) => Ok(AbstractStream(Box::pin(self.connect(a).await?))),
        }
    }
    async fn listen(&self, addr: &GeneralizedAddr) -> IoResult<AbstractListener> {
        use GeneralizedAddr as G;
        match addr {
            G::Inet(a) => abstract_listener_on(self, a).await,
            G::Unix(a) => abstract_listener_on(self, a).await,
        }
    }
}
