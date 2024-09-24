//! Support for generalized addresses.
//!
//! We use the [`SocketAddr`] type in this module,
//! and its associated [`Stream`] and [`Listener`] types,
//! when we want write code
//! that can treat AF_UNIX addresses and internet addresses as a single type.
//!
//! As an alternative, you could also write your code to be generic
//! over address, listener, provider, and stream types.
//! That would give you the performance benefits of monomorphization
//! over some corresponding costs in complexity and code size.
//! Generally, it's better to use these types unless you know
//! that the minor performance overhead here will matter in practice.

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
///
/// To avoid confusion, you might want to avoid importing this type directly.
/// Instead, import [`rtcompat::general`](crate::general)
/// and refer to this type as `general::SocketAddr`.
#[derive(Clone, Debug, derive_more::From, derive_more::TryInto)]
#[non_exhaustive]
pub enum SocketAddr {
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
pub struct Stream(Pin<Box<dyn ReadAndWrite>>);
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
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

/// The type of the result from an [`IncomingStreams`].
type StreamItem = IoResult<(Stream, SocketAddr)>;

/// A stream of incoming connections on a [`general::Listener`](Listener).
pub struct IncomingStreams(Pin<Box<dyn stream::Stream<Item = StreamItem> + Send + Sync>>);

impl stream::Stream for IncomingStreams {
    type Item = IoResult<(Stream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

/// A listener returned by a `NetStreamProvider<general::SocketAddr>`.
pub struct Listener {
    /// The `futures::Stream` of incoming network streams.
    streams: IncomingStreams,
    /// The local address on which we're listening.
    local_addr: SocketAddr,
}

impl NetStreamListener<SocketAddr> for Listener {
    type Stream = Stream;
    type Incoming = IncomingStreams;

    fn incoming(self) -> IncomingStreams {
        self.streams
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr.clone())
    }
}

/// Use `provider` to launch a `NetStreamListener` at `address`, and wrap that listener
/// as a `Listener`.
async fn abstract_listener_on<ADDR, P>(provider: &P, address: &ADDR) -> IoResult<Listener>
where
    P: NetStreamProvider<ADDR>,
    SocketAddr: From<ADDR>,
{
    let lis = provider.listen(address).await?;
    let local_addr = SocketAddr::from(lis.local_addr()?);
    let streams = lis.incoming().map(|result| {
        result.map(|(socket, addr)| (Stream(Box::pin(socket)), SocketAddr::from(addr)))
    });
    let streams = IncomingStreams(Box::pin(streams));
    Ok(Listener {
        streams,
        local_addr,
    })
}

#[async_trait]
impl<T> NetStreamProvider<SocketAddr> for T
where
    T: NetStreamProvider<net::SocketAddr> + NetStreamProvider<unix::SocketAddr>,
{
    type Stream = Stream;
    type Listener = Listener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Stream> {
        use SocketAddr as G;
        match addr {
            G::Inet(a) => Ok(Stream(Box::pin(self.connect(a).await?))),
            G::Unix(a) => Ok(Stream(Box::pin(self.connect(a).await?))),
        }
    }
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Listener> {
        use SocketAddr as G;
        match addr {
            G::Inet(a) => abstract_listener_on(self, a).await,
            G::Unix(a) => abstract_listener_on(self, a).await,
        }
    }
}
