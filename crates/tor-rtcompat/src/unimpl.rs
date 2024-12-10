//! Implementations for unsupported stream and listener types.
//!
//! Sometimes we find it convenient to have an implementation for `NetStreamProvider` on an
//! uninhabited type.  When we do, this module provides the associated types for its listener and streams.

use std::io::Result as IoResult;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::StreamOps;

/// An unconstructable AsyncRead+AsyncWrite type.
///
/// (This is the type of a Stream for any unsupported address type.)
#[derive(Debug, Clone)]
pub struct FakeStream(void::Void);

/// An unconstructable listener type.
///
/// (This is the type of a NetStreamListener for any unsupported address type.)
#[derive(Debug, Clone)]
pub struct FakeListener<ADDR>(void::Void, PhantomData<ADDR>);

/// An unconstructable stream::Stream type.
///
/// (This is the type of a incoming connection stream for any unsupported address type.)
pub struct FakeIncomingStreams<ADDR>(void::Void, PhantomData<ADDR>);

impl futures::io::AsyncRead for FakeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        void::unreachable(self.0)
    }
}

impl futures::io::AsyncWrite for FakeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        void::unreachable(self.0)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        void::unreachable(self.0)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        void::unreachable(self.0)
    }
}

impl<ADDR> futures::stream::Stream for FakeIncomingStreams<ADDR> {
    type Item = IoResult<(FakeStream, ADDR)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        void::unreachable(self.0)
    }
}

impl<ADDR> crate::traits::NetStreamListener<ADDR> for FakeListener<ADDR>
where
    ADDR: Unpin + Send + Sync + 'static,
{
    type Incoming = FakeIncomingStreams<ADDR>;
    type Stream = FakeStream;
    fn incoming(self) -> Self::Incoming {
        void::unreachable(self.0)
    }
    fn local_addr(&self) -> IoResult<ADDR> {
        void::unreachable(self.0)
    }
}

impl StreamOps for FakeStream {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        void::unreachable(self.0)
    }
}
