//! Stub types to provide in place of an unimplemented TLS server-side implementation.

use std::{borrow::Cow, io::Result as IoResult, pin::Pin, task::Context};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};

use crate::{CertifiedConn, StreamOps, tls::TlsConnector};

/// A [`TlsConnector`] or stream that can never be constructed or returned.
#[derive(Clone, Debug)]
pub struct UnimplementedTls(void::Void);

#[async_trait]
impl<S: Send + 'static> TlsConnector<S> for UnimplementedTls {
    type Conn = UnimplementedTls;

    async fn negotiate_unvalidated(&self, _stream: S, _sni_hostname: &str) -> IoResult<Self::Conn> {
        void::unreachable(self.0)
    }
}

impl CertifiedConn for UnimplementedTls {
    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        void::unreachable(self.0)
    }

    fn peer_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        void::unreachable(self.0)
    }

    fn own_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        void::unreachable(self.0)
    }
}

impl AsyncRead for UnimplementedTls {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> std::task::Poll<IoResult<usize>> {
        void::unreachable(self.0)
    }
}
impl AsyncWrite for UnimplementedTls {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<IoResult<usize>> {
        void::unreachable(self.0)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> std::task::Poll<IoResult<()>> {
        void::unreachable(self.0)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> std::task::Poll<IoResult<()>> {
        void::unreachable(self.0)
    }
}
impl StreamOps for UnimplementedTls {
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        void::unreachable(self.0)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        void::unreachable(self.0)
    }
}
