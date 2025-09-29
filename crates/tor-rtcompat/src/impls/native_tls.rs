//! Implementation for using `native_tls`

use crate::traits::{CertifiedConn, StreamOps, TlsConnector, TlsProvider};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use native_tls_crate as native_tls;
use std::io::{Error as IoError, Result as IoResult};
use tracing::instrument;

/// A [`TlsProvider`] that uses `native_tls`.
///
/// It supports wrapping any reasonable stream type that implements `AsyncRead` + `AsyncWrite`.
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "native-tls",
        any(feature = "tokio", feature = "async-std", feature = "smol")
    )))
)]
#[derive(Default, Clone)]
#[non_exhaustive]
pub struct NativeTlsProvider {}

impl<S> CertifiedConn for async_native_tls::TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
        let cert = self.peer_certificate();
        match cert {
            Ok(Some(c)) => {
                let der = c.to_der().map_err(IoError::other)?;
                Ok(Some(der))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(IoError::other(e)),
        }
    }

    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            tor_error::bad_api_usage!("native-tls does not support exporting keying material"),
        ))
    }
}

impl<S: AsyncRead + AsyncWrite + StreamOps + Unpin> StreamOps for async_native_tls::TlsStream<S> {
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
        self.get_ref().set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        self.get_ref().new_handle()
    }
}

/// An implementation of [`TlsConnector`] built with `native_tls`.
pub struct NativeTlsConnector<S> {
    /// The inner connector object.
    connector: async_native_tls::TlsConnector,
    /// Phantom data to ensure proper variance.
    _phantom: std::marker::PhantomData<fn(S) -> S>,
}

#[async_trait]
impl<S> TlsConnector<S> for NativeTlsConnector<S>
where
    S: AsyncRead + AsyncWrite + StreamOps + Unpin + Send + 'static,
{
    type Conn = async_native_tls::TlsStream<S>;

    #[instrument(skip_all, level = "trace")]
    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn> {
        let conn = self
            .connector
            .connect(sni_hostname, stream)
            .await
            .map_err(IoError::other)?;
        Ok(conn)
    }
}

impl<S> TlsProvider<S> for NativeTlsProvider
where
    S: AsyncRead + AsyncWrite + StreamOps + Unpin + Send + 'static,
{
    type Connector = NativeTlsConnector<S>;

    type TlsStream = async_native_tls::TlsStream<S>;

    fn tls_connector(&self) -> Self::Connector {
        let mut builder = native_tls::TlsConnector::builder();
        // These function names are scary, but they just mean that we
        // aren't checking whether the signer of this cert
        // participates in the web PKI, and we aren't checking the
        // hostname in the cert.
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);

        // We don't participate in the web PKI, so there is no reason for us to load the standard
        // list of CAs and CRLs. This can save us an megabyte or two.
        builder.disable_built_in_roots(true);

        let connector = builder.into();

        NativeTlsConnector {
            connector,
            _phantom: std::marker::PhantomData,
        }
    }

    fn supports_keying_material_export(&self) -> bool {
        false
    }
}
