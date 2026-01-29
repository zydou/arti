//! TLS server trait implementations for Rustls.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use std::{
    borrow::Cow,
    io::{Error as IoError, Result as IoResult},
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tracing::instrument;

use crate::{CertifiedConn, StreamOps, tls::TlsAcceptorSettings, tls::TlsConnector};
use futures_rustls::rustls::ServerConfig as RustlsServerConfig;

/// A server-side TLS stream.
///
/// Created by [`RustlsAcceptor`].
#[pin_project]
pub struct RustlsServerStream<S> {
    /// The underlying Rustls stream.
    ///
    /// We have to wrap this so that we can also expose the certificate we sent,
    /// for use in Tor's link authentication.
    #[pin]
    stream: futures_rustls::server::TlsStream<S>,

    /// The certificate that we sent.
    ///
    /// (If we sent multiple certs, this should be the one corresponding to our private key.)
    cert_der: Arc<[u8]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsServerStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_close(cx)
    }
}

impl<S: StreamOps> StreamOps for RustlsServerStream<S> {
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
        self.stream.get_ref().0.set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        self.stream.get_ref().0.new_handle()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> CertifiedConn for RustlsServerStream<S> {
    fn peer_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        let (_, session) = self.stream.get_ref();
        Ok(session
            .peer_certificates()
            .and_then(|certs| certs.first().map(|c| Cow::from(c.as_ref()))))
    }

    fn export_keying_material(
        &self,
        len: usize,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        let (_, session) = self.stream.get_ref();
        session
            .export_keying_material(Vec::with_capacity(len), label, context)
            .map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, e))
    }

    fn own_certificate(&self) -> IoResult<Option<Cow<'_, [u8]>>> {
        Ok(Some(Cow::from(self.cert_der.as_ref())))
    }
}

/// A server implementation for Rustls.
///
/// Accepts asynchronous streams (typically over TCP), and performs the server-side TLS handshake.
#[derive(Clone, derive_more::Debug)]
pub struct RustlsAcceptor<S> {
    /// The underlying TLS acceptor.
    #[debug(skip)]
    acceptor: futures_rustls::TlsAcceptor,
    /// The certificate corresponding to our private key.
    cert_der: Arc<[u8]>,
    /// Phantomdata to mark this type as invariant in S.
    _phantom: PhantomData<fn(S) -> S>,
}

#[async_trait]
impl<S> TlsConnector<S> for RustlsAcceptor<S>
where
    S: AsyncRead + AsyncWrite + StreamOps + Unpin + Send + 'static,
{
    type Conn = RustlsServerStream<S>;

    #[instrument(skip_all, level = "trace")]
    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn> {
        let _ignore = sni_hostname;
        let stream = self.acceptor.accept(stream).await?;
        Ok(RustlsServerStream {
            stream,
            cert_der: Arc::clone(&self.cert_der),
        })
    }
}

impl<S> RustlsAcceptor<S> {
    /// Construct a new RustlsAcceptor from a provided [`TlsAcceptorSettings`]
    pub(crate) fn new(settings: &TlsAcceptorSettings) -> IoResult<Self> {
        let cert_der = settings.cert_der().into();

        let cfg: RustlsServerConfig = rustls_server_config(settings)?;
        let acceptor = futures_rustls::TlsAcceptor::from(Arc::new(cfg));
        Ok(Self {
            acceptor,
            cert_der,
            _phantom: PhantomData,
        })
    }
}

/// Try to convert a [`TlsAcceptorSettings`] into a configuration for a rustls server.
///
/// This is not necessarily suitable for general use outside of being a Tor relay.
fn rustls_server_config(settings: &TlsAcceptorSettings) -> IoResult<RustlsServerConfig> {
    use futures_rustls::rustls::pki_types as pki;
    use futures_rustls::rustls::version::{TLS12, TLS13};

    // Convert certificate and key into expected format.
    let cert_chain = settings
        .identity
        .certificates_der()
        .into_iter()
        .map(|c| pki::CertificateDer::from_slice(c).into_owned())
        .collect();
    let key_der = settings
        .identity
        .private_key_pkcs8_der()
        .map_err(IoError::other)?;
    let key_der =
        pki::PrivateKeyDer::Pkcs8(pki::PrivatePkcs8KeyDer::from(key_der.as_ref())).clone_key();

    // Initialize the ServerConfig.
    let config = RustlsServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13]) // 1.2 and 1.3 only.
        .with_no_client_auth() // Don't require client authentication.
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, e))?;

    // TODO: Possibly, modify config.  There are numerous fields we could adjust.

    Ok(config)
}
