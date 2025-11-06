//! Implementation for using Rustls with a runtime.
//!
//! #

use crate::StreamOps;
use crate::traits::{CertifiedConn, TlsConnector, TlsProvider};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_rustls::rustls::{self, crypto::CryptoProvider};
use rustls::client::danger;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::{CertificateError, Error as TLSError};
use rustls_pki_types::{CertificateDer, ServerName};
use tracing::instrument;
use webpki::EndEntityCert; // this is actually rustls_webpki.

use std::{
    io::{self, Error as IoError, Result as IoResult},
    sync::Arc,
};

/// A [`TlsProvider`] that uses `rustls`.
///
/// It supports wrapping any reasonable stream type that implements `AsyncRead` + `AsyncWrite`.
///
/// # Cryptographic providers
///
/// The application is responsible for calling [`CryptoProvider::install_default()`]
/// before constructing [`TlsProvider`].  If they do not, we will issue a warning,
/// and install a default ([ring]) provider.
///
/// We choose ring because, of the two builtin providers that ship with rustls,
/// it has the best license.
/// We _could_ instead use [aws-lc-rs] (for its early MLKEM768 support),
/// but it is [still under the old OpenSSL license][aws-lc-license], which is GPL-incompatible.
/// (Although Arti isn't under the GPL itself, we are trying to stay compatible with it.)
///
/// See the [rustls documentation][all-providers] for a list of other rustls
/// cryptography providcers.
///
/// [ring]: https://crates.io/crates/ring
/// [aws-lc-rs]: https://github.com/aws/aws-lc-rs
/// [aws-lc-license]: https://github.com/aws/aws-lc/issues/2203
/// [all-providers]: https://docs.rs/rustls/latest/rustls/#cryptography-providers
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "rustls",
        any(feature = "tokio", feature = "async-std", feature = "smol")
    )))
)]
#[derive(Clone)]
#[non_exhaustive]
pub struct RustlsProvider {
    /// Inner `ClientConfig` logic used to create connectors.
    config: Arc<futures_rustls::rustls::ClientConfig>,
}

impl<S> CertifiedConn for futures_rustls::client::TlsStream<S> {
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
        let (_, session) = self.get_ref();
        Ok(session
            .peer_certificates()
            .and_then(|certs| certs.first().map(|c| Vec::from(c.as_ref()))))
    }

    fn export_keying_material(
        &self,
        len: usize,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>> {
        let (_, session) = self.get_ref();
        session
            .export_keying_material(Vec::with_capacity(len), label, context)
            .map_err(|e| IoError::new(io::ErrorKind::InvalidData, e))
    }
}

impl<S: StreamOps> StreamOps for futures_rustls::client::TlsStream<S> {
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
        self.get_ref().0.set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        self.get_ref().0.new_handle()
    }
}

/// An implementation of [`TlsConnector`] built with `rustls`.
pub struct RustlsConnector<S> {
    /// The inner connector object.
    connector: futures_rustls::TlsConnector,
    /// Phantom data to ensure proper variance.
    _phantom: std::marker::PhantomData<fn(S) -> S>,
}

#[async_trait]
impl<S> TlsConnector<S> for RustlsConnector<S>
where
    S: AsyncRead + AsyncWrite + StreamOps + Unpin + Send + 'static,
{
    type Conn = futures_rustls::client::TlsStream<S>;

    #[instrument(skip_all, level = "trace")]
    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn> {
        let name: ServerName<'_> = sni_hostname
            .try_into()
            .map_err(|e| IoError::new(io::ErrorKind::InvalidInput, e))?;
        self.connector.connect(name.to_owned(), stream).await
    }
}

impl<S> TlsProvider<S> for RustlsProvider
where
    S: AsyncRead + AsyncWrite + StreamOps + Unpin + Send + 'static,
{
    type Connector = RustlsConnector<S>;

    type TlsStream = futures_rustls::client::TlsStream<S>;

    fn tls_connector(&self) -> Self::Connector {
        let connector = futures_rustls::TlsConnector::from(Arc::clone(&self.config));
        RustlsConnector {
            connector,
            _phantom: std::marker::PhantomData,
        }
    }

    fn supports_keying_material_export(&self) -> bool {
        true
    }
}

/// Try to install a default crypto provider if none has been installed, so that Rustls can operate.
///
/// (Warns if we have to do this: the application should be responsible for choosing a provider.)
fn ensure_provider_installed() {
    if CryptoProvider::get_default().is_none() {
        // If we haven't installed a CryptoProvider at this point, we warn and install
        // the `ring` provider.  That isn't great, but the alternative would be to
        // panic.  Right now, that would cause many of our tests to fail.
        tracing::warn!(
            "Creating a RustlsRuntime, but no CryptoProvider is installed. The application \
                        should call CryptoProvider::install_default()"
        );
        let _idempotent_ignore = CryptoProvider::install_default(
            futures_rustls::rustls::crypto::ring::default_provider(),
        );
    }
}

impl RustlsProvider {
    /// Construct a new [`RustlsProvider`].
    pub(crate) fn new() -> Self {
        ensure_provider_installed();

        // Be afraid: we are overriding the default certificate verification and
        // TLS signature checking code! See notes on `Verifier` below for
        // details.
        //
        // Note that the `set_certificate_verifier` function is somewhat
        // misnamed: it overrides not only how certificates are verified, but
        // also how certificates are used to check the signatures in a TLS
        // handshake.
        let config = futures_rustls::rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier(
                CryptoProvider::get_default()
                    .expect("CryptoProvider not installed")
                    .signature_verification_algorithms,
            )))
            .with_no_client_auth();

        RustlsProvider {
            config: Arc::new(config),
        }
    }
}

impl Default for RustlsProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// A custom [`rustls::client::danger::ServerCertVerifier`]
///
/// This verifier is necessary since Tor relays doesn't participate in the web
/// browser PKI, and as such their certificates won't check out as valid ones.
///
/// We enforce that the certificate itself has correctly authenticated the TLS
/// connection, but nothing else.
#[derive(Clone, Debug)]
struct Verifier(pub(crate) WebPkiSupportedAlgorithms);

impl danger::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _roots: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<danger::ServerCertVerified, TLSError> {
        // We don't check anything about the certificate at this point other
        // than making sure it is well-formed.
        //
        // When we make a channel, we'll check that it's authenticated by the
        // other party's real identity key, inside the Tor handshake.
        //
        // In theory, we shouldn't have to do even this much: rustls should not
        // allow a handshake  without a certificate, and the certificate's
        // well-formedness should get checked below in one of the
        // verify_*_signature functions.  But this check is cheap, so let's
        // leave it in.
        let _cert: EndEntityCert<'_> = end_entity
            .try_into()
            .map_err(|_| TLSError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Note that we don't even check timeliness or key usage: Tor uses the presented
        // relay certificate just as a container for the relay's public link
        // key.  Actual timeliness checks will happen later, on the certificates
        // that authenticate this one, when we process the relay's CERTS cell in
        // `tor_proto::channel::handshake`.
        //
        // (This is what makes it safe for us _not_ to call
        // EndEntityCert::verify_for_usage.)

        Ok(danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, TLSError> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, TLSError> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        // We don't actually want to send any DNs for our root certs,
        // since they aren't real.
        None
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    /// A certificate returned by a C Tor relay implementation.
    ///
    /// We want to have a test for this, since some older versions of `webpki`
    /// rejected C Tor's certificates as unparsable because they did not contain
    /// any extensions.  Back then, we had to use `x509_signature`,
    /// which now appears unmaintained.
    const TOR_CERTIFICATE: &[u8] = include_bytes!("./tor-generated.der");

    #[test]
    fn basic_tor_cert() {
        ensure_provider_installed();
        let der = CertificateDer::from_slice(TOR_CERTIFICATE);
        let _cert = EndEntityCert::try_from(&der).unwrap();
    }
}
