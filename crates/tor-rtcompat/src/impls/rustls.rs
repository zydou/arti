//! Implementation for using Rustls with a runtime.

use crate::traits::{CertifiedConn, TlsConnector, TlsProvider};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use rustls::{Certificate, CertificateError, Error as TLSError, ServerName};
use rustls_crate as rustls;

use std::{
    io::{self, Error as IoError, Result as IoResult},
    sync::Arc,
};

/// A [`TlsProvider`] that uses `rustls`.
///
/// It supports wrapping any reasonable stream type that implements `AsyncRead` + `AsyncWrite`.
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "rustls", any(feature = "tokio", feature = "async-std"))))
)]
#[derive(Clone)]
#[non_exhaustive]
pub struct RustlsProvider {
    /// Inner `ClientConfig` logic used to create connectors.
    config: Arc<async_rustls::rustls::ClientConfig>,
}

impl<S> CertifiedConn for async_rustls::client::TlsStream<S> {
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
        let (_, session) = self.get_ref();
        Ok(session
            .peer_certificates()
            .and_then(|certs| certs.first().map(|c| Vec::from(c.as_ref()))))
    }
}

/// An implementation of [`TlsConnector`] built with `rustls`.
pub struct RustlsConnector<S> {
    /// The inner connector object.
    connector: async_rustls::TlsConnector,
    /// Phantom data to ensure proper variance.
    _phantom: std::marker::PhantomData<fn(S) -> S>,
}

#[async_trait]
impl<S> TlsConnector<S> for RustlsConnector<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Conn = async_rustls::client::TlsStream<S>;

    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn> {
        let name = sni_hostname
            .try_into()
            .map_err(|e| IoError::new(io::ErrorKind::InvalidInput, e))?;
        self.connector.connect(name, stream).await
    }
}

impl<S> TlsProvider<S> for RustlsProvider
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Connector = RustlsConnector<S>;

    type TlsStream = async_rustls::client::TlsStream<S>;

    fn tls_connector(&self) -> Self::Connector {
        let connector = async_rustls::TlsConnector::from(Arc::clone(&self.config));
        RustlsConnector {
            connector,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl RustlsProvider {
    /// Construct a new [`RustlsProvider`.]
    pub(crate) fn new() -> Self {
        // Be afraid: we are overriding the default certificate verification and
        // TLS signature checking code! See notes on `Verifier` below for
        // details.
        //
        // Note that the `set_certificate_verifier` function is somewhat
        // misnamed: it overrides not only how certificates are verified, but
        // also how certificates are used to check the signatures in a TLS
        // handshake.
        let config = async_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(Verifier {}))
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

/// A [`rustls_crate::client::ServerCertVerifier`] based on the [`x509_signature`] crate.
///
/// This verifier is necessary since Tor relays doesn't participate in the web
/// browser PKI, and as such their certificates won't check out as valid ones.
///
/// What's more, the `webpki` crate rejects most of Tor's certificates as
/// unparsable because they do not contain any extensions: That means we need to
/// replace the TLS-handshake signature checking functions too, since otherwise
/// `rustls` would  think all the certificates were invalid.
///
/// Fortunately, the p2p people have provided `x509_signature` for this
/// purpose.
#[derive(Clone, Debug)]
struct Verifier {}

impl rustls_crate::client::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, TLSError> {
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
        let _cert = get_cert(end_entity)?;

        // Note that we don't even check timeliness: Tor uses the presented
        // relay certificate just as a container for the relay's public link
        // key.  Actual timeliness checks will happen later, on the certificates
        // that authenticate this one, when we process the relay's CERTS cell in
        // `tor_proto::channel::handshake`.

        Ok(rustls::client::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, TLSError> {
        let cert = get_cert(cert)?;
        let scheme = convert_scheme(dss.scheme)?;

        // NOTE:
        //
        // We call `check_signature` here rather than `check_tls12_signature`.
        // That means that we're allowing the other side to use signature
        // algorithms that aren't actually supported by TLS 1.2.
        //
        // It turns out, apparently, unless my experiments are wrong,  that
        // OpenSSL will happily use PSS with TLS 1.2.  At least, it seems to do
        // so when invoked via native_tls in the test code for this crate.
        cert.check_signature(scheme, message, dss.signature())
            .map(|_| rustls::client::HandshakeSignatureValid::assertion())
            .map_err(|_| TLSError::InvalidCertificate(CertificateError::BadSignature))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, TLSError> {
        let cert = get_cert(cert)?;
        let scheme = convert_scheme(dss.scheme)?;

        cert.check_tls13_signature(scheme, message, dss.signature())
            .map(|_| rustls::client::HandshakeSignatureValid::assertion())
            .map_err(|_| TLSError::InvalidCertificate(CertificateError::BadSignature))
    }
}

/// Parse a `rustls::Certificate` as an `x509_signature::X509Certificate`, if possible.
fn get_cert(c: &rustls::Certificate) -> Result<x509_signature::X509Certificate, TLSError> {
    x509_signature::parse_certificate(c.as_ref())
        .map_err(|_| TLSError::InvalidCertificate(CertificateError::BadSignature))
}

/// Convert from the signature scheme type used in `rustls` to the one used in
/// `x509_signature`.
///
/// (We can't just use the x509_signature crate's "rustls" feature to have it
/// use the same enum from `rustls`, because it seems to be on a different
/// version from the rustls we want.)
fn convert_scheme(
    scheme: rustls::SignatureScheme,
) -> Result<x509_signature::SignatureScheme, TLSError> {
    use rustls::SignatureScheme as R;
    use x509_signature::SignatureScheme as X;

    // Yes, we do allow PKCS1 here.  That's fine in practice when PKCS1 is only
    // used (as in TLS 1.2) for signatures; the attacks against correctly
    // implemented PKCS1 make sense only when it's used for encryption.
    Ok(match scheme {
        R::RSA_PKCS1_SHA256 => X::RSA_PKCS1_SHA256,
        R::ECDSA_NISTP256_SHA256 => X::ECDSA_NISTP256_SHA256,
        R::RSA_PKCS1_SHA384 => X::RSA_PKCS1_SHA384,
        R::ECDSA_NISTP384_SHA384 => X::ECDSA_NISTP384_SHA384,
        R::RSA_PKCS1_SHA512 => X::RSA_PKCS1_SHA512,
        R::RSA_PSS_SHA256 => X::RSA_PSS_SHA256,
        R::RSA_PSS_SHA384 => X::RSA_PSS_SHA384,
        R::RSA_PSS_SHA512 => X::RSA_PSS_SHA512,
        R::ED25519 => X::ED25519,
        R::ED448 => X::ED448,
        _ => {
            // Either `x509-signature` crate doesn't support these (nor should it really), or
            // rustls itself doesn't.
            return Err(TLSError::PeerIncompatible(
                rustls::PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }
    })
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn test_cvt_scheme() {
        use rustls::SignatureScheme as R;
        use x509_signature::SignatureScheme as X;

        macro_rules! check_cvt {
            { $id:ident } =>
            { assert_eq!(convert_scheme(R::$id).unwrap(), X::$id); }
        }

        check_cvt!(RSA_PKCS1_SHA256);
        check_cvt!(RSA_PKCS1_SHA384);
        check_cvt!(RSA_PKCS1_SHA512);
        check_cvt!(ECDSA_NISTP256_SHA256);
        check_cvt!(ECDSA_NISTP384_SHA384);
        check_cvt!(RSA_PSS_SHA256);
        check_cvt!(RSA_PSS_SHA384);
        check_cvt!(RSA_PSS_SHA512);
        check_cvt!(ED25519);
        check_cvt!(ED448);

        assert!(convert_scheme(R::RSA_PKCS1_SHA1).is_err());
        assert!(convert_scheme(R::Unknown(0x1337)).is_err());
    }
}
