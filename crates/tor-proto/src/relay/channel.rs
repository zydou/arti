//! Relay channel code.
//!
//! This contains relay specific channel code. In other words, everyting that a relay needs to
//! establish a channel according to the Tor protocol.

pub(crate) mod handshake;

use tor_cert::{Ed25519Cert, rsa::RsaCrosscert};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

/// Object containing the key and certificate that basically identifies us as a relay. They are
/// used for channel authentication.
///
/// We use this intermediary object in order to not have tor-proto crate have access to the KeyMgr
/// meaning access to all keys. This restricts the view to what is needed.
#[expect(unused)] // TODO(relay). remove
pub struct RelayIdentities {
    /// As a relay, our RSA identity key: KP_relayid_rsa
    rsa_id: RsaIdentity,
    /// As a relay, our Ed identity key: KP_relayid_ed
    ed_id: Ed25519Identity,
    /// The Ed25519 identity signing cert (CertType 4)
    cert_id_sign_ed: Ed25519Cert,
    /// The Ed25519 signing TLS cert (CertType 5)
    cert_sign_tls_ed: Ed25519Cert,
    /// The Ed25519 signing link auth cert (CertType 6)
    cert_sign_link_auth_ed: Ed25519Cert,
    /// Legacy: the RSA identity X509 cert (CertType 2). We only have the bytes here as
    /// create_legacy_rsa_id_cert() takes a key and gives us back the encoded cert.
    cert_id_x509_rsa: Vec<u8>,
    /// Legacy: the RSA identity cert (CertType 7)
    cert_id_rsa: RsaCrosscert,
}

impl RelayIdentities {
    /// Constructor.
    pub fn new(
        rsa_id: RsaIdentity,
        ed_id: Ed25519Identity,
        cert_id_sign_ed: Ed25519Cert,
        cert_sign_tls_ed: Ed25519Cert,
        cert_sign_link_auth_ed: Ed25519Cert,
        cert_id_x509_rsa: Vec<u8>,
        cert_id_rsa: RsaCrosscert,
    ) -> Self {
        Self {
            rsa_id,
            ed_id,
            cert_id_sign_ed,
            cert_sign_tls_ed,
            cert_sign_link_auth_ed,
            cert_id_x509_rsa,
            cert_id_rsa,
        }
    }
}
