//! Relay channel code.
//!
//! This contains relay specific channel code. In other words, everyting that a relay needs to
//! establish a channel according to the Tor protocol.

pub(crate) mod handshake;

use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use std::sync::Arc;

use tor_cert::{Ed25519Cert, rsa::RsaCrosscert};
use tor_llcrypto as ll;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::{channel::RelayInitiatorHandshake, memquota::ChannelAccount};

/// Object containing the key and certificate that basically identifies us as a relay. They are
/// used for channel authentication.
///
/// We use this intermediary object in order to not have tor-proto crate have access to the KeyMgr
/// meaning access to all keys. This restricts the view to what is needed.
#[expect(unused)] // TODO(relay). remove
pub struct RelayIdentities {
    /// As a relay, our RSA identity key: KP_relayid_rsa
    pub(crate) rsa_id: RsaIdentity,
    /// As a relay, our Ed identity key: KP_relayid_ed
    pub(crate) ed_id: Ed25519Identity,
    /// The Ed25519 identity signing cert (CertType 4)
    pub(crate) cert_id_sign_ed: Ed25519Cert,
    /// The Ed25519 signing TLS cert (CertType 5)
    pub(crate) cert_sign_tls_ed: Ed25519Cert,
    /// The Ed25519 signing link auth cert (CertType 6)
    pub(crate) cert_sign_link_auth_ed: Ed25519Cert,
    /// Legacy: the RSA identity X509 cert (CertType 2). We only have the bytes here as
    /// create_legacy_rsa_id_cert() takes a key and gives us back the encoded cert.
    pub(crate) cert_id_x509_rsa: Vec<u8>,
    /// Legacy: the RSA identity cert (CertType 7)
    pub(crate) cert_id_rsa: RsaCrosscert,
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

impl RelayIdentities {
    /// Return our Ed identity key (KP_relayid_ed) as bytes.
    pub(crate) fn ed_id_bytes(&self) -> [u8; 32] {
        self.ed_id.into()
    }

    /// Return the digest of the RSA x509 certificate (CertType 2) as bytes.
    pub(crate) fn rsa_x509_digest(&self) -> [u8; 32] {
        ll::d::Sha256::digest(&self.cert_id_x509_rsa).into()
    }
}

/// Structure for building and launching a relay Tor channel.
#[derive(Default)]
#[non_exhaustive]
pub struct RelayChannelBuilder;

impl RelayChannelBuilder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Launch a new handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on the result to start the
    /// handshake.  If that succeeds, you'll have authentication info from the relay: call
    /// `check()` on the result to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T, S>(
        self,
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        memquota: ChannelAccount,
    ) -> RelayInitiatorHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        RelayInitiatorHandshake::new(tls, sleep_prov, identities, memquota)
    }
}
