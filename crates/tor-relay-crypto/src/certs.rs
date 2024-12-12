//! Certificate related types and functions for an arti relay.

use std::time::SystemTime;

use tor_cert::{CertEncodeError, CertType, CertifiedKey, Ed25519Cert, EncodedEd25519Cert};

use crate::pk::{RelayIdentityKeypair, RelayLinkSigningKeypair, RelaySigningKeypair};

/// Generate the relay signing certificate from the given relay identity keypair and the relay
/// signing keypair.
pub fn gen_signing_cert(
    kp_relay_id: &RelayIdentityKeypair,
    kp_relaysign_id: &RelaySigningKeypair,
    expiry: SystemTime,
) -> Result<EncodedEd25519Cert, CertEncodeError> {
    Ed25519Cert::constructor()
        .cert_type(CertType::IDENTITY_V_SIGNING)
        .expiration(expiry)
        .signing_key(kp_relay_id.to_ed25519_id())
        .cert_key(CertifiedKey::Ed25519(kp_relaysign_id.to_ed25519_id()))
        .encode_and_sign(kp_relay_id)
}

/// Generate the relay link certificate from the given relay signing keypair and the relay
/// link keypair.
pub fn gen_link_cert(
    kp_relaysign_id: &RelaySigningKeypair,
    kp_link_id: &RelayLinkSigningKeypair,
    expiry: SystemTime,
) -> Result<EncodedEd25519Cert, CertEncodeError> {
    Ed25519Cert::constructor()
        .cert_type(CertType::SIGNING_V_LINK_AUTH)
        .expiration(expiry)
        .signing_key(kp_relaysign_id.to_ed25519_id())
        .cert_key(CertifiedKey::Ed25519(kp_link_id.to_ed25519_id()))
        .encode_and_sign(kp_relaysign_id)
}

/// Certificate for the medium-term relay signing key (`K_relaysign_ed`).
///
/// This is an ed25519 certificate encoded in Tor's
/// [certificate format](https://spec.torproject.org/cert-spec.html#ed-certs)
/// with [`CERT_KEY_TYPE`](https://spec.torproject.org/cert-spec.html#list-key-types)
/// set to `ed25519` (`01`),
/// and the [`CERT_TYPE`](https://spec.torproject.org/cert-spec.html#list-cert-types)
/// set to `IDENTITY_V_SIGNING` (`04`).
///
/// The signing key is the relay identity key (`K_relayid_ed`)`).
#[derive(Debug, Clone, PartialEq, derive_more::From)]
pub struct RelaySigningKeyCert(EncodedEd25519Cert);

impl RelaySigningKeyCert {
    /// Return the `CertType` of this cert.
    fn cert_type() -> CertType {
        CertType::IDENTITY_V_SIGNING
    }
}

/// Certificate for the short-term signing keypair for link authentication.
///
/// This is an ed25519 certificate encoded in Tor's
/// [certificate format](https://spec.torproject.org/cert-spec.html#ed-certs)
/// with [`CERT_KEY_TYPE`](https://spec.torproject.org/cert-spec.html#list-key-types)
/// set to `ed25519` (`01`),
/// and the [`CERT_TYPE`](https://spec.torproject.org/cert-spec.html#list-cert-types)
/// set to `SIGNING_V_LINK_AUTH` (`06`).
///
/// The signing key is the relay identity key (`K_relayid_ed`)`).
#[derive(Debug, Clone, PartialEq, derive_more::From)]
pub struct RelayLinkSigningKeyCert(EncodedEd25519Cert);

impl RelayLinkSigningKeyCert {
    /// Return the `CertType` of this cert.
    fn cert_type() -> CertType {
        CertType::SIGNING_V_LINK_AUTH
    }
}
