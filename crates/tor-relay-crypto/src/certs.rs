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
