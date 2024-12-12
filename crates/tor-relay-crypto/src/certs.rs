//! Certificate related types and functions for an arti relay.

use std::time::SystemTime;

use tor_cert::{CertEncodeError, CertType, CertifiedKey, Ed25519Cert, EncodedEd25519Cert};
use tor_checkable::{SelfSigned, Timebound};
use tor_key_forge::{InvalidCertError, ParsedEd25519Cert, ToEncodableCert};
use tor_llcrypto::pk::ed25519::{self, Ed25519Identity};

use crate::pk::{RelayIdentityKeypair, RelayLinkSigningKeypair, RelaySigningKeypair};

// TODO: maybe we can eventually unify the 2 `gen_*_cert` functions
// into a single one taking a `K: HasCertType` generic param and returning `Result<K>`.
// That way, we could call `K::cert_type()` to get the cert type,
// making it impossible for the `gen_*_cert function to accidentally use
// a different cert type than the validation function.

/// Generate the relay signing certificate from the given relay identity keypair and the relay
/// signing keypair.
pub fn gen_signing_cert(
    kp_relay_id: &RelayIdentityKeypair,
    kp_relaysign_id: &RelaySigningKeypair,
    expiry: SystemTime,
) -> Result<RelayLinkSigningKeyCert, CertEncodeError> {
    Ed25519Cert::constructor()
        .cert_type(RelayLinkSigningKeyCert::cert_type())
        .expiration(expiry)
        .signing_key(kp_relay_id.to_ed25519_id())
        .cert_key(CertifiedKey::Ed25519(kp_relaysign_id.to_ed25519_id()))
        .encode_and_sign(kp_relay_id)
        .map(RelayLinkSigningKeyCert::from)
}

/// Generate the relay link certificate from the given relay signing keypair and the relay
/// link keypair.
pub fn gen_link_cert(
    kp_relaysign_id: &RelaySigningKeypair,
    kp_link_id: &RelayLinkSigningKeypair,
    expiry: SystemTime,
) -> Result<RelayLinkSigningKeyCert, CertEncodeError> {
    Ed25519Cert::constructor()
        .cert_type(RelayLinkSigningKeyCert::cert_type())
        .expiration(expiry)
        .signing_key(kp_relaysign_id.to_ed25519_id())
        .cert_key(CertifiedKey::Ed25519(kp_link_id.to_ed25519_id()))
        .encode_and_sign(kp_relaysign_id)
        .map(RelayLinkSigningKeyCert::from)
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

impl ToEncodableCert<RelaySigningKeypair> for RelaySigningKeyCert {
    type ParsedCert = ParsedEd25519Cert;
    type EncodableCert = EncodedEd25519Cert;
    type SigningKey = RelayIdentityKeypair;

    fn validate(
        cert: Self::ParsedCert,
        subject: &RelaySigningKeypair,
        signed_with: &Self::SigningKey,
    ) -> Result<Self, InvalidCertError> {
        // TODO: take the time/time provider as an arg?
        let now = SystemTime::now();
        validate_ed25519_cert(
            cert,
            &subject.public().into(),
            &signed_with.public().into(),
            Self::cert_type(),
            &now,
        )
        .map(RelaySigningKeyCert::from)
    }

    fn to_encodable_cert(self) -> Self::EncodableCert {
        self.0
    }
}

impl ToEncodableCert<RelayLinkSigningKeypair> for RelayLinkSigningKeyCert {
    type ParsedCert = ParsedEd25519Cert;
    type EncodableCert = EncodedEd25519Cert;
    type SigningKey = RelaySigningKeypair;

    fn validate(
        cert: Self::ParsedCert,
        subject: &RelayLinkSigningKeypair,
        signed_with: &Self::SigningKey,
    ) -> Result<Self, InvalidCertError> {
        // TODO: take the time/time provider as an arg?
        let now = SystemTime::now();
        validate_ed25519_cert(
            cert,
            &subject.public().into(),
            &signed_with.public().into(),
            Self::cert_type(),
            &now,
        )
        .map(RelayLinkSigningKeyCert::from)
    }

    fn to_encodable_cert(self) -> Self::EncodableCert {
        self.0
    }
}

/// Validate the specified `cert`, checking that
///    * its [`CertType`] is `cert_type, and
///    * its subject key is `subject`, and
///    * it is signed with the `signed_with` key, and
///    * it is timely (it is not expired or not yet valid at the specified `ts`)
fn validate_ed25519_cert(
    cert: ParsedEd25519Cert,
    subject: &ed25519::PublicKey,
    signed_with: &ed25519::PublicKey,
    cert_type: CertType,
    ts: &SystemTime,
) -> Result<EncodedEd25519Cert, InvalidCertError> {
    let cert = cert
        .should_be_signed_with(&Ed25519Identity::from(signed_with))?
        .check_signature()?;

    let cert = cert.check_valid_at(ts)?;
    let subject = Ed25519Identity::from(subject);

    if subject != *cert.subject_key()? {
        return Err(InvalidCertError::SubjectKeyMismatch);
    }

    let actual_cert_type = cert.as_ref().cert_type();
    if actual_cert_type != cert_type {
        return Err(InvalidCertError::CertType(actual_cert_type));
    }

    // TODO: validate the extensions?

    Ok(cert.into_encoded())
}
