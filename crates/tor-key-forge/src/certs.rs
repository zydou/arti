//! Helpers for encoding certificate material.

use crate::{CertType, ErasedKey, InvalidCertError, KeyUnknownCert, Result};
use tor_cert::{Ed25519Cert, EncodedEd25519Cert, SigCheckedCert, UncheckedCert};
use tor_llcrypto::pk::ed25519::{self, Ed25519Identity};

use std::{result::Result as StdResult, time::SystemTime};

/// A key certificate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CertData {
    /// A tor-specific ed25519 cert.
    TorEd25519Cert(EncodedEd25519Cert),
}

impl CertData {
    /// Convert the cert material into a known cert type,
    /// and return the type-erased value.
    ///
    /// The caller is expected to downcast the value returned to the correct concrete type.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn into_erased(self) -> Result<ErasedKey> {
        match self {
            Self::TorEd25519Cert(cert) => Ok(Box::new(cert)),
        }
    }

    /// Get the [`CertType`] of this cert.
    pub(crate) fn cert_type(&self) -> CertType {
        match self {
            CertData::TorEd25519Cert(_) => CertType::Ed25519TorCert,
        }
    }
}

// TODO: maybe all of this belongs in tor-cert?
//
// The types defined here are all wrappers over various tor-cert types
// plus the raw certificate representation (needed to reconstruct
// the `EncodedEd25519Cert` without having to encode + sign the certificate)

/// A parsed `EncodedEd25519Cert`.
#[derive(Debug, Clone, derive_more::AsRef)]
pub struct ParsedEd25519Cert {
    /// The parsed cert.
    #[as_ref]
    parsed_cert: KeyUnknownCert,
    /// The raw, unparsed cert.
    raw: Vec<u8>,
}

impl ParsedEd25519Cert {
    /// Parse the byte representation of the specified cert.
    pub fn decode(raw: Vec<u8>) -> StdResult<Self, tor_bytes::Error> {
        let parsed_cert = Ed25519Cert::decode(&raw)?;
        Ok(Self { parsed_cert, raw })
    }

    /// Declare that this should be a certificate signed with a given key.
    ///
    /// See [`KeyUnknownCert::should_be_signed_with`].
    pub fn should_be_signed_with(
        self,
        pkey: &ed25519::Ed25519Identity,
    ) -> StdResult<UncheckedEd25519Cert, tor_cert::CertError> {
        let Self { parsed_cert, raw } = self;

        let cert = parsed_cert.should_be_signed_with(pkey)?;

        Ok(UncheckedEd25519Cert { cert, raw })
    }
}

/// A parsed `EncodedEd25519Cert`.
pub struct UncheckedEd25519Cert {
    /// The parsed, unchecked cert.
    cert: UncheckedCert,
    /// The raw, unparsed cert.
    raw: Vec<u8>,
}

impl tor_checkable::SelfSigned<SigCheckedEd25519Cert> for UncheckedEd25519Cert {
    type Error = tor_cert::CertError;

    fn is_well_signed(&self) -> StdResult<(), tor_cert::CertError> {
        self.cert.is_well_signed()
    }

    fn dangerously_assume_wellsigned(self) -> SigCheckedEd25519Cert {
        let Self { cert, raw } = self;

        let cert = cert.dangerously_assume_wellsigned();
        SigCheckedEd25519Cert { cert, raw }
    }
}

/// A signature-checked `EncodedEd25519Cert`.
pub struct SigCheckedEd25519Cert {
    /// The parsed, checked cert.
    cert: SigCheckedCert,
    /// The raw, unparsed cert.
    raw: Vec<u8>,
}

impl tor_checkable::Timebound<ValidatedEd25519Cert> for SigCheckedEd25519Cert {
    type Error = tor_checkable::TimeValidityError;

    fn is_valid_at(&self, t: &SystemTime) -> StdResult<(), Self::Error> {
        self.cert.is_valid_at(t)
    }

    fn dangerously_assume_timely(self) -> ValidatedEd25519Cert {
        let Self { cert, raw } = self;

        let cert = cert.dangerously_assume_timely();
        ValidatedEd25519Cert { cert, raw }
    }
}

/// A well-signed and timely `EncodedEd25519Cert`.
#[derive(Debug, Clone, derive_more::AsRef)]
pub struct ValidatedEd25519Cert {
    /// The parsed, validated cert.
    #[as_ref]
    cert: Ed25519Cert,
    /// The raw, unparsed cert.
    raw: Vec<u8>,
}

impl ValidatedEd25519Cert {
    /// Return the subject key of this certificate.
    pub fn subject_key(&self) -> StdResult<&Ed25519Identity, InvalidCertError> {
        match self.cert.subject_key() {
            tor_cert::CertifiedKey::Ed25519(ed25519_identity) => Ok(ed25519_identity),
            _ => Err(InvalidCertError::InvalidSubjectKeyAlgorithm),
        }
    }

    /// Return the encoded representation of this cert as a `EncodedEd25519Cert`.
    pub fn into_encoded(self) -> EncodedEd25519Cert {
        EncodedEd25519Cert::dangerously_from_bytes(&self.raw)
    }
}
