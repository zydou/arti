//! Define error types for the tor-cert crate.
//!
//! Most of the encoding/decoding functions here return [`tor_bytes::Error`],
//! but many of them (related to certificate-specific operations) do not.

use thiserror::Error;

/// An error related to checking or validating a certificate
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertError {
    /// The key on a certificate was not as expected.
    #[error("Key on certificate was not as expected")]
    KeyMismatch,

    /// We tried to get the signing key from a certificate that didn't include
    /// one.
    #[error("Missing signing key on certificate")]
    MissingPubKey,

    /// We tried to validate a signature, and found that it was wrong.
    #[error("Signature on certificate was invalid")]
    BadSignature,
}

/// An error related to signing or encoding a certificate
#[cfg(feature = "encode")]
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum CertEncodeError {
    /// This certificate contains the public key that it is supposed to
    /// be signed by, and the provided signing private key isn't it.
    #[error("Tried to sign with wrong key")]
    KeyMismatch,

    /// The certificate contains more than 255 extensions.
    #[error("Too many extensions")]
    TooManyExtensions,

    /// Some extension had a length of over 2^16.
    #[error("Extension too long")]
    ExtensionTooLong,

    /// A mandatory field was not provided.
    #[error("Missing field {0:?}")]
    MissingField(&'static str),

    /// We encountered a problem when encoding the certificate: probably, that
    /// some length field would have to be longer than its maximum.  This is
    /// probably a bug in the calling code.
    #[error("Tried to generate a cert we couldn't encode.")]
    Bytes(#[from] tor_bytes::EncodeError),
}
