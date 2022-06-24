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
