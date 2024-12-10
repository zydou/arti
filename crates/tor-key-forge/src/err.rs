//! An error type for the `tor-key-forge` crate.

use crate::ssh::SshKeyAlgorithm;

/// An Error type for this crate.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Attempted to use an unsupported key.
    #[error("Unsupported key algorithm {0}")]
    UnsupportedKeyAlgorithm(SshKeyAlgorithm),

    /// Failed to parse certificate.
    #[error("Failed to parse certificate")]
    CertParse(tor_bytes::Error),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}
