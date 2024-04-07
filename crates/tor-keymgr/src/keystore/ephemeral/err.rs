//! An error type for [`ArtiEphemeralKeystore`](crate::ArtiEphemeralKeystore).

use std::sync::Arc;

use tor_error::{ErrorKind, HasKind};

use crate::KeystoreError;

/// An error returned by [`ArtiEphemeralKeystore`](crate::ArtiEphemeralKeystore)'s
/// [`Keystore`](crate::Keystore) implementation.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum ArtiEphemeralKeystoreError {
    /// An error that occurred  building an ArtiPath from a KeySpecifier
    #[error("unable to build ArtiPath from KeySpecifier")]
    ArtiPathUnavailableError(#[from] crate::key_specifier::ArtiPathUnavailableError),
    /// An error that occurred serializing a key to OpenSSH text format
    #[error("{0}")]
    SshKeySerialize(#[from] ssh_key::Error),
}

impl KeystoreError for ArtiEphemeralKeystoreError {}

impl HasKind for ArtiEphemeralKeystoreError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

impl From<ArtiEphemeralKeystoreError> for crate::Error {
    fn from(e: ArtiEphemeralKeystoreError) -> Self {
        crate::Error::Keystore(Arc::new(e))
    }
}
