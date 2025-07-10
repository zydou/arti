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

    /// An unsupported operation.
    #[error("Operation not supported: {action}")]
    NotSupported {
        /// The action we were trying to perform.
        action: &'static str,
    },
}

impl KeystoreError for ArtiEphemeralKeystoreError {}

impl HasKind for ArtiEphemeralKeystoreError {
    fn kind(&self) -> ErrorKind {
        match self {
            // TODO: These could probably use more specific ErrorKinds. They
            // are explicitly matched instead of using a default match to
            // encourage future additions to use the appropriate ErrorKind
            // rather than letting the default match handle it.
            Self::ArtiPathUnavailableError(_) => ErrorKind::Other,
            Self::SshKeySerialize(_) => ErrorKind::Other,
            Self::NotSupported { .. } => ErrorKind::BadApiUsage,
        }
    }
}

impl From<ArtiEphemeralKeystoreError> for crate::Error {
    fn from(e: ArtiEphemeralKeystoreError) -> Self {
        crate::Error::Keystore(Arc::new(e))
    }
}
