//! An error type for [`ArtiNativeKeyStore`](crate::ArtiNativeKeyStore).

use crate::KeystoreError;
use tor_error::{ErrorKind, HasKind};

use std::error::Error as StdError;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// An error returned by [`ArtiNativeKeyStore`](crate::ArtiNativeKeyStore)'s
/// [`KeyStore`](crate::KeyStore) implementation.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum ArtiNativeKeystoreError {
    /// An error that occurred while accessing the filesystem.
    #[error("An error occurred while accessing the filesystem")]
    Filesystem {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<io::Error>,
    },

    /// Encountered an invalid path or invalid permissions.
    #[error("Invalid path or permissions")]
    FsMistrust {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<fs_mistrust::Error>,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// The action that caused an [`ArtiNativeKeystoreError::Filesystem`] or
/// [`ArtiNativeKeystoreError::FsMistrust`] error.
#[derive(Copy, Clone, Debug)]
pub(crate) enum FilesystemAction {
    /// Filesystem key store initialization.
    Init,
    /// Filesystem read
    Read,
    /// Filesystem write
    Write,
    /// Filesystem remove
    Remove,
}

impl KeystoreError for ArtiNativeKeystoreError {}

impl AsRef<dyn StdError> for ArtiNativeKeystoreError {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        self
    }
}

impl HasKind for ArtiNativeKeystoreError {
    fn kind(&self) -> ErrorKind {
        // TODO hs
        ErrorKind::Other
    }
}
