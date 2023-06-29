//! An error type for [`ArtiNativeKeystore`](crate::ArtiNativeKeystore).

use crate::KeystoreError;
use tor_error::{ErrorKind, HasKind};

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// An error returned by [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)'s
/// [`Keystore`](crate::Keystore) implementation.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum ArtiNativeKeystoreError {
    /// An error that occurred while accessing the filesystem.
    #[error("IO error on {path} while attempting to {action}")]
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
    #[error("Invalid path or permissions on {path} while attempting to {action}")]
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
#[derive(Copy, Clone, Debug, derive_more::Display)]
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

impl HasKind for ArtiNativeKeystoreError {
    fn kind(&self) -> ErrorKind {
        use ArtiNativeKeystoreError as KE;

        match self {
            KE::Filesystem { .. } => ErrorKind::KeystoreAccessFailed,
            KE::FsMistrust { .. } => ErrorKind::KeystoreFsPermissions,
            KE::Bug(e) => e.kind(),
        }
    }
}
