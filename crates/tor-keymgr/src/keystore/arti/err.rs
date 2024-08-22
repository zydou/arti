//! An error type for [`ArtiNativeKeystore`](crate::ArtiNativeKeystore).

use crate::{ArtiPathSyntaxError, KeystoreError, UnknownKeyTypeError};
use tor_error::{ErrorKind, HasKind};
use tor_keys::{KeyType, SshKeyAlgorithm};

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

    /// Encountered an inaccessible path or invalid permissions.
    #[error("Inaccessible path or bad permissions on {path} while attempting to {action}")]
    FsMistrust {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<fs_mistrust::Error>,
    },

    /// Found a key with an invalid path.
    #[error("Key has invalid path: {path}")]
    MalformedPath {
        /// The path of the key.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: MalformedPathError,
    },

    /// An error due to encountering an unsupported [`KeyType`].
    #[error("{0}")]
    UnknownKeyType(#[from] UnknownKeyTypeError),

    /// An error due to encountering a directory or symlink at a key path.
    #[error("File at {0} is not a regular file")]
    NotARegularFile(PathBuf),

    /// Failed to parse an OpenSSH key
    #[error("Failed to parse OpenSSH with type {key_type:?}")]
    SshKeyParse {
        /// The path of the malformed key.
        path: PathBuf,
        /// The type of key we were trying to fetch.
        key_type: KeyType,
        /// The underlying error.
        #[source]
        err: Arc<ssh_key::Error>,
    },

    /// The OpenSSH key we retrieved is of the wrong type.
    #[error("Unexpected OpenSSH key type: wanted {wanted_key_algo}, found {found_key_algo}")]
    UnexpectedSshKeyType {
        /// The path of the malformed key.
        path: PathBuf,
        /// The algorithm we expected the key to use.
        wanted_key_algo: SshKeyAlgorithm,
        /// The algorithm of the key we got.
        found_key_algo: SshKeyAlgorithm,
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

/// The keystore contained a file whose name syntactically improper
///
/// Keys are supposed to have pathnames consisting of an `ArtiPath`
/// followed by a file extension.
///
/// See also [`KeyPathError`](crate::KeyPathError), which occurs at a higher level.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum MalformedPathError {
    /// Found a key with a non-UTF-8 path.
    #[error("the path is not valid UTF-8")]
    Utf8,

    /// Found a key with no extension.
    #[error("no extension")]
    NoExtension,

    /// The file path is not a valid [`ArtiPath`](crate::ArtiPath).
    #[error("not a valid ArtiPath")]
    InvalidArtiPath(ArtiPathSyntaxError),
}

impl KeystoreError for ArtiNativeKeystoreError {}

impl HasKind for ArtiNativeKeystoreError {
    fn kind(&self) -> ErrorKind {
        use tor_persist::FsMistrustErrorExt as _;
        use ArtiNativeKeystoreError as KE;

        match self {
            KE::Filesystem { .. } => ErrorKind::KeystoreAccessFailed,
            KE::FsMistrust { err, .. } => err.keystore_error_kind(),
            KE::MalformedPath { .. } => ErrorKind::KeystoreAccessFailed,
            KE::UnknownKeyType(_) => ErrorKind::KeystoreAccessFailed,
            KE::NotARegularFile(_) => ErrorKind::KeystoreCorrupted,
            KE::SshKeyParse { .. } | KE::UnexpectedSshKeyType { .. } => {
                ErrorKind::KeystoreCorrupted
            }
            KE::Bug(e) => e.kind(),
        }
    }
}

impl From<ArtiNativeKeystoreError> for crate::Error {
    fn from(e: ArtiNativeKeystoreError) -> Self {
        crate::Error::Keystore(Arc::new(e))
    }
}
