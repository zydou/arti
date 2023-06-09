//! An error type for the `tor-keymgr` crate.

use crate::key_type::ssh::SshKeyAlgorithm;
use crate::KeyType;
use tor_error::{ErrorKind, HasKind};

use thiserror::Error;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// A key store error.
//
// TODO hs: refactor this error type.
//
// Here is a non-exhaustive list of potential improvements:
//   * use dyn KeySpecifier instead of ArtiPath in the error context
//   * use an enum for the FileSystem action instead of a static string
//   * decide what NotFound is supposed to mean (it has a double meaning
//   right now: "not found in any of the key stores" when returned by KeyMgr,
//   and "not found in this key store" when
//   returned by a KeyStore)
//   * Create a KeystoreCorruption variant (UnexpectedSshKeyType would be one of the potential
//   causes of this error)
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred while accessing the filesystem.
    #[error("An error occurred while accessing the filesystem")]
    Filesystem {
        /// The action we were trying to perform.
        //
        // TODO hs: consider using an enum instead of a static string
        action: &'static str,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: FsErrorSource,
    },

    /// The requested key was not found.
    #[error("Key not found")]
    NotFound {/* TODO hs: add context */},

    /// Failed to read an OpenSSH key
    #[error("Failed to read OpenSSH from {path} with type {key_type:?}")]
    SshKeyRead {
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The type of key we were trying to fetch.
        key_type: KeyType,
        /// The underlying error.
        #[source]
        err: Arc<ssh_key::Error>,
    },

    /// The OpenSSH key we retrieved is of the wrong type.
    #[error(
        "Unexpected OpenSSH key type at {path:?}: wanted {wanted_key_algo}, found {found_key_algo}"
    )]
    UnexpectedSshKeyType {
        /// The path of the key we were trying to fetch.
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

/// The underlying cause of an [`Error::KeyStoreFile`] error.
//
// TODO hs (#901): this introduces multiple levels of error `#[source]` nesting.
//
// When addressing #901, turn `FsErrorSource::IoError` into a new variant of the outer `Error` type
// rather than a variant of `Filesystem`.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum FsErrorSource {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),
}

impl From<io::Error> for FsErrorSource {
    fn from(e: io::Error) -> FsErrorSource {
        FsErrorSource::IoError(Arc::new(e))
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        // TODO hs: create `ErrorKind` variants for `tor_keymgr::Error`s.
        match self {
            Error::Filesystem { .. } => todo!(),
            Error::NotFound { .. } => todo!(),
            Error::SshKeyRead { .. } => todo!(),
            Error::UnexpectedSshKeyType { .. } => todo!(),
            Error::Bug(e) => e.kind(),
        }
    }
}
