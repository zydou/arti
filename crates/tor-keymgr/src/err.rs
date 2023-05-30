//! An error type for the `tor-keymgr` crate.

use crate::key_type::ssh::SshKeyAlgorithm;
use crate::KeyType;
use tor_error::{ErrorKind, HasKind};

use thiserror::Error;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// A key store error.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred while accessing the filesystem.
    #[error("An error occurred while accessing the filesystem")]
    Filesystem {
        /// The action we were trying to perform.
        action: &'static str,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<io::Error>,
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
