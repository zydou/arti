//! An error type for the `tor-keymgr` crate.

use tor_error::{ErrorKind, HasKind};
#[cfg(feature = "keymgr")]
use {crate::key_type::ssh::SshKeyAlgorithm, crate::KeyType};

use dyn_clone::DynClone;
use thiserror::Error;

#[cfg(feature = "keymgr")]
use {std::io, std::path::PathBuf, std::sync::Arc};

use std::error::Error as StdError;
use std::fmt;

/// An Error type for this crate.
// TODO hs: replace Error with BoxedError
#[allow(unreachable_pub)]
pub type BoxedError = Box<dyn KeystoreError>;

/// An error returned by a [`KeyStore`](crate::KeyStore).
// TODO hs: replace Error with KeyStoreError and create an `ArtiNativeKeyStoreError: KeyStoreError`
// type for ArtiNativeKeyStore.
pub trait KeystoreError:
    HasKind + AsRef<dyn StdError> + DynClone + fmt::Debug + fmt::Display + Send + Sync + 'static
{
}

// Generate a Clone impl for Box<dyn KeystoreError>
dyn_clone::clone_trait_object!(KeystoreError);

impl<K: KeystoreError + Send + Sync> From<K> for BoxedError {
    fn from(k: K) -> Self {
        Box::new(k)
    }
}

impl StdError for BoxedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        let e: &dyn StdError = self;
        e.source()
    }
}

/// A key store error.
//
// TODO hs: refactor this error type.
//
// Here is a non-exhaustive list of potential improvements:
//   * use dyn KeySpecifier instead of ArtiPath in the error context
//   * use an enum for the FileSystem action instead of a static string
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred while accessing the filesystem.
    #[error("An error occurred while accessing the filesystem")]
    #[cfg(feature = "keymgr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
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

    /// Encountered a malformed key.
    #[error("Malformed key: {0}")]
    #[cfg(feature = "keymgr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
    MalformedKey(#[from] MalformedKeyErrorSource),

    /// An internal error.
    #[error("Internal error")]
    #[cfg(feature = "keymgr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
    Bug(#[from] tor_error::Bug),

    /// Key manager support disabled in cargo features
    #[error("Key manager support disabled in cargo features")]
    #[cfg(not(feature = "keymgr"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "keymgr"))))]
    KeyMgrNotSupported,
}

/// The underlying cause of an [`Error::Filesystem`] error.
//
// TODO hs (#901): this introduces multiple levels of error `#[source]` nesting.
//
// When addressing #901, turn `FsErrorSource::IoError` into a new variant of the outer `Error` type
// rather than a variant of `Filesystem`.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[cfg(feature = "keymgr")]
pub enum FsErrorSource {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// Permissions on a file or path were incorrect
    #[error("Invalid permissions")]
    Permissions(#[source] fs_mistrust::Error),
}

#[cfg(feature = "keymgr")]
impl From<io::Error> for FsErrorSource {
    fn from(e: io::Error) -> FsErrorSource {
        FsErrorSource::IoError(Arc::new(e))
    }
}

#[cfg(feature = "keymgr")]
impl From<fs_mistrust::Error> for FsErrorSource {
    fn from(e: fs_mistrust::Error) -> FsErrorSource {
        match e {
            fs_mistrust::Error::Io { err, .. } => FsErrorSource::IoError(err),
            other => FsErrorSource::Permissions(other),
        }
    }
}

/// The underlying cause of an [`Error::MalformedKey`] error.
//
// TODO hs (#901): this introduces multiple levels of error `#[source]` nesting.
//
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[cfg(feature = "keymgr")]
pub enum MalformedKeyErrorSource {
    /// Failed to parse an OpenSSH key
    #[error("Failed to parse OpenSSH with type {key_type:?}")]
    SshKeyParse {
        /// The type of key we were trying to fetch.
        key_type: KeyType,
        /// The underlying error.
        #[source]
        err: Arc<ssh_key::Error>,
    },

    /// The OpenSSH key we retrieved is of the wrong type.
    #[error("Unexpected OpenSSH key type: wanted {wanted_key_algo}, found {found_key_algo}")]
    UnexpectedSshKeyType {
        /// The algorithm we expected the key to use.
        wanted_key_algo: SshKeyAlgorithm,
        /// The algorithm of the key we got.
        found_key_algo: SshKeyAlgorithm,
    },

    // TODO hs: remove
    /// Unsupported key type.
    #[error("Found a key type we don't support yet: {0:?}")]
    Unsupported(KeyType),
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        // TODO hs: create `ErrorKind` variants for `tor_keymgr::Error`s.
        match self {
            #[cfg(feature = "keymgr")]
            Error::Filesystem { .. } => todo!(),
            #[cfg(feature = "keymgr")]
            Error::MalformedKey { .. } => todo!(),
            #[cfg(feature = "keymgr")]
            Error::Bug(e) => e.kind(),
            #[cfg(not(feature = "keymgr"))]
            Error::KeyMgrNotSupported => ErrorKind::Other,
        }
    }
}
