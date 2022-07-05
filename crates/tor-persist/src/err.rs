//! Error types for `tor-persist.

use std::sync::Arc;

use tor_error::ErrorKind;

/// An error manipulating persistent state.
//
// Such errors are "global" in the sense that it doesn't relate to any guard or any circuit
// or anything, so callers may use `#[from]` when they include it in their own error.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// Permissions on a file or path were incorrect
    #[error("Invalid permissions on state file")]
    Permissions(#[from] fs_mistrust::Error),

    /// Tried to save without holding an exclusive lock.
    //
    // TODO This error seems to actually be sometimes used to make store a no-op.
    //      We should consider whether this is best handled as an error, but for now
    //      this seems adequate.
    #[error("Storage not locked")]
    NoLock,

    /// Problem when serializing JSON data.
    #[error("JSON serialization error")]
    Serialize(#[source] Arc<serde_json::Error>),

    /// Problem when deserializing JSON data.
    #[error("JSON serialization error")]
    Deserialize(#[source] Arc<serde_json::Error>),
}

impl tor_error::HasKind for Error {
    #[rustfmt::skip] // the tabular layout of the `match` makes this a lot clearer
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use tor_error::ErrorKind as K;
        match self {
            E::IoError(..)     => K::PersistentStateAccessFailed,
            E::Permissions(e)  => if e.is_bad_permission() {
                K::FsPermissions
            } else {
                K::PersistentStateAccessFailed
            }
            E::NoLock          => K::BadApiUsage,
            E::Serialize(..)   => K::Internal,
            E::Deserialize(..) => K::PersistentStateCorrupted,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(Arc::new(e))
    }
}

impl Error {
    /// Error conversion for JSON errors; use only when loading
    pub(crate) fn loading(e: serde_json::Error) -> Error {
        Error::Deserialize(Arc::new(e))
    }

    /// Error conversion for JSON errors; use only when storing
    pub(crate) fn storing(e: serde_json::Error) -> Error {
        Error::Serialize(Arc::new(e))
    }
}
