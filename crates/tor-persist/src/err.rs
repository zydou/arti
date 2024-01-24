//! Error types for `tor-persist.

use std::sync::Arc;

use crate::FsMistrustErrorExt as _;
use fs_mistrust::anon_home::PathExt as _;
use tor_error::ErrorKind;

/// A resource that we failed to access or where we found a problem.
#[derive(Debug, Clone, derive_more::Display)]
pub(crate) enum Resource {
    /// The manager as a whole.
    #[display(fmt = "persistent storage manager")]
    Manager,
    /// A checked directory.
    #[display(fmt = "directory {}", "dir.anonymize_home()")]
    Directory {
        /// The path to the directory.    
        dir: std::path::PathBuf,
    },
    /// A file on disk within our checked directory.
    #[display(fmt = "{} in {}", "file.display()", "container.anonymize_home()")]
    File {
        /// The path to the checked directory
        container: std::path::PathBuf,
        /// The path within the checked directory to the file.
        file: std::path::PathBuf,
    },
    /// Testing-only: a scratch-item in a memory-backed store.
    #[cfg(feature = "testing")]
    #[display(fmt = "{} in memory-backed store", key)]
    Temporary {
        /// The key for the scratch item
        key: String,
    },
}

/// An action that we were trying to perform when an error occurred.
#[derive(Debug, Clone, derive_more::Display, Eq, PartialEq)]
pub(crate) enum Action {
    /// We were trying to load an element from the store.
    #[display(fmt = "loading persistent data")]
    Loading,
    /// We were trying to save an element into the store.
    #[display(fmt = "storing persistent data")]
    Storing,
    /// We were trying to remove an element from the store.
    #[display(fmt = "storing persistent data")]
    Deleting,
    /// We were trying to acquire the lock for the store.
    #[display(fmt = "acquiring lock")]
    Locking,
    /// We were trying to release the lock for the store.
    #[display(fmt = "releasing lock")]
    Unlocking,
    /// We were trying to validate the storage and initialize the manager.
    #[display(fmt = "constructing storage manager")]
    Initializing,
}

/// An underlying error manipulating persistent state.
///
/// Since these are more or less orthogonal to what we were doing and where the
/// problem was, this is a separate type.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum ErrorSource {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// Permissions on a file or path were incorrect
    #[error("Invalid permissions")]
    Permissions(#[source] fs_mistrust::Error),

    /// Tried to save without holding an exclusive lock.
    //
    // TODO This error seems to actually be sometimes used to make store a no-op.
    //      We should consider whether this is best handled as an error, but for now
    //      this seems adequate.
    #[error("Storage not locked")]
    NoLock,

    /// Problem when serializing or deserializing JSON data.
    #[error("JSON error")]
    Serde(#[from] Arc<serde_json::Error>),
}

/// An error that occurred while manipulating persistent state.
#[derive(Clone, Debug, derive_more::Display)]
#[display(fmt = "{} while {} on {}", source, action, resource)]
pub struct Error {
    /// The underlying error failure.
    source: ErrorSource,
    /// The action we were trying to perform
    action: Action,
    /// The resource we were trying to perform it on.
    resource: Resource,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

impl Error {
    /// Return the underlying error source.
    pub fn source(&self) -> &ErrorSource {
        &self.source
    }

    /// Construct a new Error from its components.
    pub(crate) fn new(err: impl Into<ErrorSource>, action: Action, resource: Resource) -> Self {
        Error {
            source: err.into(),
            action,
            resource,
        }
    }
}

impl tor_error::HasKind for Error {
    #[rustfmt::skip] // the tabular layout of the `match` makes this a lot clearer
    fn kind(&self) -> ErrorKind {
        use ErrorSource as E;
        use tor_error::ErrorKind as K;
        match &self.source {
            E::IoError(..)     => K::PersistentStateAccessFailed,
            E::Permissions(e)  => e.state_error_kind(),
            E::NoLock          => K::BadApiUsage,
            E::Serde(..) if self.action == Action::Storing  => K::Internal,
            E::Serde(..) => K::PersistentStateCorrupted,
        }
    }
}

impl From<std::io::Error> for ErrorSource {
    fn from(e: std::io::Error) -> ErrorSource {
        ErrorSource::IoError(Arc::new(e))
    }
}

impl From<serde_json::Error> for ErrorSource {
    fn from(e: serde_json::Error) -> ErrorSource {
        ErrorSource::Serde(Arc::new(e))
    }
}

impl From<fs_mistrust::Error> for ErrorSource {
    fn from(e: fs_mistrust::Error) -> ErrorSource {
        match e {
            fs_mistrust::Error::Io { err, .. } => ErrorSource::IoError(err),
            other => ErrorSource::Permissions(other),
        }
    }
}
