//! Error types for `tor-persist.

use std::sync::Arc;

use crate::slug::BadSlug;
use crate::FsMistrustErrorExt as _;
use fs_mistrust::anon_home::PathExt as _;
use tor_basic_utils::PathExt as _;
use tor_error::{into_bad_api_usage, Bug, ErrorKind};

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
    #[display(fmt = "{} in {}", "file.display_lossy()", "container.anonymize_home()")]
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
    /// An instance state directory
    #[display(
        fmt = "instance {:?}/{:?} in {}",
        "kind",
        "identity",
        "state_dir.anonymize_home()"
    )]
    InstanceState {
        /// The path to the top-level state directory.
        state_dir: std::path::PathBuf,
        /// The instance's kind
        kind: String,
        /// The instance's identity
        identity: String,
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
    #[display(fmt = "deleting persistent data")]
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
    /// We were trying to enumerate state objects
    #[display(fmt = "enumerating instances")]
    Enumerating,
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

    /// Another task or process holds this persistent state lock, but we need exclusive access
    #[error("State already lockedr")]
    AlreadyLocked,

    /// Programming error
    #[error("Programming error")]
    Bug(#[from] Bug),
}

impl From<BadSlug> for ErrorSource {
    fn from(bs: BadSlug) -> ErrorSource {
        into_bad_api_usage!("bad slug")(bs).into()
    }
}
/// [`BadSlug`] errors auto-convert to a [`BadApiUsage`](tor_error::ErrorKind::BadApiUsage)
///
/// (Users of `tor-persist` ought to have newtypes for user-supplied slugs,
/// and thereby avoid passing syntactically invalid slugs to `tor-persist`.)
impl From<BadSlug> for Error {
    fn from(bs: BadSlug) -> Error {
        // This metadata is approximate, but better information isn't readily available
        // and this shouldn't really happen.
        Error::new(bs, Action::Initializing, Resource::Manager)
    }
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
            E::AlreadyLocked   => K::LocalResourceAlreadyInUse,
            E::Bug(e)          => e.kind(),
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

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use std::io;
    use tor_error::ErrorReport as _;

    #[test]
    fn error_display() {
        assert_eq!(
            Error::new(
                io::Error::from(io::ErrorKind::PermissionDenied),
                Action::Initializing,
                Resource::InstanceState {
                    state_dir: "/STATE_DIR".into(),
                    kind: "KIND".into(),
                    identity: "IDENTY".into(),
                }
            )
            .report()
            .to_string(),
            r#"error: IO error while constructing storage manager on instance "KIND"/"IDENTY" in /STATE_DIR: permission denied"#
        );
    }
}
