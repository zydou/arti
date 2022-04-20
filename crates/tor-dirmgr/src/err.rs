//! Declare an error type for the tor-dirmgr crate.

use std::sync::Arc;

use crate::DocSource;
use futures::task::SpawnError;
use thiserror::Error;
use tor_error::{ErrorKind, HasKind};

/// An error originated by the directory manager code
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// We received a document we didn't want at all.
    #[error("unwanted object: {0}")]
    Unwanted(&'static str),
    /// This DirMgr doesn't support downloads.
    #[error("tried to download information on a DirMgr with no download support")]
    NoDownloadSupport,
    /// We couldn't read something from disk that we should have been
    /// able to read.
    #[error("corrupt cache: {0}")]
    CacheCorruption(&'static str),
    /// rusqlite gave us an error.
    #[error("sqlite error: {0}")]
    SqliteError(#[source] Arc<rusqlite::Error>),
    /// A schema version that says we can't read it.
    #[error("unrecognized data storage schema")]
    UnrecognizedSchema,
    /// We couldn't configure the network.
    #[error("bad network configuration")]
    BadNetworkConfig(&'static str),
    /// User requested an operation that required a usable
    /// bootstrapped directory, but we didn't have one.
    #[error("directory not present or not up-to-date")]
    DirectoryNotPresent,
    /// A consensus document is signed by an unrecognized authority set.
    #[error("authorities on consensus do not match what we expect.")]
    UnrecognizedAuthorities,
    /// A directory manager has been dropped; background tasks can exit too.
    #[error("dirmgr has been dropped; background tasks exiting")]
    ManagerDropped,
    /// We made a bunch of attempts, but weren't unable to advance the
    /// state of a download.
    #[error("unable to finish bootstrapping a directory")]
    CantAdvanceState,
    /// Blob storage error
    #[error("storage error: {0}")]
    StorageError(String),
    /// An error given by the consensus diff crate.
    #[error("consdiff error: {0}")]
    ConsensusDiffError(#[from] tor_consdiff::Error),
    /// Invalid UTF8 in directory response.
    #[error("invalid utf-8 from directory server")]
    BadUtf8FromDirectory(#[source] std::string::FromUtf8Error),
    /// Invalid UTF8 from our cache.
    #[error("Invalid utf-8 in directory cache")]
    BadUtf8InCache(#[source] std::str::Utf8Error),
    /// Invalid hexadecimal value in the cache.
    #[error("Invalid hexadecimal id in directory cache")]
    BadHexInCache(#[source] hex::FromHexError),
    /// An error given by the network document crate.
    #[error("netdoc error from {source}: {cause}")]
    NetDocError {
        /// Where the document came from.
        source: DocSource,
        /// What error we got.
        #[source]
        cause: tor_netdoc::Error,
    },
    /// An error caused by an expired or not-yet-valid object.
    #[error("object expired or not yet valid.")]
    UntimelyObject(#[from] tor_checkable::TimeValidityError),
    /// An error given by dirclient
    #[error("dirclient error: {0}")]
    DirClientError(#[from] tor_dirclient::Error),
    /// An error given by the checkable crate.
    #[error("checkable error: {0}")]
    SignatureError(#[source] Arc<signature::Error>),
    /// An IO error occurred while manipulating storage on disk.
    #[error("IO error: {0}")]
    IOError(#[source] Arc<std::io::Error>),
    /// An attempt was made to bootstrap a `DirMgr` created in offline mode.
    #[error("cannot bootstrap offline DirMgr")]
    OfflineMode,

    /// Unable to spawn task
    #[error("unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Other error from an external directory provider
    #[error("external directory provider")]
    ExternalDirProvider {
        /// What happened
        #[source]
        cause: Arc<dyn std::error::Error + Send + Sync + 'static>,

        /// The kind
        kind: ErrorKind,
    },

    /// A programming problem, either in our code or the code calling it.
    #[error("programming problem: {0}")]
    Bug(#[from] tor_error::Bug),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(Arc::new(err))
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Self {
        Self::SignatureError(Arc::new(err))
    }
}

impl Error {
    /// Construct a new `Error` from a `SpawnError`.
    pub(crate) fn from_spawn(spawning: &'static str, err: SpawnError) -> Error {
        Error::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }

    /// Construct a new `Error` from `tor_netdoc::Error`.
    ///
    /// Also takes a source so that we can keep track of where the document came from.
    pub(crate) fn from_netdoc(source: DocSource, cause: tor_netdoc::Error) -> Error {
        Error::NetDocError { source, cause }
    }

    /// Return true if this error is serious enough that we should mark this
    /// cache as having failed.
    pub(crate) fn indicates_cache_failure(&self) -> bool {
        match self {
            // These indicate a problem from the cache.
            Error::Unwanted(_)
            | Error::UnrecognizedAuthorities
            | Error::BadUtf8FromDirectory(_)
            | Error::ConsensusDiffError(_)
            | Error::SignatureError(_)
            | Error::IOError(_)
            | Error::UntimelyObject(_) => true,

            // These errors cannot come from a directory cache.
            Error::NoDownloadSupport
            | Error::CacheCorruption(_)
            | Error::SqliteError(_)
            | Error::UnrecognizedSchema
            | Error::BadNetworkConfig(_)
            | Error::DirectoryNotPresent
            | Error::ManagerDropped
            | Error::CantAdvanceState
            | Error::StorageError(_)
            | Error::BadUtf8InCache(_)
            | Error::BadHexInCache(_)
            | Error::OfflineMode
            | Error::Spawn { .. }
            | Error::Bug(_) => false,

            // For this one, we delegate.
            Error::DirClientError(e) => e.should_retire_circ(),

            // TODO: This one is special.  It could mean that the directory
            // cache is serving us bad unparsable stuff, or it could mean that
            // for some reason we're unable to parse a real legit document.
            //
            // If the cache is serving us something unparsable, it might be
            // because the cache doesn't know all the same parsing rules for the
            // object that we know.  That case might need special handling to
            // avoid erroneously avoiding a good cache... especially if the document
            // is one that the cache could be tricked into serving us.
            Error::NetDocError { .. } => true,

            // We can never see this kind of error from within the crate.
            Error::ExternalDirProvider { .. } => false,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        use ErrorKind as EK;
        let kind = sqlite_error_kind(&err);
        match kind {
            EK::Internal | EK::BadApiUsage => {
                // TODO: should this be a .is_bug() on EK ?
                tor_error::Bug::from_error(kind, err, "sqlite detected bug").into()
            }
            _ => Self::SqliteError(Arc::new(err)),
        }
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Unwanted(_) => EK::TorProtocolViolation,
            E::NoDownloadSupport => EK::NotImplemented,
            E::CacheCorruption(_) => EK::CacheCorrupted,
            E::SqliteError(e) => sqlite_error_kind(e),
            E::UnrecognizedSchema => EK::CacheCorrupted,
            E::BadNetworkConfig(_) => EK::InvalidConfig,
            E::DirectoryNotPresent => EK::DirectoryExpired,
            E::BadUtf8FromDirectory(_) => EK::TorProtocolViolation,
            E::BadUtf8InCache(_) => EK::CacheCorrupted,
            E::BadHexInCache(_) => EK::CacheCorrupted,
            E::UnrecognizedAuthorities => EK::TorProtocolViolation,
            E::ManagerDropped => EK::ArtiShuttingDown,
            E::CantAdvanceState => EK::TorAccessFailed,
            E::StorageError(_) => EK::CacheAccessFailed,
            E::ConsensusDiffError(_) => EK::TorProtocolViolation,
            E::NetDocError { source, .. } => match source {
                DocSource::LocalCache => EK::CacheCorrupted,
                DocSource::DirServer { .. } => EK::TorProtocolViolation,
            },
            E::UntimelyObject(_) => EK::TorProtocolViolation,
            E::DirClientError(e) => e.kind(),
            E::SignatureError(_) => EK::TorProtocolViolation,
            E::IOError(_) => EK::CacheAccessFailed,
            E::OfflineMode => EK::BadApiUsage,
            E::Spawn { cause, .. } => cause.kind(),
            E::ExternalDirProvider { kind, .. } => *kind,
            E::Bug(e) => e.kind(),
        }
    }
}

/// Convert a sqlite error code into a real ErrorKind.
fn sqlite_error_kind(e: &rusqlite::Error) -> ErrorKind {
    use rusqlite::ErrorCode as RE;
    use ErrorKind as EK;

    match e {
        rusqlite::Error::SqliteFailure(code, _) => match code.code {
            RE::DatabaseCorrupt => EK::CacheCorrupted,
            RE::SchemaChanged
            | RE::TooBig
            | RE::ConstraintViolation
            | RE::TypeMismatch
            | RE::ApiMisuse
            | RE::NoLargeFileSupport
            | RE::ParameterOutOfRange
            | RE::OperationInterrupted
            | RE::ReadOnly
            | RE::OperationAborted
            | RE::DatabaseBusy
            | RE::DatabaseLocked
            | RE::OutOfMemory
            | RE::InternalMalfunction => EK::Internal,

            RE::FileLockingProtocolFailed
            | RE::AuthorizationForStatementDenied
            | RE::NotFound
            | RE::DiskFull
            | RE::CannotOpen
            | RE::SystemIoFailure
            | RE::PermissionDenied => EK::CacheAccessFailed,
            RE::NotADatabase => EK::InvalidConfig,
            _ => EK::Internal,
        },

        // TODO: Some of the other sqlite error types can sometimes represent
        // possible database corruption (like UTF8Error.)  But I haven't
        // found a way to distinguish when.
        _ => EK::Internal,
    }
}
