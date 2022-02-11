//! Declare an error type for the tor-dirmgr crate.

use std::sync::Arc;

use futures::task::SpawnError;
use thiserror::Error;

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
    /// A bad argument was provided to some configuration function.
    #[error("bad argument: {0}")]
    BadArgument(&'static str),
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
    /// An updater no longer has anything to update.
    #[error("directory updater has shut down")]
    UpdaterShutdown,
    /// We couldn't configure the network.
    #[error("bad network configuration")]
    BadNetworkConfig(&'static str),
    /// User requested an operation that required a usable
    /// bootstrapped directory, but we didn't have one.
    #[error("directory not present or not up-to-date")]
    DirectoryNotPresent,
    /// Another process has locked the store for writing.
    #[error("couldn't get write lock on directory cache")]
    CacheIsLocked,
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
    /// An error emitted by the runtime. The argument is the formatted error of the runtime.
    #[error("runtime error: {0}")]
    RuntimeError(String),
    /// Blob storage error
    #[error("storage error: {0}")]
    StorageError(String),
    /// An error given by the consensus diff crate.
    #[error("consdiff error: {0}")]
    ConsensusDiffError(#[from] tor_consdiff::Error),
    /// A string parsing error.
    #[error("string parsing error: {0}")]
    StringParsingError(String),
    /// An error given by the network document crate.
    #[error("netdoc error: {0}")]
    NetDocError(#[from] tor_netdoc::Error),
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
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::StringParsingError(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::StringParsingError(err.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::StringParsingError(err.to_string())
    }
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

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Self::SqliteError(Arc::new(err))
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
}
