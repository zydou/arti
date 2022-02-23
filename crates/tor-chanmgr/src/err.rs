//! Declare error types for tor-chanmgr

use std::net::SocketAddr;
use std::sync::Arc;

use futures::task::SpawnError;
use thiserror::Error;

use tor_error::{internal, ErrorKind};

/// An error returned by a channel manager.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum Error {
    /// A ChanTarget was given for which no channel could be built.
    #[error("Target was unusable: {0}")]
    UnusableTarget(#[source] tor_error::Bug),

    /// We were waiting on a pending channel, but it didn't succeed.
    #[error("Pending channel failed to launch")]
    PendingFailed,

    /// It took too long for us to establish this connection.
    #[error("Channel timed out")]
    ChanTimeout,

    /// A protocol error while making a channel
    #[error("Protocol error while opening a channel: {0}")]
    Proto(#[from] tor_proto::Error),

    /// Network IO error or TLS error
    #[error("Network IO error, or TLS error, in {action}, talking to {peer}")]
    Io {
        /// Who we were talking to
        peer: SocketAddr,

        /// What we were doing
        action: &'static str,

        /// What happened.  Might be some TLS library error wrapped up in io::Error
        #[source]
        source: Arc<std::io::Error>,
    },

    /// Unable to spawn task
    #[error("unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
    /// An internal error of some kind that should never occur.
    #[error("Internal error: {0}")]
    Internal(#[from] tor_error::Bug),
}

impl From<tor_rtcompat::TimeoutError> for Error {
    fn from(_: tor_rtcompat::TimeoutError) -> Error {
        Error::ChanTimeout
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Error {
        Error::Internal(internal!("Thread failed while holding lock"))
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use tor_proto::Error as ProtoErr;
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::ChanTimeout | E::Io { .. } | E::Proto(ProtoErr::IoErr(_)) => EK::TorAccessFailed,
            E::Spawn { cause, .. } => cause.kind(),
            E::Proto(e) => e.kind(),
            E::PendingFailed => EK::TorAccessFailed,
            E::UnusableTarget(_) | E::Internal(_) => EK::Internal,
        }
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
