//! Declare an error type for tor-circmgr

use std::sync::Arc;

use futures::task::SpawnError;
use retry_error::RetryError;
use thiserror::Error;

use tor_error::ErrorKind;
use tor_linkspec::OwnedChanTarget;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// No suitable relays for a request
    #[error("no relays for circuit: {0}")]
    NoRelays(String),

    /// We need to have a consensus directory to build this kind of
    /// circuits, and we only got a list of fallbacks.
    #[error("Consensus directory needed")]
    NeedConsensus,

    /// We were waiting on a pending circuit, but it didn't succeed.
    #[error("Pending circuit(s) failed to launch")]
    PendingFailed,

    /// A circuit build took too long to finish.
    #[error("Circuit took too long to build")]
    CircTimeout,

    /// We started building a circuit on a guard, but later decided not
    /// to use that guard.
    #[error("Discarded circuit because of speculative guard selection")]
    GuardNotUsable,

    /// Tried to take a circuit for a purpose it doesn't support.
    #[error("Circuit usage not supported: {0}")]
    UsageNotSupported(String),

    /// A request spent too long waiting for a circuit
    #[error("Spent too long waiting for a circuit to build")]
    RequestTimeout,

    /// Unable to get or build a circuit, despite retrying.
    #[error("{0}")]
    RequestFailed(RetryError<Box<Error>>),

    /// A circuit succeeded, but was cancelled before it could be used.
    ///
    /// Circuits can be cancelled either by a call to
    /// `retire_all_circuits()`, or by a configuration change that
    /// makes old paths unusable.
    #[error("Circuit cancelled")]
    CircCancelled,

    /// An error caused by a programming issue or a failure in another
    /// library that we can't work around.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Problem with channel
    #[error("Problem with channel to {peer}")]
    Channel {
        /// Which relay we were trying to connect to
        peer: OwnedChanTarget,

        /// What went wrong
        #[source]
        cause: tor_chanmgr::Error,
    },

    /// Protocol issue while building a circuit.
    #[error("Problem building a circuit: {0}")]
    Protocol(#[from] tor_proto::Error),

    /// Problem loading or storing persistent state.
    #[error("Problem loading or storing state: {0}")]
    State(#[from] tor_persist::Error),

    /// Problem creating or updating a guard manager.
    #[error("Problem creating or updating guards list: {0}")]
    GuardMgr(#[source] tor_guardmgr::GuardMgrError),

    /// Problem selecting a guard relay.
    #[error("Unable to select a guard relay: {0}")]
    Guard(#[from] tor_guardmgr::PickGuardError),

    /// We have an expired consensus
    #[error("Consensus is expired")]
    ExpiredConsensus,

    /// Unable to spawn task
    #[error("unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
}

impl From<futures::channel::oneshot::Canceled> for Error {
    fn from(_: futures::channel::oneshot::Canceled) -> Error {
        Error::PendingFailed
    }
}

impl From<tor_rtcompat::TimeoutError> for Error {
    fn from(_: tor_rtcompat::TimeoutError) -> Error {
        Error::CircTimeout
    }
}

impl From<tor_guardmgr::GuardMgrError> for Error {
    fn from(err: tor_guardmgr::GuardMgrError) -> Error {
        match err {
            tor_guardmgr::GuardMgrError::State(e) => Error::State(e),
            _ => Error::GuardMgr(err),
        }
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Channel { cause, .. } => cause.kind(),
            _ => EK::TODO,
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
