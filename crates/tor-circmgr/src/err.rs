//! Declare an error type for tor-circmgr

use std::sync::Arc;

use futures::task::SpawnError;
use retry_error::RetryError;
use thiserror::Error;

use tor_error::{Bug, ErrorKind, HasKind};
use tor_linkspec::OwnedChanTarget;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// No suitable relays for a request
    #[error("Can't build path for circuit: {0}")]
    NoPath(String),

    /// No suitable exit relay for a request.
    #[error("Can't find exit for circuit: {0}")]
    NoExit(String),

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
    #[error("Circuit canceled")]
    CircCanceled,

    /// An error caused by a programming issue . or a failure in another
    /// library that we can't work around.
    #[error("Programming issue: {0}")]
    Bug(#[from] Bug),

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

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Channel { cause, .. } => cause.kind(),
            E::Bug(e) => e.kind(),
            E::NoPath(_) => EK::NoPath,
            E::NoExit(_) => EK::NoExit,
            E::PendingFailed => EK::TODO, // circuit failed, but it would be neat to have the error.
            E::CircTimeout => EK::CircuitTimeout,
            E::GuardNotUsable => EK::TODO, // ?????  This one is for speculative guard selection for guards we decided not to use.
            E::RequestTimeout => EK::CircuitTimeout,
            E::RequestFailed(e) => e
                .sources()
                // Treat the *final* failure reason as why we failed.
                // TODO(nickm) Is it reasonable to do so?
                .last()
                .map(|e| e.kind())
                .unwrap_or(EK::Internal),
            E::CircCanceled => EK::Canceled,
            E::Protocol(e) => e.kind(),
            E::State(e) => e.kind(),
            E::GuardMgr(e) => e.kind(),
            E::Guard(_) => EK::NoPath,
            E::ExpiredConsensus => EK::DirectoryExpired,
            E::Spawn { cause, .. } => cause.kind(),
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
