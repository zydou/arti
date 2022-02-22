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
    /// We started building a circuit on a guard, but later decided not
    /// to use that guard.
    //
    // TODO: We shouldn't count this as an error for the purposes of the number
    // of allowable failures of a circuit request.
    #[error("Discarded circuit because of speculative guard selection")]
    GuardNotUsable,

    /// We were waiting on a pending circuit, but it failed to report
    #[error("Pending circuit(s) failed without reporting status")]
    PendingCanceled,

    /// A circuit succeeded, but was cancelled before it could be used.
    ///
    /// Circuits can be cancelled either by a call to
    /// `retire_all_circuits()`, or by a configuration change that
    /// makes old paths unusable.
    //
    // TODO: We shouldn't count this as an error for the purposes of the number
    // of allowable failures of a circuit request.
    #[error("Circuit canceled")]
    CircCanceled,

    /// A circuit build took too long to finish.
    #[error("Circuit took too long to build")]
    CircTimeout,

    /// A request spent too long waiting for a circuit
    #[error("Spent too long waiting for a circuit to build")]
    RequestTimeout,

    /// No suitable relays for a request
    #[error("Can't build path for circuit: {0}")]
    NoPath(String),

    /// No suitable exit relay for a request.
    #[error("Can't find exit for circuit: {0}")]
    NoExit(String),

    /// Problem creating or updating a guard manager.
    #[error("Problem creating or updating guards list: {0}")]
    GuardMgr(#[source] tor_guardmgr::GuardMgrError),

    /// Problem selecting a guard relay.
    #[error("Unable to select a guard relay: {0}")]
    Guard(#[from] tor_guardmgr::PickGuardError),

    /// Unable to get or build a circuit, despite retrying.
    #[error("{0}")]
    RequestFailed(RetryError<Box<Error>>),

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

    /// Problem loading or storing persistent state.
    #[error("Problem loading or storing state: {0}")]
    State(#[from] tor_persist::Error),

    /// An error caused by a programming issue . or a failure in another
    /// library that we can't work around.
    #[error("Programming issue: {0}")]
    Bug(#[from] Bug),
}

impl From<futures::channel::oneshot::Canceled> for Error {
    fn from(_: futures::channel::oneshot::Canceled) -> Error {
        Error::PendingCanceled
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
            E::PendingCanceled => EK::ReactorShuttingDown,
            E::CircTimeout => EK::TorNetworkTimeout,
            E::GuardNotUsable => EK::TransientFailure,
            E::RequestTimeout => EK::TorNetworkTimeout,
            E::RequestFailed(e) => e
                .sources()
                .max_by_key(|e| e.severity())
                .map(|e| e.kind())
                .unwrap_or(EK::Internal),
            E::CircCanceled => EK::TransientFailure,
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

    /// Return an integer representing the relative severity of this error.
    ///
    /// Used to determine which error to use when determining the kind of a retry error.
    fn severity(&self) -> usize {
        use Error as E;
        match self {
            E::GuardNotUsable => 10,
            E::PendingCanceled => 20,
            E::CircCanceled => 20,
            E::CircTimeout => 30,
            E::RequestTimeout => 30,
            E::NoPath(_) => 40,
            E::NoExit(_) => 40,
            E::GuardMgr(_) => 40,
            E::Guard(_) => 40,
            E::RequestFailed(_) => 40,
            E::Channel { .. } => 40,
            E::Protocol(_) => 45,
            E::ExpiredConsensus => 50,
            E::Spawn { .. } => 90,
            E::State(_) => 90,
            E::Bug(_) => 100,
        }
    }
}
