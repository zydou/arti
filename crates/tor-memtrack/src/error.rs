//! Errors arising from memory tracking

use crate::internal_prelude::*;

/// An error occurring when tracking memory usage
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum Error {
    /// The memory quota tracker has been torn down
    #[error("attempted to use shut down memory tracker")]
    TrackerShutdown,

    /// The Account has been torn down
    ///
    /// This can happen if the account or participant has Collapsed due to reclamation
    #[error("memory pressure (attempted to use closed memory tracking account)")]
    AccountClosed,

    /// The Participant has been torn down
    ///
    /// This can happen if the account or participant has Collapsed due to reclamation
    #[error("memory pressure (attempt to allocate by torn-down memory tracking participant)")]
    ParticipantShutdown,

    /// Previous bug, memory quota tracker is corrupted
    #[error("memory tracker is corrupted due to previous bug")]
    TrackerCorrupted,

    /// Bug
    #[error("internal error")]
    Bug(#[from] Bug),
}

/// An error occurring when setting up a memory quota tracker
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum StartupError {
    /// Task spawn failed
    #[error("couldn't spawn reclamation task")]
    Spawn(#[source] Arc<SpawnError>),
}

impl From<SpawnError> for StartupError {
    fn from(e: SpawnError) -> StartupError {
        StartupError::Spawn(Arc::new(e))
    }
}

/// Tracker corrupted
///
/// Separate type so we don't expose `PoisonError -> crate::Error` conversion
#[derive(Debug, Clone, Error)]
#[error("poisoned( corrupted)")]
pub(crate) struct TrackerCorrupted;

impl<T> From<PoisonError<T>> for TrackerCorrupted {
    fn from(_: PoisonError<T>) -> TrackerCorrupted {
        TrackerCorrupted
    }
}

impl From<TrackerCorrupted> for Error {
    fn from(_: TrackerCorrupted) -> Error {
        Error::TrackerCorrupted
    }
}

/// Error returned when reclaim task crashes
///
/// Does not escape the crate; is used for logging.
#[derive(Debug, Clone, Error)]
pub(crate) enum ReclaimCrashed {
    /// Previous bug, memory quota tracker is corrupted
    #[error("memory tracker corrupted due to previous bug")]
    TrackerCorrupted(#[from] TrackerCorrupted),

    /// Bug
    #[error("internal error")]
    Bug(#[from] Bug),
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::TrackerShutdown => EK::ArtiShuttingDown,
            E::AccountClosed => EK::LocalResourceExhausted,
            E::ParticipantShutdown => EK::LocalResourceExhausted,
            E::TrackerCorrupted => EK::Internal,
            E::Bug(e) => e.kind(),
        }
    }
}
