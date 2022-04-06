//! Declare error types for the `tor-guardmgr` crate.

use futures::task::SpawnError;
use std::sync::Arc;
use std::time::Instant;
use tor_error::{ErrorKind, HasKind};

/// A error caused by a failure to pick a guard.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PickGuardError {
    /// All members of the current sample were down.
    #[error("All guards are down")]
    AllGuardsDown {
        /// The next time at which any guard will be retriable.
        retry_at: Option<Instant>,
    },

    /// Some guards were running, but all of them were either blocked on pending
    /// circuits at other guards, unusable for the provided purpose, or filtered
    /// out.
    #[error("No running guards were usable for the selected purpose")]
    NoGuardsUsable,

    /// We have no usable fallback directories.
    #[error("All fallback directories are down")]
    AllFallbacksDown {
        /// The next time at which any fallback directory will back available.
        retry_at: Option<Instant>,
    },

    /// Tried to select guards or fallbacks from an empty list.
    #[error("Tried to pick from an empty list")]
    NoCandidatesAvailable,
}

impl tor_error::HasKind for PickGuardError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use PickGuardError as E;
        match self {
            E::AllFallbacksDown { .. } | E::AllGuardsDown { .. } => EK::TorAccessFailed,
            E::NoGuardsUsable | E::NoCandidatesAvailable => EK::NoPath,
        }
    }
}

impl tor_error::HasRetryTime for PickGuardError {
    fn retry_time(&self) -> tor_error::RetryTime {
        use tor_error::RetryTime as RT;
        use PickGuardError as E;
        match self {
            // Some errors contain times that we can just use.
            E::AllGuardsDown {
                retry_at: Some(when),
            } => RT::At(*when),
            E::AllFallbacksDown {
                retry_at: Some(when),
            } => RT::At(*when),

            // If we don't know when the guards/fallbacks will be back up,
            // though, then we should suggest a random delay.
            E::AllGuardsDown { .. } | E::AllFallbacksDown { .. } => RT::AfterWaiting,

            // We were asked to choose some kind of guard that doesn't exist in
            // our current universe; that's not going to be come viable down the
            // line.
            E::NoGuardsUsable | E::NoCandidatesAvailable => RT::Never,
        }
    }
}
/// An error caused while creating or updating a guard manager.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GuardMgrError {
    /// An error manipulating persistent state
    #[error("Problem accessing persistent state")]
    State(#[from] tor_persist::Error),

    /// An error that occurred while trying to spawn a daemon task.
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
}

impl HasKind for GuardMgrError {
    #[rustfmt::skip] // to preserve table in match
    fn kind(&self) -> ErrorKind {
        use GuardMgrError as G;
        match self {
            G::State(e)               => e.kind(),
            G::Spawn{ cause, .. }     => cause.kind(),
        }
    }
}

impl GuardMgrError {
    /// Construct a new `GuardMgrError` from a `SpawnError`.
    pub(crate) fn from_spawn(spawning: &'static str, err: SpawnError) -> GuardMgrError {
        GuardMgrError::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }
}
