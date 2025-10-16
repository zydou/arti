//! Declare error types for the `tor-guardmgr` crate.

use futures::task::SpawnError;
use std::sync::Arc;
use std::time::Instant;
use tor_basic_utils::iter::FilterCount;
use tor_error::{Bug, ErrorKind, HasKind};

/// A error caused by a failure to pick a guard.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PickGuardError {
    /// All members of the current sample were down or unusable.
    #[error(
        "No usable guards. Rejected {} as down, then {} as pending, then \
         {} as unsuitable to purpose, then {} with filter.{}",
        running.display_frac_rejected(),
        pending.display_frac_rejected(),
        suitable.display_frac_rejected(),
        filtered.display_frac_rejected(),
        if let Some(retry_at) = retry_at {
            format!(" Retrying in {:?}.", humantime::format_duration(*retry_at - Instant::now()))
        } else {
            "".to_string()
        },
    )]
    AllGuardsDown {
        /// The next time at which any guard will be retriable.
        retry_at: Option<Instant>,
        /// How many guards we rejected because they had failed too recently.
        running: FilterCount,
        /// How many guards we rejected because we are already probing them.
        pending: FilterCount,
        /// How many guards we rejected as unsuitable for the intended application.
        suitable: FilterCount,
        /// How many guards we rejected because of the provided filter.
        filtered: FilterCount,
    },

    /// We have no usable fallback directories.
    #[error(
        "No usable fallbacks. Rejected {} as not running, then {} as filtered.", 
         running.display_frac_rejected(),
        filtered.display_frac_rejected()
    )]
    AllFallbacksDown {
        /// The next time at which any fallback directory will back available.
        retry_at: Option<Instant>,
        /// The number of fallbacks that were believed to be running or down, after applying
        /// the filter.
        running: FilterCount,
        /// The number of fallbacks that satisfied our filter, or did not.
        filtered: FilterCount,
    },

    /// Tried to select guards or fallbacks from an empty list.
    #[error("Tried to pick from an empty list")]
    NoCandidatesAvailable,

    /// An internal programming error occurred.
    #[error("Internal error")]
    Internal(#[from] Bug),
}

impl tor_error::HasKind for PickGuardError {
    fn kind(&self) -> tor_error::ErrorKind {
        use PickGuardError as E;
        use tor_error::ErrorKind as EK;
        match self {
            E::AllFallbacksDown { .. } | E::AllGuardsDown { .. } => EK::TorAccessFailed,
            E::NoCandidatesAvailable => EK::NoPath,
            E::Internal(_) => EK::Internal,
        }
    }
}

impl tor_error::HasRetryTime for PickGuardError {
    fn retry_time(&self) -> tor_error::RetryTime {
        use PickGuardError as E;
        use tor_error::RetryTime as RT;
        match self {
            // Some errors contain times that we can just use.
            E::AllGuardsDown {
                retry_at: Some(when),
                ..
            } => RT::At(*when),
            E::AllFallbacksDown {
                retry_at: Some(when),
                ..
            } => RT::At(*when),

            // If we don't know when the guards/fallbacks will be back up,
            // though, then we should suggest a random delay.
            E::AllGuardsDown { .. } | E::AllFallbacksDown { .. } => RT::AfterWaiting,

            // We were asked to choose some kind of guard that doesn't exist in
            // our current universe; that's not going to be come viable down the
            // line.
            E::NoCandidatesAvailable => RT::Never,

            // Don't try to recover from internal errors.
            E::Internal(_) => RT::Never,
        }
    }
}
/// An error caused while creating or updating a guard manager.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GuardMgrError {
    /// An error manipulating persistent state
    #[error("Problem accessing persistent guard state")]
    State(#[from] tor_persist::Error),

    /// Configuration is not valid or available
    #[error("Invalid configuration")]
    InvalidConfig(#[from] GuardMgrConfigError),

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
            G::InvalidConfig(e)       => e.kind(),
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

/// An error encountered while configuring or reconfiguring a guard manager
///
/// When this occurs during initial configuration, it will be returned wrapped
/// up in `GuardMgrError`.
///
/// When it occurs during reconfiguration, it is not exposed to caller:
/// instead, it is converted into a `tor_config::ReconfigureError`.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GuardMgrConfigError {
    /// Specified configuration requires exclusive access to stored state, which we don't have
    #[error(
        "Configuration requires exclusive access to shared state, but another instance of Arti has the lock: {0}"
    )]
    NoLock(String),
}

impl From<GuardMgrConfigError> for tor_config::ReconfigureError {
    fn from(g: GuardMgrConfigError) -> tor_config::ReconfigureError {
        use GuardMgrConfigError as G;
        use tor_config::ReconfigureError as R;
        match g {
            e @ G::NoLock(_) => R::UnsupportedSituation(e.to_string()),
        }
    }
}

impl HasKind for GuardMgrConfigError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use GuardMgrConfigError as G;
        match self {
            // `InvalidConfig` and `FeatureDisabled` aren't right, because
            // those should be detected at config build time and reported as `ConfigBuildError`.
            // `InvalidConfigTransition` isn't right, because restarting arti won't help.
            // Possibly at some point we will allow concurrent artis to work this way.
            G::NoLock(_) => EK::NotImplemented,
        }
    }
}
