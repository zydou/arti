//! Errors relating to being a hidden service client
use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;

use tor_error::{Bug, ErrorKind, HasKind};

/// Error that occurred attempting to reach a hidden service
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum ConnError {
    /// Unable to spawn
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

impl HasKind for ConnError {
    fn kind(&self) -> ErrorKind {
        use ConnError as CE;
        match self {
            CE::Spawn { cause, .. } => cause.kind(),
            CE::Bug(e) => e.kind(),
        }
    }
}

/// Error that occurred attempting to start up a hidden service client connector
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum StartupError {
    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use StartupError as SE;
        match self {
            SE::Bug(e) => e.kind(),
        }
    }
}
