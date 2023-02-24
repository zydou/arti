//! Errors relating to being a hidden service client
use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;

use tor_error::Bug;

/// Error that occurred attempting to reach a hidden service
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum HsClientConnError {
    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),

    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },
}
