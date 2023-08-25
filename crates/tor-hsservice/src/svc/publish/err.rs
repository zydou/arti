//! Error types for `publish` module.

use std::sync::Arc;

use futures::task::SpawnError;

/// An error from creating or talking with a Publisher.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum PublisherError {
    /// Unable to spawn task
    //
    // TODO lots of our Errors have a variant exactly like this.
    // Maybe we should make a struct tor_error::SpawnError.
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
}

impl PublisherError {
    /// Construct a new `PublisherError` from a `SpawnError`.
    //
    // TODO lots of our Errors have a function exactly like this.
    pub(super) fn from_spawn(spawning: &'static str, err: SpawnError) -> PublisherError {
        PublisherError::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }
}
