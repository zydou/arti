//! Declare an error type for the `tor-hsservice` crate.

use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;

use tor_error::Bug;

/// An error which occurs trying to create and start up an onion service
///
/// This is only returned by startup methods.
/// After the service is created and started,
/// we will continue to try keep the service alive,
/// retrying things as necessary.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum StartupError {}

/// An error which occurs trying to communicate with a particular client
///
/// This is returned by `RendRequest::accept` and `StreamRequest::accept`.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum ClientError {}

/// An error which means we cannot continue to try to operate an onion service.
///
/// These errors only occur during operation, and only for catastrophic reasons
/// (such as the async reactor shutting down).
//
// TODO HSS where is FatalError emitted from this crate into the wider program ?
// Perhaps there will be some kind of monitoring handle that can produce one of these.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum FatalError {
    /// Unable to spawn task
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },

    /// An error caused by a programming issue . or a failure in another
    /// library that we can't work around.
    #[error("Programming error")]
    Bug(#[from] Bug),
}
