//! Declare an error type for the `tor-hsservice` crate.

use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;

use tor_error::{Bug, ErrorKind, HasKind};
use tor_keymgr::KeystoreError;

pub use crate::svc::rend_handshake::{EstablishSessionError, IntroRequestError};

/// An error which occurs trying to create and start up an onion service
///
/// This is only returned by startup methods.
/// After the service is created and started,
/// we will continue to try keep the service alive,
/// retrying things as necessary.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum StartupError {
    /// A keystore operation failed.
    #[error("Keystore error while attempting to {action}")]
    Keystore {
        /// The action we were trying to perform.
        action: &'static str,
        /// The underlying error
        #[source]
        cause: Box<dyn KeystoreError>,
    },

    /// Keystore corruption.
    #[error("The keystore is unrecoverably corrupt")]
    KeystoreCorrupted,

    /// Unable to spawn task
    //
    // TODO too many types have an open-coded version of FooError::Spawn
    // Instead we should:
    //  * Have tor_rtcompat provide a SpawnError struct which contains the task identifier
    //  * Have tor_rtcompat provide a spawn method that takes an identifier
    //    (and which passes that identifier to runtimes that support such a thing,
    //    including our own mock spawner)
    //  * Change every crate's task spawning and error handling to use the new things
    //    (breaking changes to the error type, unless we retain unused compat error variants)
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Tried to launch an onion service that has already been launched.
    #[error("Onion service has already been launched")]
    AlreadyLaunched,
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use StartupError as E;
        match self {
            E::Keystore { cause, .. } => cause.kind(),
            E::KeystoreCorrupted => EK::KeystoreCorrupted,
            E::Spawn { cause, .. } => cause.kind(),
            E::AlreadyLaunched => EK::BadApiUsage,
        }
    }
}

/// An error which occurs trying to communicate with a particular client.
///
/// This is returned by `RendRequest::accept` and `StreamRequest::accept`.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Failed to process an INTRODUCE2 request.
    #[error("Could not process INTRODUCE request")]
    BadIntroduce(#[source] IntroRequestError),

    /// Failed to complete a rendezvous request.
    #[error("Could not connect rendezvous circuit.")]
    EstablishSession(#[source] EstablishSessionError),

    /// Failed to send a CONNECTED message and get a stream.
    #[error("Could not accept stream from rendezvous circuit")]
    AcceptStream(#[source] tor_proto::Error),

    /// Failed to send a END message and reject a stream.
    #[error("Could not reject stream from rendezvous circuit")]
    RejectStream(#[source] tor_proto::Error),
}

impl HasKind for ClientError {
    fn kind(&self) -> ErrorKind {
        match self {
            ClientError::BadIntroduce(e) => e.kind(),
            ClientError::EstablishSession(e) => e.kind(),
            ClientError::AcceptStream(e) => e.kind(),
            ClientError::RejectStream(e) => e.kind(),
        }
    }
}

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
