//! Declare an error type for the `tor-hsservice` crate.

use std::sync::Arc;
use std::time::Duration;

use futures::task::SpawnError;

use thiserror::Error;

use tor_error::error_report;
use tor_error::{Bug, ErrorKind, HasKind};

pub use crate::svc::rend_handshake::{EstablishSessionError, IntroRequestError};
use crate::HsNickname;

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
        cause: tor_keymgr::Error,
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

/// Latest time to retry a failed IPT store (eg, disk full)
// TODO HSS configure?
const IPT_STORE_RETRY_MAX: Duration = Duration::from_secs(60);

/// An error arising when trying to store introduction points
///
/// These don't escape the crate, except to be logged.
///
/// These errors might be fatal, or they might be something we should retry.
#[derive(Clone, Debug, Error)]
pub(crate) enum IptStoreError {
    /// Unable to store introduction points
    #[error("Unable to store introduction points")]
    Store(#[from] tor_persist::Error),

    /// Fatal error
    #[error("Fatal error")]
    Fatal(#[from] FatalError),
}

impl From<Bug> for IptStoreError {
    fn from(bug: Bug) -> IptStoreError {
        FatalError::from(bug).into()
    }
}

impl IptStoreError {
    /// Log this error, and report latest time to retry
    ///
    /// It's OK to retry this earlier, if we are prompted somehow by other work;
    /// this is the longest time we should wait, so that we poll periodically
    /// to see if the situation has improved.
    ///
    /// If the operation shouldn't be retried, the problem was a fatal error,
    /// which is simply returned.
    // TODO HSS should this be a HasRetryTime impl instead?  But that has different semantics.
    pub(crate) fn log_retry_max(self, nick: &HsNickname) -> Result<Duration, FatalError> {
        use IptStoreError as ISE;
        let wait = match self {
            ISE::Store(_) => IPT_STORE_RETRY_MAX,
            ISE::Fatal(e) => return Err(e),
        };
        error_report!(self, "HS service {}: error", nick);
        Ok(wait)
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

    /// Failed to access the keystore.
    #[error("failed to access keystore")]
    Keystore(#[from] tor_keymgr::Error),

    /// The identity keypair of the service could not be found in the keystore.
    #[error("Hidden service identity key not found: {0}")]
    MissingHsIdKeypair(HsNickname),

    /// An error caused by a programming issue . or a failure in another
    /// library that we can't work around.
    #[error("Programming error")]
    Bug(#[from] Bug),
}

impl HasKind for FatalError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use FatalError as FE;
        match self {
            FE::Spawn { cause, .. } => cause.kind(),
            FE::Keystore(e) => e.kind(),
            FE::MissingHsIdKeypair(_) => EK::Internal, // TODO HSS this is wrong
            FE::Bug(e) => e.kind(),
        }
    }
}
