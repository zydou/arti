//! Declare tor client specific errors.

use std::fmt::{self, Display};
use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;
use tor_error::{ErrorKind, HasKind};
use tor_rtcompat::TimeoutError;

/// Main high-level error type for the Arti Tor client
///
/// If you need to handle different errors differently,
/// use the [`kind`](`tor_error::HasKind::kind`) trait method
/// to check what kind of error it is,
#[derive(Error, Debug)]
// TODO #[derive(Clone)] // we need to make everything inside Clone first
pub struct TorError {
    /// The actual error
    #[from]
    detail: Error,
}

/// Represents errors that can occur while doing Tor operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Error while getting a circuit
    #[error("Error while getting a circuit {0}")]
    CircMgr(#[from] tor_circmgr::Error),

    /// Error while getting a circuit
    #[error("Directory state error {0}")]
    DirMgr(#[from] tor_dirmgr::Error),

    /// A protocol error while launching a stream
    #[error("Protocol error while launching a stream: {0}")]
    Proto(#[from] tor_proto::Error),

    /// An error while interfacing with the persistent data layer.
    #[error("Error from state manager: {0}")]
    Persist(#[from] tor_persist::Error),

    /// The directory cache took too long to reply to us.
    #[error("directory timed out")]
    Timeout,

    /// Onion services not supported.
    #[error("Rejecting .onion address as unsupported.")]
    OnionAddressNotSupported,

    /// Unusable target address.
    #[error("Could not parse target address: {0}")]
    Address(#[from] crate::address::TorAddrError),

    /// Hostname not valid.
    #[error("Rejecting hostname as invalid.")]
    InvalidHostname,

    /// Address was local, and that's not allowed.
    #[error("Cannot connect to a local-only address without enabling allow_local_addrs")]
    LocalAddress,

    /// An internal error of some kind that should never occur.
    #[error("Internal error: {0}")]
    Internal(&'static str),

    /// Building configuration for the client failed.
    #[error("Configuration failed: {0}")]
    Configuration(#[from] tor_config::ConfigBuildError),

    /// Unable to change configuration.
    #[error("Reconfiguration failed: {0}")]
    Reconfigure(#[from] tor_config::ReconfigureError),

    /// Unable to spawn task
    #[error("unable to spawn task")]
    Spawn(#[from] Arc<SpawnError>),
}

impl Display for TorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tor: {}: {}", self.detail.kind(), &self.detail)
    }
}

impl tor_error::HasKind for TorError {
    fn kind(&self) -> ErrorKind {
        self.detail.kind()
    }
}

impl From<TimeoutError> for Error {
    fn from(_: TimeoutError) -> Self {
        Error::Timeout
    }
}

impl From<SpawnError> for Error {
    fn from(e: SpawnError) -> Error {
        Arc::new(e).into()
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        ErrorKind::TODO
    }
}
