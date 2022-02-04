//! Declare tor client specific errors.

use std::fmt::{self, Display};
use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;
use tor_circmgr::TargetPorts;
use tor_error::{ErrorKind, HasKind};
use tor_rtcompat::TimeoutError;

/// Wrapper for definitions which need to vary according to `error_details`
macro_rules! define_according_to_cfg_error_details { { $vis:vis } => {
// We cheat with the indentation, a bit.  Happily rustfmt doesn't seem to mind.

/// Main high-level error type for the Arti Tor client
///
/// If you need to handle different errors differently,
/// use the [`kind`](`tor_error::HasKind::kind`) trait method
/// to check what kind of error it is,
#[derive(Error, Debug)]
// TODO #[derive(Clone)] // we need to make everything inside Clone first
// TODO Use assert_impl! or something to ensure this is Send Sync Clone Debug Display 'static
//   as per https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/262#note_2772823
//   bullet point 5
#[allow(clippy::exhaustive_structs)]
pub struct TorError {
    /// The actual error
    #[source]
    $vis detail: Box<Error>,
}

/// Alias for the [`Result`] type used within the `arti_client` crate.
$vis type Result<T> = std::result::Result<T, Error>;

impl From<Error> for TorError {
    fn from(detail: Error) -> TorError {
        TorError {
            detail: detail.into(),
        }
    }
}

/// Represents errors that can occur while doing Tor operations.
#[derive(Error, Debug)]
#[non_exhaustive]
// should be $vis
// but right now we need to re-export it unconditionally
pub enum Error {
    /// Error setting up the circuit manager
    #[error("Error setting up the circuit manager {0}")]
    CircMgrSetup(#[source] tor_circmgr::Error), // TODO should this be its own type?

    /// Failed to obtain exit circuit
    #[error("Failed to obtain exit circuit for {exit_ports}")]
    ObtainExitCircuit {
        /// What for
        exit_ports: TargetPorts,

        /// What went wrong
        #[source]
        cause: tor_circmgr::Error,
    },

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

// End of the use of $vis to refer to visibility according to `error_detail`
} }

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
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::ObtainExitCircuit { cause, .. } => cause.kind(),
            _ => EK::TODO,
        }
    }
}

#[cfg(feature = "error_detail")]
define_according_to_cfg_error_details! { pub }

#[cfg(not(feature = "error_detail"))]
define_according_to_cfg_error_details! { pub(crate) }
