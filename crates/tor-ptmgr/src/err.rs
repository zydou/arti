//! Errors to do with pluggable transports.

use std::path::PathBuf;
use std::sync::Arc;
use tor_chanmgr::factory::AbstractPtError;
use tor_config::{CfgPath, CfgPathError};
use tor_error::{ErrorKind, HasKind, HasRetryTime, RetryTime};

/// An error spawning or managing a pluggable transport.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PtError {
    /// We failed to launch a set of pluggable transports in the provided deadline.
    #[error("PT launch timed out")]
    Timeout,
    /// A PT binary does not support a set of pluggable transports.
    #[error("PT binary does not support transports: {0:?}")]
    ClientTransportsUnsupported(Vec<String>),
    /// A PT binary failed to launch a pluggable transport, and reported
    /// an error message.
    #[error("Transport '{}' failed to launch, saying: {:?}", transport, message)]
    ClientTransportGaveError {
        /// The transport that failed.
        transport: String,
        /// The failure message.
        message: String,
    },
    /// A pluggable transport binary failed to understand us.
    #[error("PT reported protocol error: {0}")]
    ChildProtocolViolation(String),
    /// A pluggable transport binary violated the protocol.
    #[error("PT violated protocol: {0}")]
    ProtocolViolation(String),
    /// A pluggable transport binary doesn't support version 1 of the IPC protocol.
    #[error("PT binary uses unsupported protocol version")]
    UnsupportedVersion,
    /// A pluggable transport binary couldn't use the provided proxy URI.
    #[error("PT binary failed to use proxy URI: {0}")]
    ProxyError(String),
    /// A pluggable transport binary quit or was stopped.
    #[error("PT binary gone")]
    ChildGone,
    /// An error was encountered communicating with a pluggable transport binary. The PT is no
    /// longer usable.
    #[error("Failed to read from PT binary: {0}")]
    ChildReadFailed(Arc<std::io::Error>),
    /// We couldn't spawn a pluggable transport binary as a child process.
    #[error("Couldn't execute PT binary at {}: {}", path.to_string_lossy(), error)]
    ChildSpawnFailed {
        /// The binary path we tried to execute.
        path: PathBuf,
        /// The I/O error returned.
        #[source]
        error: Arc<std::io::Error>,
    },
    /// We failed to parse something a pluggable transport sent us.
    #[error("Couldn't parse IPC line \"{}\": {}", line, error)]
    IpcParseFailed {
        /// The offending line.
        line: String,
        /// The error encountered parsing it.
        error: String,
    },
    /// We couldn't create a temporary directory.
    #[error("Failed to create a temporary directory: {0}")]
    TempdirCreateFailed(#[source] Arc<std::io::Error>),
    /// We couldn't expand a path.
    #[error("Failed to expand path {}: {}", path, error)]
    PathExpansionFailed {
        /// The offending path.
        path: CfgPath,
        /// The error encountered.
        #[source]
        error: CfgPathError,
    },
    /// The pluggable transport reactor failed.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

impl HasKind for PtError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use PtError as E;
        match self {
            E::ClientTransportsUnsupported(_) => EK::InvalidConfig,
            E::ChildProtocolViolation(_)
            | E::ProtocolViolation(_)
            | E::UnsupportedVersion
            | E::IpcParseFailed { .. } => EK::LocalProtocolViolation,
            E::Timeout
            | E::ClientTransportGaveError { .. }
            | E::ChildGone
            | E::ChildReadFailed(_)
            | E::ChildSpawnFailed { .. }
            | E::ProxyError(_) => EK::ExternalToolFailed,
            E::TempdirCreateFailed(_) => EK::FsPermissions,
            E::PathExpansionFailed { .. } => EK::InvalidConfig,
            E::Internal(e) => e.kind(),
        }
    }
}

impl HasRetryTime for PtError {
    fn retry_time(&self) -> RetryTime {
        use PtError as E;
        use RetryTime as RT;
        match self {
            E::ClientTransportsUnsupported(_)
            | E::ChildProtocolViolation(_)
            | E::ProtocolViolation(_)
            | E::IpcParseFailed { .. }
            | E::UnsupportedVersion
            | E::Internal(_)
            | E::PathExpansionFailed { .. } => RT::Never,
            E::TempdirCreateFailed(_)
            | E::ClientTransportGaveError { .. }
            | E::Timeout
            | E::ProxyError(_)
            | E::ChildGone
            | E::ChildReadFailed(_) => RT::AfterWaiting,
            E::ChildSpawnFailed { error, .. } => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    RT::Never
                } else {
                    RT::AfterWaiting
                }
            }
        }
    }
}

impl AbstractPtError for PtError {}

/// Standard-issue `Result` alias, with [`PtError`].
pub type Result<T> = std::result::Result<T, PtError>;
