//! Errors to do with pluggable transports.

use fs_mistrust::anon_home::PathExt as _;
use futures::task::SpawnError;
use std::path::PathBuf;
use std::sync::Arc;
use tor_chanmgr::factory::AbstractPtError;
use tor_config_path::{CfgPath, CfgPathError};
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
    TransportGaveError {
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
    #[error("Couldn't execute PT binary at {}: {}", path.anonymize_home(), error)]
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
    /// We couldn't create a state directory.
    #[error("Failed to create a state directory at {}: {}", path.anonymize_home(), error)]
    StatedirCreateFailed {
        /// The offending path.
        path: PathBuf,
        /// The error encountered.
        #[source]
        error: Arc<std::io::Error>,
    },
    /// We couldn't expand a path.
    #[error("Failed to expand path {}: {}", path, error)]
    PathExpansionFailed {
        /// The offending path.
        path: CfgPath,
        /// The error encountered.
        #[source]
        error: CfgPathError,
    },
    /// A binary path does not have the syntax of a *file* name.
    ///
    /// For example, it ends in a slash, indicating a directory.
    //
    // TODO: this should be rejected at the configuration parsing level, and treated as a bug here.
    #[error("Configured binary path {} doesn't have syntax of a file", path.anonymize_home())]
    NotAFile {
        /// The offending path.
        path: PathBuf,
    },
    /// Unable to spawn reactor task.
    #[error("Unable to spawn reactor task.")]
    Spawn {
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
    /// The requested transport was found to be missing due to racing with reconfiguration
    #[error("Transport not found due to concurrent reconfiguration")]
    // TODO: That this can occur at all is a bug.
    // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/901#note_2858455
    UnconfiguredTransportDueToConcurrentReconfiguration,
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
            | E::TransportGaveError { .. }
            | E::ChildGone
            | E::ChildReadFailed(_)
            | E::ChildSpawnFailed { .. }
            | E::ProxyError(_) => EK::ExternalToolFailed,
            E::StatedirCreateFailed { .. } => EK::PersistentStateAccessFailed,
            E::UnconfiguredTransportDueToConcurrentReconfiguration => EK::TransientFailure,
            E::PathExpansionFailed { .. } => EK::InvalidConfig,
            E::NotAFile { .. } => EK::InvalidConfig,
            E::Internal(e) => e.kind(),
            E::Spawn { cause, .. } => cause.kind(),
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
            | E::NotAFile { .. }
            | E::UnsupportedVersion
            | E::Internal(_)
            | E::Spawn { .. }
            | E::PathExpansionFailed { .. } => RT::Never,
            E::StatedirCreateFailed { .. }
            | E::TransportGaveError { .. }
            | E::Timeout
            | E::UnconfiguredTransportDueToConcurrentReconfiguration
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
