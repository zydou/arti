//! Helpers for reporting Arti errors via HTTP protocols.

use super::ErrorKind;
use http::StatusCode;

#[rustfmt::skip]
impl ErrorKind {
/// Return an HTTP status code corresponding to this `ErrorKind`.
///
/// These codes are not guaranteed to be the same across different versions of `tor-error`.
pub fn http_status_code(self) -> StatusCode {
    use ErrorKind as EK;
    use http::StatusCode as SC;
    match self {
        EK::ArtiShuttingDown
        | EK::BadApiUsage
        | EK::BootstrapRequired
        | EK::CacheAccessFailed
        | EK::CacheCorrupted
        | EK::ClockSkew
        | EK::DirectoryExpired
        | EK::ExternalToolFailed
        | EK::FsPermissions
        | EK::Internal
        | EK::InvalidConfig
        | EK::InvalidConfigTransition
        | EK::KeystoreAccessFailed
        | EK::KeystoreCorrupted
        | EK::NoHomeDirectory
        | EK::Other
        | EK::PersistentStateAccessFailed
        | EK::PersistentStateCorrupted
        | EK::SoftwareDeprecated
        | EK::TorDirectoryUnusable
        | EK::TransientFailure
        | EK::ReactorShuttingDown
        | EK::RelayIdMismatch
        | EK::RelayTooBusy
        | EK::TorAccessFailed
        | EK::TorDirectoryError => SC::INTERNAL_SERVER_ERROR,

        EK::FeatureDisabled | EK::NotImplemented => SC::NOT_IMPLEMENTED,

        EK::CircuitCollapse
        | EK::CircuitRefused
        | EK::ExitPolicyRejected
        | EK::LocalNetworkError
        | EK::LocalProtocolViolation
        | EK::LocalResourceAlreadyInUse
        | EK::LocalResourceExhausted
        | EK::NoExit
        | EK::NoPath => SC::SERVICE_UNAVAILABLE,

        EK::TorProtocolViolation | EK::RemoteProtocolViolation | EK::RemoteNetworkFailed => {
            SC::BAD_GATEWAY
        }

        EK::ExitTimeout | EK::TorNetworkTimeout | EK::RemoteNetworkTimeout => SC::GATEWAY_TIMEOUT,

        EK::ForbiddenStreamTarget => SC::FORBIDDEN,

        EK::OnionServiceAddressInvalid | EK::InvalidStreamTarget => SC::BAD_REQUEST,
        EK::OnionServiceWrongClientAuth => SC::FORBIDDEN,
        EK::OnionServiceConnectionFailed
        | EK::OnionServiceMissingClientAuth
        | EK::OnionServiceNotFound
        | EK::OnionServiceNotRunning
        | EK::OnionServiceProtocolViolation => SC::SERVICE_UNAVAILABLE,

        EK::RemoteConnectionRefused
        | EK::RemoteHostNotFound
        | EK::RemoteHostResolutionFailed
        | EK::RemoteStreamClosed
        | EK::RemoteStreamError
        | EK::RemoteStreamReset => SC::SERVICE_UNAVAILABLE,
    }
}
}
