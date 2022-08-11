//! Error handling.

use thiserror::Error;
use tor_error::{ErrorKind, HasKind};

/// Result alias using this crate's error type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error originating from the tor-congestion crate.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// A call to `RoundtripTimeEstimator::sendme_received` was made without calling
    /// `RoundtripTimeEstimator::expect_sendme` first.
    #[error("Informed of a SENDME we weren't expecting")]
    MismatchedEstimationCall,
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        match self {
            E::MismatchedEstimationCall => ErrorKind::TorProtocolViolation,
        }
    }
}
