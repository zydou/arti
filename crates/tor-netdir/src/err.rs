//! Declare error type for tor-netdir

use thiserror::Error;
use tor_error::HasKind;

/// An error returned by the network directory code
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// We don't have enough directory info to build circuits
    #[error("Not enough directory information to build circuits")]
    NotEnoughInfo,
    /// We don't have any directory information.
    #[error("No directory information available")]
    NoInfo,
    /// We have directory information, but it is too expired to use.
    #[error("Directory is expired, and we haven't got a new one yet")]
    DirExpired,
    /// We have directory information, but it is too expired to use.
    #[error("Directory is published too far in the future: Your clock is probably wrong")]
    DirNotYetValid,
    /// We received a consensus document that should be impossible.
    #[error("Invalid information from consensus document: {0}")]
    InvalidConsensus(&'static str),
}

impl HasKind for Error {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use Error as E;
        match self {
            E::DirExpired => EK::DirectoryExpired,
            E::DirNotYetValid => EK::ClockSkew,
            E::NotEnoughInfo | E::NoInfo => EK::BootstrapRequired,
            E::InvalidConsensus(_) => EK::TorProtocolViolation,
        }
    }
}

/// An error returned when looking up onion service directories.
#[derive(Error, Clone, Debug)]
#[cfg(feature = "onion-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "onion-common")))]
#[non_exhaustive]
pub enum OnionDirLookupError {
    /// We tried to look up an onion service directory for a time period that
    /// did not correspond to one of our hash rings.
    #[error("Tried to look up an onion service directory for an invalid time period.")]
    WrongTimePeriod,
}

#[cfg(feature = "onion-common")]
impl HasKind for OnionDirLookupError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use OnionDirLookupError as E;
        match self {
            E::WrongTimePeriod => EK::BadApiUsage,
        }
    }
}
