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
        use Error as E;
        use tor_error::ErrorKind as EK;
        match self {
            E::DirExpired => EK::DirectoryExpired,
            E::DirNotYetValid => EK::ClockSkew,
            E::NotEnoughInfo | E::NoInfo => EK::BootstrapRequired,
            E::InvalidConsensus(_) => EK::TorProtocolViolation,
        }
    }
}

/// An error that has occurred while trying to decode a set of externally provided link specifiers
/// into a reasonable [`VerbatimLinkSpecCircTarget`](tor_linkspec::verbatim::VerbatimLinkSpecCircTarget).
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
#[cfg(feature = "hs-common")]
pub enum VerbatimCircTargetDecodeError {
    /// We failed to interpret the provided link specs, or didn't find enough detail in them.
    #[error("Unable to decode relay information")]
    CantDecode(#[from] tor_linkspec::decode::ChanTargetDecodeError),

    /// When we went to look up the relay, we found that the identities were not compatible with one another.
    #[error("Impossible combination of identities")]
    ImpossibleIds(#[source] crate::RelayLookupError),

    /// The onion key type was one that we don't support.
    #[error("Received an unsupported onion key type")]
    UnsupportedOnionKey,

    /// An internal error occurred, probably due to a programming mistake.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

/// An error returned when looking up onion service directories.
#[derive(Error, Clone, Debug)]
#[cfg(feature = "hs-common")]
#[non_exhaustive]
pub enum OnionDirLookupError {
    /// We tried to look up an onion service directory for a time period that
    /// did not correspond to one of our hash rings.
    #[error("Tried to look up an onion service directory for an invalid time period.")]
    WrongTimePeriod,
}

#[cfg(feature = "hs-common")]
impl HasKind for OnionDirLookupError {
    fn kind(&self) -> tor_error::ErrorKind {
        use OnionDirLookupError as E;
        use tor_error::ErrorKind as EK;
        match self {
            E::WrongTimePeriod => EK::BadApiUsage,
        }
    }
}
