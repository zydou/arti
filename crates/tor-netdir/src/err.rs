//! Declare error type for tor-netdir

use thiserror::Error;

/// An error returned by the network directory code
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A document was completely unreadable.
    #[error("bad document: {0}")]
    BadDoc(#[from] tor_netdoc::Error),
    /// We don't have enough directory info to build circuits
    #[error("not enough directory information to build circuits")]
    NotEnoughInfo,
    /// Failed to construct a testing document.
    #[cfg(any(test, feature = "testing"))]
    #[error("could not build testing document")]
    CannotBuildTestnetDoc(#[from] tor_netdoc::BuildError),
}
