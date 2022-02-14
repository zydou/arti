//! Declare error type for tor-netdir

use thiserror::Error;

/// An error returned by the network directory code
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Problem reading a document from disk.
    #[error("io error: {0:?}")]
    Io(#[from] std::io::Error),
    /// Incorrect signature on a document.
    #[error("bad signature")]
    Sig(#[from] signature::Error),
    /// An object is expired or not yet valid.
    #[error("not currently valid: {0}")]
    Untimely(#[from] tor_checkable::TimeValidityError),
    /// We received a document we didn't want at all.
    #[error("unwanted object: {0}")]
    Unwanted(&'static str),
    /// A document was completely unreadable.
    #[error("bad document: {0}")]
    BadDoc(#[from] tor_netdoc::Error),
    /// A bad argument was provided to some configuration function.
    #[error("bad argument: {0}")]
    BadArgument(&'static str),
    /// We couldn't read something from disk that we should have been
    /// able to read.
    #[error("corrupt cache: {0}")]
    CacheCorruption(&'static str),
    /// We don't have enough directory info to build circuits
    #[error("not enough directory information to build circuits")]
    NotEnoughInfo,
    /// Failed to construct a testing document.
    #[cfg(any(test, feature = "testing"))]
    #[error("could not build testing document")]
    CannotBuildTestnetDoc(#[from] tor_netdoc::BuildError),
}
