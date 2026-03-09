//! Declare an error type for the tor-consdiff crate.

use thiserror::Error;
use tor_netdoc::parse2;

use std::num::ParseIntError;

/// An error type from the tor-consdiff crate.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// We got a consensus diff that we couldn't parse, or which we found
    /// to be somehow invalid.
    // TODO: it would be neat to have line numbers here.
    #[error("Invalid diff: {0}")]
    BadDiff(&'static str),

    /// We got a consensus diff that looked valid, but we couldn't apply it
    /// to the given input.
    #[error("Diff didn't apply to input: {0}")]
    CantApply(&'static str),

    /// Invalid input for consdiff computation supplied, most likely not a valid
    /// consensus.
    #[error("Invalid input supplied: {0}")]
    InvalidInput(parse2::ParseError),

    /// Internal error.
    #[error("Internal error")]
    Bug(tor_error::Bug),
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Error {
        Error::BadDiff("can't parse line number")
    }
}
impl From<hex::FromHexError> for Error {
    fn from(_e: hex::FromHexError) -> Error {
        Error::BadDiff("invalid hexadecimal in 'hash' line")
    }
}

impl From<parse2::ParseError> for Error {
    fn from(e: parse2::ParseError) -> Self {
        Self::InvalidInput(e)
    }
}

impl From<tor_error::Bug> for Error {
    fn from(e: tor_error::Bug) -> Self {
        Self::Bug(e)
    }
}

/// An error type for consensus diff generation.
///
// TODO: Potentially make this a first-class citizen error and rename Error to
// ApplyConsDiffError.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum GenEdDiffError {
    /// Diff results in the insertion of a line with a single dot, which is not
    /// possible according to the specification.
    #[error("Dotline found at {0}")]
    ContainsDotLine(usize),

    /// Formatting error, mostly convenience to allow for `?` in write calls.
    #[error("Formatting error: {0}")]
    Write(#[from] std::fmt::Error),
}
