//! Miscellaneous straightforward error structs for particular situations

use thiserror::Error;

/// Error type indicating that an input was incomplete, and could not be
/// processed.
///
/// This type is kept separate from most other error types since it is not a
/// true error; usually, it just means that the calling function should read
/// more data and try again.
///
/// Don't return this error type for parsing errors that _can't_ be recovered
/// from by reading more data.
#[derive(Clone, Debug, Default, Error)]
#[error("Incomplete data; more input needed")]
#[non_exhaustive]
pub struct Truncated;

impl Truncated {
    /// Return a new [`Truncated`] instance.
    pub fn new() -> Self {
        Default::default()
    }
}
