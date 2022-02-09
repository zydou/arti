//! Internal: Declare an Error type for tor-bytes

use thiserror::Error;

/// Error type for decoding Tor objects from bytes.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Tried to read something, but we didn't find enough bytes.
    ///
    /// This can mean that the object is truncated, or that we need to
    /// read more and try again, depending on the context in which it
    /// was received.
    #[error("object truncated (or not fully present)")]
    Truncated,
    /// Called Reader::should_be_exhausted(), but found bytes anyway.
    #[error("extra bytes at end of object")]
    ExtraneousBytes,
    /// An attempt to parse an object failed for some reason related to its
    /// contents.
    #[error("bad object: {0}")]
    BadMessage(&'static str),
    /// A parsing error that should never happen.
    ///
    /// We use this one in lieu of calling assert() and expect() and
    /// unwrap() from within parsing code.
    #[error("internal programming error")]
    Internal(#[from] tor_error::InternalError),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (Truncated, Truncated) => true,
            (ExtraneousBytes, ExtraneousBytes) => true,
            (BadMessage(a), BadMessage(b)) => a == b,
            // notably, this means that an internal error is equal to nothing, not even itself.
            (_, _) => false,
        }
    }
}
