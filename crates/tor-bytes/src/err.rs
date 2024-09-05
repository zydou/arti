//! Internal: Declare an Error type for tor-bytes

use std::borrow::Cow;
use std::num::NonZeroUsize;

use thiserror::Error;
use tor_error::{into_internal, Bug};

/// Error type for decoding Tor objects from bytes.
//
// TODO(nickm): This error type could use a redesign: it doesn't do a good job
// of preserving context.  At the least it should say what kind of object it
// found any given problem in.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Tried to read something, but we didn't find enough bytes.
    ///
    /// This can mean that the object is truncated, or that we need to
    /// read more and try again, depending on the context in which it
    /// was received.
    #[error("Object truncated (or not fully present), at least {deficit} more bytes needed")]
    Truncated {
        /// Lower bound on number of additional bytes needed
        deficit: NonZeroUsize,
    },
    /// Called Reader::should_be_exhausted(), but found bytes anyway.
    #[error("Extra bytes at end of object")]
    ExtraneousBytes,
    /// Invalid length value
    #[error("Object length too large to represent as usize")]
    BadLengthValue,
    /// An attempt to parse an object failed for some reason related to its
    /// contents.
    #[deprecated(since = "0.6.2", note = "Use InvalidMessage instead.")]
    #[error("Bad object: {0}")]
    BadMessage(&'static str),
    /// An attempt to parse an object failed for some reason related to its
    /// contents.
    #[error("Bad object: {0}")]
    InvalidMessage(Cow<'static, str>),
    /// A parsing error that should never happen.
    ///
    /// We use this one in lieu of calling assert() and expect() and
    /// unwrap() from within parsing code.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (Truncated { deficit: a }, Truncated { deficit: b }) => a == b,
            (ExtraneousBytes, ExtraneousBytes) => true,
            #[allow(deprecated)]
            (BadMessage(a), BadMessage(b)) => a == b,
            (InvalidMessage(a), InvalidMessage(b)) => a == b,
            (BadLengthValue, BadLengthValue) => true,
            // notably, this means that an internal error is equal to nothing, not even itself.
            (_, _) => false,
        }
    }
}

impl Error {
    /// Make an [`Error::Truncated`] with a specified deficit
    ///
    /// Suitable for use in tests.
    ///
    /// # Panics
    ///
    /// Panics if the specified `deficit` is zero.
    pub fn new_truncated_for_test(deficit: usize) -> Self {
        let deficit = NonZeroUsize::new(deficit).expect("zero deficit in assert!");
        Error::Truncated { deficit }
    }
}

/// Error type for encoding Tor objects to bytes.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum EncodeError {
    /// We tried to encode an object with an attached length, but the length was
    /// too large to encode in the available space.
    #[error("Object length too large to encode")]
    BadLengthValue,
    /// A parsing error that should never happen.
    ///
    /// We use this variant instead of calling assert() and expect() and
    /// unwrap() from within encoding implementations.
    #[error("Internal error")]
    Bug(#[from] Bug),
}

impl EncodeError {
    /// Converts this error into a [`Bug`]
    ///
    /// Use when any encoding error is a bug.
    //
    // TODO: should this be a `From` impl or would that be too error-prone?
    #[deprecated(note = "please use the `From<EncodeError>` trait for `Bug` instead")]
    pub fn always_bug(self) -> Bug {
        match self {
            EncodeError::Bug(bug) => bug,
            EncodeError::BadLengthValue => into_internal!("EncodingError")(self),
        }
    }
}

// This trait is used to convert any encoding error into a bug
impl From<EncodeError> for Bug {
    fn from(error: EncodeError) -> Bug {
        match error {
            EncodeError::Bug(bug) => bug,
            EncodeError::BadLengthValue => into_internal!("EncodingError")(error),
        }
    }
}
