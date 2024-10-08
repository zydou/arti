//! Internal: Declare an Error type for tor-bytes

use std::borrow::Cow;
use std::num::NonZeroUsize;

use derive_deftly::{define_derive_deftly, Deftly};
use safelog::Sensitive;
use thiserror::Error;
use tor_error::{into_internal, Bug};

define_derive_deftly! {
    /// `impl PartialEq for Error`
    PartialEqForError expect items:

    impl PartialEq for $ttype {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
              $(
                ${when not(vmeta(never_eq))}
                #[allow(deprecated)]
                (${vpat fprefix=a_}, ${vpat fprefix=b_}) => {
                  $(
                    if $<a_ $fname> != $<b_ $fname> { return false; }
                  )
                    return true;
                },
              )
                (_, _) => false,
            }
        }
    }
}

/// Error type for decoding Tor objects from bytes.
//
// TODO(nickm): This error type could use a redesign: it doesn't do a good job
// of preserving context.  At the least it should say what kind of object it
// found any given problem in.
#[derive(Error, Debug, Clone, Deftly)]
#[derive_deftly(PartialEqForError)]
#[non_exhaustive]
pub enum Error {
    /// Something was truncated
    ///
    /// It might be an inner data structure, or the outer message being parsed.
    #[deprecated(since = "0.22.0", note = "Use Reader::incomplete_error instead.")]
    #[error("something was truncated (maybe inner structure, maybe outer message)")]
    Truncated,
    /// Tried to read something, but we didn't find enough bytes.
    ///
    /// This can means that the outer object is truncated.
    /// Possibly we need to read more and try again,
    ///
    /// This error is only returned by [`Reader`](crate::Reader)s created with
    /// [`from_possibly_incomplete_slice`](crate::Reader::from_possibly_incomplete_slice).
    ///
    /// # Do not directly construct this variant
    ///
    /// It is usually a bug to explicitly construct this variant.
    /// Use [`Reader::incomplete_error`](crate::Reader::incomplete_error) instead.
    ///
    /// In tests using
    /// [`Reader::from_slice_for_test`](crate::Reader::from_slice_for_test),
    /// use [`Error::new_incomplete_for_test`].
    #[error("Object truncated (or not fully present), at least {deficit} more bytes needed")]
    Incomplete {
        /// Lower bound on number of additional bytes needed
        deficit: Sensitive<NonZeroUsize>,
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
    ///
    /// # General case, more specific variants also exist
    ///
    /// This variant is used when encountering parsing trouble
    /// for which there is no more specific variant.
    ///
    /// Other variants can occur when deserialising malformed messages.
    /// for example (but not necessarily only):
    /// [`ExtraneousBytes`](Error::ExtraneousBytes),
    /// [`MissingData`](Error::MissingData), and
    /// [`BadLengthValue`](Error::BadLengthValue).
    #[error("Bad object: {0}")]
    InvalidMessage(Cow<'static, str>),
    /// The message contains data which is too short (perhaps in an inner counted section)
    ///
    /// # Usually, do not directly construct this variant
    ///
    /// It is often a bug to explicitly construct this variant.
    /// Consider [`Reader::incomplete_error`](crate::Reader::incomplete_error) instead.
    ///
    /// (It can be appropriate in test cases,
    /// or during bespoke parsing of an inner substructure.)
    #[error("message (or inner portion) too short")]
    MissingData,
    /// A parsing error that should never happen.
    ///
    /// We use this one in lieu of calling assert() and expect() and
    /// unwrap() from within parsing code.
    #[error("Internal error")]
    #[deftly(never_eq)] // an internal error is equal to nothing, not even itself.
    Bug(#[from] tor_error::Bug),
}

impl Error {
    /// Make an [`Error::Incomplete`] with a specified deficit
    ///
    /// Suitable for use in tests.
    ///
    /// # Panics
    ///
    /// Panics if the specified `deficit` is zero.
    pub fn new_incomplete_for_test(deficit: usize) -> Self {
        let deficit = NonZeroUsize::new(deficit)
            .expect("zero deficit in assert!")
            .into();
        Error::Incomplete { deficit }
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
