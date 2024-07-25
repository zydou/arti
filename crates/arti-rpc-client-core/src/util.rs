//! Helper utilities
//!

// TODO RPC: Consider replacing this with a derive-deftly template.
//
/// Define an `impl From<fromty> for toty`` that wraps its input as
/// `toty::variant(Arc::new(e))``
macro_rules! define_from_for_arc {
    { $fromty:ty => $toty:ty [$variant:ident] } => {
        impl From<$fromty> for $toty {
            fn from(e: $fromty) -> $toty {
                Self::$variant(std::sync::Arc::new(e))
            }
        }
    };
}
use std::ffi::{CStr, CString, NulError};

pub(crate) use define_from_for_arc;

/// A string that is guaranteed to be UTF-8 and NUL-terminated,
/// for fast access as either type.
//
// TODO RPC: Rename so we can expose it more sensibly.
#[derive(Clone, Debug)]
pub struct Utf8CString {
    /// The body of this string.
    ///
    /// # Safety
    ///
    /// INVARIANT: This string must be valid UTF-8.
    ///
    /// (We do not _yet_ depend on this invariant for safety in our rust code, but we do promise in
    /// our C ffi that it will hold.)
    string: Box<CStr>,
}

impl AsRef<CStr> for Utf8CString {
    fn as_ref(&self) -> &CStr {
        &self.string
    }
}

impl AsRef<str> for Utf8CString {
    fn as_ref(&self) -> &str {
        // TODO: We might someday decide to implement this using unsafe methods, to avoid walking
        // over the string to enforce properties that are already there.
        self.string.to_str().expect("Utf8CString was not UTF-8‽")
    }
}

// TODO: In theory we could have an unchecked version of this function, if we are 100%
// sure that serde_json will reject every string that contains a NUL.  But let's not do
// that unless the NUL check shows up in profiles.
impl TryFrom<String> for Utf8CString {
    type Error = NulError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Safety: Since `value` is a string, it is guaranteed to be UTF-8.
        Ok(Utf8CString {
            string: CString::new(value)?.into_boxed_c_str(),
        })
    }
}

/// Ffi-related functionality for Utf8CStr
#[cfg(feature = "ffi")]
pub(crate) mod ffi {
    use std::ffi::c_char;

    impl super::Utf8CString {
        /// Expose this Utf8CStr as a C string.
        pub(crate) fn as_ptr(&self) -> *const c_char {
            self.string.as_ptr()
        }
    }
}
