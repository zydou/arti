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
#[derive(Clone, Debug)]
pub(crate) struct Utf8CStr {
    /// The body of this string.
    ///
    /// INVARIANT: This string must be valid UTF-8.
    string: Box<CStr>,
}

impl AsRef<CStr> for Utf8CStr {
    fn as_ref(&self) -> &CStr {
        &self.string
    }
}

impl AsRef<str> for Utf8CStr {
    fn as_ref(&self) -> &str {
        // TODO: We might someday decide to implement this using unsafe methods, to avoid walking
        // over the string to enforce properties that are already there.
        self.string.to_str().expect("Utf8CString was not UTF-8‽")
    }
}

// TODO: In theory we could have an unchecked version of this function, if we are 100%
// sure that serde_json will reject every string that contains a NUL.  But let's not do
// that unless the NUL check shows up in profiles.
impl TryFrom<String> for Utf8CStr {
    type Error = NulError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Utf8CStr {
            string: CString::new(value)?.into_boxed_c_str(),
        })
    }
}

/// Ffi-related functionality for Utf8CStr
#[cfg(feature = "ffi")]
pub(crate) mod ffi {
    use std::ffi::c_char;

    impl super::Utf8CStr {
        /// Expose this Utf8CStr as a C string.
        pub(crate) fn as_ptr(&self) -> *const c_char {
            self.string.as_ptr()
        }

        /// Consume this Utf8CStr and return its value as an owned C string,
        /// so that we can return it to the application.
        ///
        /// The resulting string may only be freed with [`arti_free_str`][crate::ffi::arti_free_str].
        //
        // Note: The requirement about how the string may be freed is potentially onerous, but our
        // only other design options are not great here. TODO RPC: We should think about whether
        // we can do better.
        pub(crate) fn into_owned_ptr(self) -> *mut c_char {
            self.string.into_c_string().into_raw()
        }
    }
}
