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
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
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
        // Safety: Since `value` is a `String`, it is guaranteed to be UTF-8.
        Ok(Utf8CString {
            string: CString::new(value)?.into_boxed_c_str(),
        })
    }
}

impl std::fmt::Display for Utf8CString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &str = self.as_ref();
        std::fmt::Display::fmt(s, f)
    }
}

/// An error from trying to convert a byte-slice to a Utf8CString.
#[derive(Clone, Debug, thiserror::Error)]
enum Utf8CStringFromBytesError {
    /// The bytes contained a nul, so we can't convert into a nul-terminated string.
    #[error("Bytes contained 0")]
    Nul(#[from] NulError),
    /// The bytes were not value UTF-8
    #[error("Bytes were not utf-8.")]
    Utf8(#[from] std::str::Utf8Error),
}

impl Utf8CString {
    /// Try to construct a new `Utf8CString` from a given byte slice.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Utf8CStringFromBytesError> {
        let s: &str = std::str::from_utf8(bytes)?;
        Ok(s.to_owned().try_into()?)
    }
}

impl serde::Serialize for Utf8CString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl<'de> serde::Deserialize<'de> for Utf8CString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Visitor to implement Deserialize for Utf8CString
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Utf8CString;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str("a UTF-8 string with no internal NULs")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Utf8CString::try_from_bytes(v).map_err(|e| E::custom(e))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Utf8CString::try_from(v.to_owned()).map_err(|e| E::custom(e))
            }
        }
        deserializer.deserialize_str(Visitor)
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

#[cfg(test)]
/// Assert that s1 and s2 are both valid json, and parse to the same serde_json::Value.
macro_rules! assert_same_json {
        { $s1:expr, $s2:expr } => {
            let v1: serde_json::Value = serde_json::from_str($s1).unwrap();
            let v2: serde_json::Value = serde_json::from_str($s2).unwrap();
            assert_eq!(v1, v2);
        }
    }
#[cfg(test)]
pub(crate) use assert_same_json;
