//! Support for decoding and encoding RPC messages.
//!
//! Every message is either a Request (sent to Arti)
//! or a Response (received from Arti).

pub(crate) mod request;
pub(crate) mod response;

use std::ffi::NulError;

use serde::{Deserialize, Serialize};

use crate::util::Utf8CString;

/// An identifier for a request made to the Arti RPC system.
///
/// Every request must have an ID, chosen by the application that's sending it.
/// If these IDs are not distinct, the application can get confused about
/// which reply corresponds to which request.
///
/// The [`RpcConn`](crate::conn::RpcConn) type can generate unique IDs
/// for outbound requests as needed.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq, derive_more::From)]
#[serde(untagged)]
#[non_exhaustive]
pub enum AnyRequestId {
    /// A numeric request ID.
    ///
    /// Note that values larger than `±2^53-1` may not work with all
    /// JSON implementations.
    Number(i64),
    /// A string request ID.
    String(String),
}

impl AnyRequestId {
    /// Convert this request ID into a json value.
    //
    // (This is a private function because we don't want to expose serde_json in our API.)
    fn into_json_value(self) -> serde_json::Value {
        match self {
            AnyRequestId::Number(n) => serde_json::Value::Number(n.into()),
            AnyRequestId::String(s) => serde_json::Value::String(s),
        }
    }
}

/// An identifier for some object visible to the Arti RPC system.
///
/// A single object may have multiple underlying identifiers.
/// These identifiers should always be treated as opaque
/// from the application's perspective.
#[derive(
    Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq, derive_more::From, derive_more::Into,
)]
#[serde(transparent)]
pub struct ObjectId(Utf8CString);

impl ObjectId {
    /// Return the global ID for an RPC connection.
    pub fn connection_id() -> Self {
        ObjectId(
            "connection"
                .to_string()
                .try_into()
                .expect("Surprising NULs in string"),
        )
    }

    /// Return this ID as a nul-terminated C string.
    #[cfg(feature = "ffi")]
    pub(crate) fn as_ptr(&self) -> *const std::ffi::c_char {
        self.0.as_ptr()
    }
}

impl TryFrom<String> for ObjectId {
    type Error = NulError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(Utf8CString::try_from(value)?))
    }
}
impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl From<ObjectId> for String {
    fn from(v: ObjectId) -> String {
        v.as_ref().into()
    }
}

/// Serde helper: deserializes (and discards) the contents of any json Object,
/// and does not accept any other type.
#[derive(Debug)]
struct JsonAnyObj {}
// Note: We can't just use `derive(Deserialize)` here, since that would permit empty arrays.
impl<'de> serde::de::Deserialize<'de> for JsonAnyObj {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Visitor to implement deserialize.
        struct Vis;
        impl<'de> serde::de::Visitor<'de> for Vis {
            type Value = JsonAnyObj;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                // We need to iterate over the map, or else we'll get an error.
                while let Some((k, v)) = map.next_entry()? {
                    // It's okay to allow any type here for keys;
                    // serde_json won't deserialize a key  unless it is a string.
                    let _: serde::de::IgnoredAny = k;
                    let _: serde::de::IgnoredAny = v;
                }
                Ok(JsonAnyObj {})
            }
        }

        deserializer.deserialize_map(Vis)
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn any_obj_good() {
        for ok in [
            r#"{}"#,
            r#"{"7": 7}"#,
            r#"{"stuff": "nonsense", "this": {"that": "the other"}}"#,
        ] {
            let _obj: JsonAnyObj = serde_json::from_str(ok).unwrap();
        }
    }
    #[test]
    fn any_obj_bad() {
        for bad in [r"[]", r#"7"#, r#"ksldjfa"#, r#""#, r#"{7:"foo"}"#] {
            let err: Result<JsonAnyObj, _> = serde_json::from_str(bad);
            assert!(err.is_err());
        }
    }
}
