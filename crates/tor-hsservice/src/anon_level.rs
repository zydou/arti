//! Define the `Anonymity` type to indicate a level of anonymity.

use crate::internal_prelude::*;

/// The level of anonymity that an onion service should try to run with.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Anonymity {
    /// Try to keep the location of the onion service private.
    ///
    /// Can be represented in a serde-based configuration as `true` or
    /// `"anonymous"` (case insensitive).
    #[default]
    Anonymous,
    /// Do not try to keep the location of the onion service private.
    ///
    /// (This is implemented using our "single onion service" design.)
    ///
    /// Can be represented in a serde-based configuration as`"non_anonymous"`
    /// (case insensitive).
    DangerouslyNonAnonymous,
}

/// A string used to represent `Anonymity::Anonymous` in serde.
const ANON_STRING: &str = "anonymous";

/// A string used to represent `Anonymity::DangerouslyNonAnonymous` in serde.
const DANGER_STRING: &str = "not_anonymous";

impl Serialize for Anonymity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Anonymity::Anonymous => serializer.serialize_bool(true),
            Anonymity::DangerouslyNonAnonymous => serializer.serialize_str(DANGER_STRING),
        }
    }
}

impl<'de> Deserialize<'de> for Anonymity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor struct to deserialize an Anonymity object.
        struct Vis;
        impl<'de> serde::de::Visitor<'de> for Vis {
            type Value = Anonymity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    r#"`true`, `{:?}`, or `{:?}`"#,
                    ANON_STRING, DANGER_STRING
                )
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v {
                    Ok(Anonymity::Anonymous)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Bool(v), &self))
                }
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if s.eq_ignore_ascii_case(ANON_STRING) {
                    Ok(Anonymity::Anonymous)
                } else if s.eq_ignore_ascii_case(DANGER_STRING) {
                    Ok(Anonymity::DangerouslyNonAnonymous)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(s), &self))
                }
            }
        }
        deserializer.deserialize_any(Vis)
    }
}
