//! Module to adaopt `humantime_serde` to `Option<Duration>`

use humantime_serde_crate::Serde as HtSerde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serializes an `Option<Duration>` or `Option<SystemTime>` via the humantime crate.
pub fn serialize<T, S>(d: &Option<T>, s: S) -> Result<S::Ok, S::Error>
where
    for<'a> HtSerde<&'a T>: Serialize,
    S: Serializer,
{
    let nested: Option<HtSerde<&T>> = d.as_ref().map(Into::into);
    nested.serialize(s)
}

/// Deserialize an `Option<Duration>` or `Option<SystemTime>` via the humantime crate.
pub fn deserialize<'a, T, D>(d: D) -> Result<Option<T>, D::Error>
where
    HtSerde<T>: Deserialize<'a>,
    D: Deserializer<'a>,
{
    let got: Option<HtSerde<T>> = Deserialize::deserialize(d)?;
    Ok(got.map(HtSerde::into_inner))
}
