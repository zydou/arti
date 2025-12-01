//! A module for use with `serde::with` to apply `humantime` to `Option<Option<Duration>>`.

use humantime_serde::Serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize an `Option<Option<Duration>>`.
pub fn serialize<T, S>(d: &Option<Option<T>>, s: S) -> Result<S::Ok, S::Error>
where
    for<'a> Serde<&'a T>: Serialize,
    S: Serializer,
{
    let mapped: Option<Option<Serde<&T>>> = d.as_ref().map(|d1| d1.as_ref().map(Into::into));
    mapped.serialize(s)
}

/// Deserialize an `Option<Option<Duration>>`.
pub fn deserialize<'a, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    Serde<T>: Deserialize<'a>,
    D: Deserializer<'a>,
{
    let got: Option<Option<Serde<T>>> = Deserialize::deserialize(d)?;
    Ok(got.map(|v| v.map(Serde::into_inner)))
}
