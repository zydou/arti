//! Hacks to extract the version and index from a slotmap key, using serde.
//!
//! This approach may fail in the future if `slotmap` changes its serde output;
//! but that would probably break a bunch other tools that depend on `slotmap`.
//!
//! ## Performance
//!
//! This serde-based approach might look inefficient, but the compiler is smart:
//! it can inline all of the code and turn `key_data_parts` into direct data lookups.
//!
//! (Note that this performance property requires us to use `opt-level = 2` for this crate,
//! in contrast with the rest of Arti, which currently prefers `opt-level = "s"`.)
//!
//!
//! To conform that performance is likely acceptable, run
//! `cargo asm slotmap_careful::key_data::key_data_parts`,
//! and confirm that the result would fit on a napkin.
use serde::{
    ser::{Impossible, SerializeStruct},
    Serialize,
};
use slotmap::Key;

/// Return the version encoded in `key`.
///
/// (This version that starts with 0 when a slot is first created, and increments by 1 every
/// time the slot is re-used.  It cannot grow larger than `0x7fff_ffff`.)
pub(crate) fn key_version_serde<K: Key>(key: K) -> u32 {
    key_data_parts(key.data())
        .expect("Slotmap has changed its serde format")
        .0
        >> 1
}

/// Decode a `slotmap::KeyData` into its `version` and `index` components.
///
/// Note that the `version` value here will include the trailing LSB=1 value,
/// to indicate that it is for an occupied slot.
/// The caller should right-shift the version result by 1
/// to get the actual "version" of the slot
/// (as we define "version"  in the rest of this crate).
pub(crate) fn key_data_parts(key_data: slotmap::KeyData) -> Result<(u32, u32), Failed> {
    let mut s = Ser {
        version: None,
        index: None,
    };

    key_data.serialize(&mut s)?;
    Ok((s.version.ok_or(Failed)?, s.index.ok_or(Failed)?))
}

/// Serializer for slotmap::KeyData, to extract the version and index of a key.
struct Ser {
    /// If present, a version we have found.
    version: Option<u32>,
    /// If present, a slot index we have found.
    index: Option<u32>,
}

/// An unexpected failure from serializing a key.
#[derive(Clone, Debug, thiserror::Error)]
#[error("slotmap keydata did not serialize as expected")]
pub(crate) struct Failed;

impl serde::ser::Error for Failed {
    fn custom<T>(_msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Failed
    }
}

#[allow(unused_variables)] // for all the function arguments we'll ignore
impl<'a> serde::Serializer for &'a mut Ser {
    type Ok = ();
    type Error = Failed;

    type SerializeSeq = Impossible<(), Failed>;
    type SerializeTuple = Impossible<(), Failed>;
    type SerializeTupleStruct = Impossible<(), Failed>;
    type SerializeTupleVariant = Impossible<(), Failed>;
    type SerializeMap = Impossible<(), Failed>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Impossible<(), Failed>;

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Err(Failed)
    }
    shared_no_ops! {}
}

impl<'a> SerializeStruct for &'a mut Ser {
    type Ok = ();

    type Error = Failed;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        if key == "version" {
            self.version = Some(value.serialize(&mut SerU32)?);
        } else if key == "idx" {
            self.index = Some(value.serialize(&mut SerU32)?);
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

/// Serializer that extracts a u32, and rejects anything else.
struct SerU32;

#[allow(unused_variables)] // for all the function arguments we'll ignore
impl<'a> serde::Serializer for &'a mut SerU32 {
    type Ok = u32;
    type Error = Failed;

    type SerializeSeq = Impossible<u32, Failed>;
    type SerializeTuple = Impossible<u32, Failed>;
    type SerializeTupleStruct = Impossible<u32, Failed>;
    type SerializeTupleVariant = Impossible<u32, Failed>;
    type SerializeMap = Impossible<u32, Failed>;
    type SerializeStruct = Impossible<u32, Failed>;
    type SerializeStructVariant = Impossible<u32, Failed>;

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        Ok(v)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(Failed)
    }

    shared_no_ops! {}
}

/// Helper: Define the common members of `Ser` and `SerU32`.
///
/// (These are just a bunch of methods that return `Err(Failed)`)
macro_rules! shared_no_ops {
    {} => {

        fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            Err(Failed)
        }
        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_unit_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            Err(Failed)
        }
        fn serialize_newtype_struct<T>(
            self,
            name: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            Err(Failed)
        }
        fn serialize_newtype_variant<T>(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            Err(Failed)
        }
        fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
            Err(Failed)
        }
        fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
            Err(Failed)
        }
        fn serialize_tuple_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            Err(Failed)
        }
        fn serialize_tuple_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            Err(Failed)
        }
        fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
            Err(Failed)
        }
        fn serialize_struct_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            Err(Failed)
        }
    }
}
use shared_no_ops;
