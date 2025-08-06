//! Helpers to manage lists of extensions within relay messages.
//!
//! These are used widely throughout the HS code,
//! but also in the ntor-v3 handshake.

use derive_deftly::Deftly;
use tor_bytes::{EncodeError, EncodeResult, Readable, Reader, Result, Writeable, Writer};
use tor_memquota::{HasMemoryCostStructural, derive_deftly_template_HasMemoryCost};

/// A list of extensions, represented in a common format used by many messages.
///
/// The common format is:
/// ```text
///      N_EXTENSIONS     [1 byte]
///      N_EXTENSIONS times:
///           EXT_FIELD_TYPE [1 byte]
///           EXT_FIELD_LEN  [1 byte]
///           EXT_FIELD      [EXT_FIELD_LEN bytes]
/// ```
///
/// It is subject to the additional restraints:
///
/// * Each extension type SHOULD be sent only once in a message.
/// * Parties MUST ignore any occurrences all occurrences of an extension
///   with a given type after the first such occurrence.
/// * Extensions SHOULD be sent in numerically ascending order by type.
#[derive(Clone, Debug, derive_more::Deref, derive_more::DerefMut, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[deftly(has_memory_cost(bounds = "T: HasMemoryCostStructural"))]
pub(super) struct ExtList<T> {
    /// The extensions themselves.
    pub(super) extensions: Vec<T>,
}
impl<T> Default for ExtList<T> {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }
}

/// As ExtList, but held by reference.
#[derive(Clone, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::From)]
pub(super) struct ExtListRef<'a, T> {
    /// A reference to a slice of extensions.
    extensions: &'a [T],
}

/// A kind of extension that can be used with some kind of relay message.
///
/// Each extendible message will likely define its own enum,
/// implementing this trait,
/// representing the possible extensions.
pub(super) trait ExtGroup: Readable + Writeable {
    /// An identifier kind used with this sort of extension
    type Id: From<u8> + Into<u8> + Eq + PartialEq + Ord + Copy;
    /// The field-type id for this particular extension.
    fn type_id(&self) -> Self::Id;
}
/// A single typed extension that can be used with some kind of relay message.
pub(super) trait Ext: Sized {
    /// An identifier kind used with this sort of extension.
    ///
    /// Typically defined with caret_int.
    type Id: From<u8> + Into<u8>;
    /// The field-type id for this particular extension.
    fn type_id(&self) -> Self::Id;
    /// Extract the body (not the type or the length) from a single
    /// extension.
    fn take_body_from(b: &mut Reader<'_>) -> Result<Self>;
    /// Write the body (not the type or the length) for a single extension.
    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()>;
}
impl<T: ExtGroup> Readable for ExtList<T> {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let n_extensions = b.take_u8()?;
        let extensions: Result<Vec<T>> = (0..n_extensions).map(|_| b.extract::<T>()).collect();
        Ok(Self {
            extensions: extensions?,
        })
    }
}
impl<'a, T: ExtGroup> Writeable for ExtListRef<'a, T> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        let n_extensions = self
            .extensions
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        b.write_u8(n_extensions);
        let mut exts_sorted: Vec<&T> = self.extensions.iter().collect();
        exts_sorted.sort_by_key(|ext| ext.type_id());
        exts_sorted.iter().try_for_each(|ext| ext.write_onto(b))?;
        Ok(())
    }
}
impl<T: ExtGroup> Writeable for ExtList<T> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        ExtListRef::from(&self.extensions[..]).write_onto(b)
    }
}
impl<T: ExtGroup> ExtList<T> {
    /// Insert `ext` into this list of extensions, replacing any previous
    /// extension with the same field type ID.
    #[cfg(feature = "hs")] // currently, only used when "hs' is enabled.
    pub(super) fn replace_by_type(&mut self, ext: T) {
        self.retain(|e| e.type_id() != ext.type_id());
        self.push(ext);
    }
    /// Consume this ExtList and return its members as a vector.
    pub(super) fn into_vec(self) -> Vec<T> {
        self.extensions
    }
}

/// An unrecognized or unencoded extension for some relay message.
#[derive(Clone, Debug, Deftly, Eq, PartialEq)]
#[derive_deftly(HasMemoryCost)]
// Use `Copy + 'static` and `#[deftly(has_memory_cost(copy))]` so that we don't
// need to derive HasMemoryCost for the id types, which are indeed all Copy.
#[deftly(has_memory_cost(bounds = "ID: Copy + 'static"))]
pub struct UnrecognizedExt<ID> {
    /// The field type ID for this extension.
    #[deftly(has_memory_cost(copy))]
    pub(super) type_id: ID,
    /// The body of this extension.
    pub(super) body: Vec<u8>,
}

impl<ID> UnrecognizedExt<ID> {
    /// Return a new unrecognized extension with a given ID and body.
    ///
    /// NOTE: nothing actually enforces that this type ID is not
    /// recognized.
    ///
    /// NOTE: This function accepts bodies longer than 255 bytes, but
    /// it is not possible to encode them.
    pub fn new(type_id: ID, body: impl Into<Vec<u8>>) -> Self {
        Self {
            type_id,
            body: body.into(),
        }
    }
}

/// Declare an Extension group that takes a given identifier.
//
// TODO: This is rather similar to restrict_msg(), isn't it?  Also, We use this
// pattern of (number, (cmd, length, body)*) a few of times in Tor outside the relaycell
// module.  Perhaps we can extend and unify our code here...
macro_rules! decl_extension_group {
    {
        $( #[$meta:meta] )*
        $v:vis enum $id:ident [ $type_id:ty ] {
            $(
                $(#[$cmeta:meta])*
                $([feature: #[$fmeta:meta]])?
                $case:ident),*
            $(,)?
        }
    } => {paste::paste!{
        $( #[$meta] )*
        $v enum $id {
            $( $(#[$cmeta])*
               $( #[$fmeta] )?
               $case($case),
            )*
            /// An extension of a type we do not recognize, or which we have not
            /// encoded.
            Unrecognized(crate::relaycell::extlist::UnrecognizedExt<$type_id>)
        }
        impl tor_bytes::Readable for $id {
            fn take_from(b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
                #[allow(unused)]
                use crate::relaycell::extlist::Ext as _;
                let type_id = b.take_u8()?.into();
                Ok(match type_id {
                    $(
                        $( #[$fmeta] )?
                        $type_id::[< $case:snake:upper >] => {
                            Self::$case( b.read_nested_u8len(|r| $case::take_body_from(r))? )
                        }
                    )*
                    _ => {
                        Self::Unrecognized(crate::relaycell::extlist::UnrecognizedExt {
                            type_id,
                            body: b.read_nested_u8len(|r| Ok(r.take_rest().into()))?,
                        })
                    }
                })
            }
        }
        impl tor_bytes::Writeable for $id {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> tor_bytes::EncodeResult<
()> {
                #![allow(unused_imports)]
                use crate::relaycell::extlist::Ext as _;
                use tor_bytes::Writeable as _;
                use std::ops::DerefMut;
                match self {
                    $(
                        $( #[$fmeta] )?
                        Self::$case(val) => {
                            b.write_u8(val.type_id().into());
                            let mut nested = b.write_nested_u8len();
                            val.write_body_onto(nested.deref_mut())?;
                            nested.finish()?;
                        }
                    )*
                    Self::Unrecognized(unrecognized) => {
                        b.write_u8(unrecognized.type_id.into());
                        let mut nested = b.write_nested_u8len();
                        nested.write_all(&unrecognized.body[..]);
                        nested.finish()?;
                    }
                }
                Ok(())
            }
        }
        impl crate::relaycell::extlist::ExtGroup for $id {
            type Id = $type_id;
            fn type_id(&self) -> Self::Id {
                #![allow(unused_imports)]
                use crate::relaycell::extlist::Ext as _;
                match self {
                    $(
                        $( #[$fmeta] )?
                        Self::$case(val) => val.type_id(),
                    )*
                    Self::Unrecognized(unrecognized) => unrecognized.type_id,
                }
            }
        }
        $(
        $( #[$fmeta] )?
        impl From<$case> for $id {
            fn from(val: $case) -> $id {
                $id :: $case ( val )
            }
        }
        )*
        impl From<crate::relaycell::extlist::UnrecognizedExt<$type_id>> for $id {
            fn from(val: crate::relaycell::extlist::UnrecognizedExt<$type_id>) -> $id {
                $id :: Unrecognized(val)
            }
        }
}}
}
pub(super) use decl_extension_group;
