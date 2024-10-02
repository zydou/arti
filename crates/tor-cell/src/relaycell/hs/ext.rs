//! Helpers to manage lists of HS cell extensions.
//
// TODO: We might generalize this even more in the future to handle other
// similar lists in our cell protocol.

use derive_deftly::Deftly;
use tor_bytes::{EncodeError, EncodeResult, Readable, Reader, Result, Writeable, Writer};
use tor_memquota::{derive_deftly_template_HasMemoryCost, HasMemoryCostStructural};

/// A list of extensions, represented in a common format used by many HS-related
/// message.
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
    extensions: Vec<T>,
}
impl<T> Default for ExtList<T> {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }
}
/// An kind of extension that can be used with some kind of HS-related message.
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
/// A single typed extension that can be used with some kind of HS-related message.
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
impl<T: ExtGroup> Writeable for ExtList<T> {
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
impl<T: ExtGroup> ExtList<T> {
    /// Insert `ext` into this list of extensions, replacing any previous
    /// extension with the same field type ID.
    pub(super) fn replace_by_type(&mut self, ext: T) {
        self.retain(|e| e.type_id() != ext.type_id());
        self.push(ext);
    }
}

/// An unrecognized or unencoded extension for some HS-related message.
#[derive(Clone, Debug, Deftly)]
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
// pattern of (number, (cmd, length, body)*) a few of times in Tor outside the
// hs module.  Perhaps we can extend and unify our code here...
macro_rules! decl_extension_group {
    {
        $( #[$meta:meta] )*
        $v:vis enum $id:ident [ $type_id:ty ] {
            $(
                $(#[$cmeta:meta])*
                $case:ident),*
            $(,)?
        }
    } => {paste::paste!{
        $( #[$meta] )*
        $v enum $id {
            $( $(#[$cmeta])*
               $case($case),
            )*
            /// An extension of a type we do not recognize, or which we have not
            /// encoded.
            Unrecognized(UnrecognizedExt<$type_id>)
        }
        impl Readable for $id {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                let type_id = b.take_u8()?.into();
                Ok(match type_id {
                    $(
                        $type_id::[< $case:snake:upper >] => {
                            Self::$case( b.read_nested_u8len(|r| $case::take_body_from(r))? )
                        }
                    )*
                    _ => {
                        Self::Unrecognized(UnrecognizedExt {
                            type_id,
                            body: b.read_nested_u8len(|r| Ok(r.take_rest().into()))?,
                        })
                    }
                })
            }
        }
        impl Writeable for $id {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<
()> {
                #[allow(unused)]
                use std::ops::DerefMut;
                match self {
                    $(
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
        impl ExtGroup for $id {
            type Id = $type_id;
            fn type_id(&self) -> Self::Id {
                match self {
                    $(
                        Self::$case(val) => val.type_id(),
                    )*
                    Self::Unrecognized(unrecognized) => unrecognized.type_id,
                }
            }
        }
        $(
        impl From<$case> for $id {
            fn from(val: $case) -> $id {
                $id :: $case ( val )
            }
        }
        )*
        impl From<UnrecognizedExt<$type_id>> for $id {
            fn from(val: UnrecognizedExt<$type_id>) -> $id {
                $id :: Unrecognized(val)
            }
        }
}}
}
pub(super) use decl_extension_group;
