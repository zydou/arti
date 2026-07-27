//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub use b16impl::*;
pub use b64impl::*;
pub use contact_info::*;
pub use curve25519impl::*;
pub use ed25519impl::*;
pub use edcert::*;
pub use fingerprint::*;
pub use hostname::*;
pub use rsa::*;
pub use timeimpl::*;

pub use nickname::{InvalidNickname, Nickname};

pub use boolean::NumericBoolean;

pub use fingerprint::{Base64Fingerprint, Fingerprint};

pub use identified_digest::{DigestName, IdentifiedDigest};

pub use ignored_impl::{
    Ignored, IgnoredItemOrObjectValue, ItemPresent, NoMoreArguments, NotPresent,
    NotPresentEachValue,
};

use crate::NormalItemArgument;
use crate::encode::{
    self,
    ItemArgument,
    ItemEncoder,
    ItemObjectEncodable,
    ItemValueEncodable,
    // `E` for "encode`; different from `parse2::MultiplicitySelector`
    MultiplicitySelector as EMultiplicitySelector,
    NetdocEncoder,
};
use crate::parse2::{
    self, ArgumentError, ArgumentStream, ItemArgumentParseable, ItemObjectParseable,
    ItemValueParseable, SignatureHashInputs, SignatureItemParseable, UnparsedItem,
    multiplicity::{
        ArgumentSetMethods,
        ItemSetMethods,
        // `P2` for "parse2`; different from `encode::MultiplicitySelector`
        MultiplicitySelector as P2MultiplicitySelector,
        ObjectSetMethods,
    },
    sig_hashes::Sha1WholeKeywordLine,
};

use derive_deftly::{Deftly, define_derive_deftly, define_derive_deftly_module};
use digest::Digest as _;
use educe::Educe;
use std::cmp::{self, Ordering, PartialOrd};
use std::fmt::{self, Display};
use std::iter;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::result::Result as StdResult;
use std::str::FromStr;
use subtle::{Choice, ConstantTimeEq};
use tor_error::{Bug, ErrorReport as _, internal, into_internal};
use void::{ResultVoidExt as _, Void};

/// Describes a value that van be decoded from a bunch of bytes.
///
/// Used for decoding the objects between BEGIN and END tags.
pub(crate) trait FromBytes: Sized {
    /// Try to parse a value of this type from a byte slice
    fn from_bytes(b: &[u8], p: crate::Pos) -> crate::Result<Self>;
    /// Try to parse a value of this type from a vector of bytes,
    /// and consume that value
    fn from_vec(v: Vec<u8>, p: crate::Pos) -> crate::Result<Self> {
        Self::from_bytes(&v[..], p)
    }
}

define_derive_deftly_module! {
    /// Implement conversion traits for a transparent newtype around bytes - shared code
    ///
    /// This is precisely `#[derive_deftly(Transparent)]`, but in the form of a deftly module,
    /// so that other derives (eg `BytesTransparent`) can re-use it.
    Transparent beta_deftly:

    // Expands to bullet points for "generated code", except omitting
    // `AsRef` & `AsMut` because some uses sites have additional impls of those,
    // which are best presented together in the docs.
  ${define TRANSPARENT_DOCS_IMPLS {
    ///  * impls of `Deref`, `DerefMut`
    ///  * impls of `From<field>` and "`Into`" (technically, `From<Self> for field`)
  }}

    // Expands to the implementations
  ${define TRANSPARENT_IMPLS {

  ${for fields {
    ${loop_exactly_1 "must be applied to a single-field struct"}

    impl<$tgens> From<$ftype> for $ttype {
        fn from($fpatname: $ftype) -> $ttype {
            $vpat
        }
    }

    // TODO: This implementation is probably a bug, as it forbids to derive
    // Transparent on types like `struct Foo<T>(T)`, namely `T` not being
    // covered by something else, like `PhantomData<T>` or `Vec<T>`.
    impl<$tgens> From<$ttype> for $ftype {
        fn from(self_: $ttype) -> $ftype {
            self_.$fname
        }
    }

    impl<$tgens> Deref for $ttype {
        type Target = $ftype;
        fn deref(&self) -> &$ftype {
            &self.$fname
        }
    }

    impl<$tgens> DerefMut for $ttype {
        fn deref_mut(&mut self) -> &mut $ftype {
            &mut self.$fname
        }
    }

    impl<$tgens> AsRef<$ftype> for $ttype {
        fn as_ref(&self) -> &$ftype {
            &self.$fname
        }
    }

    impl<$tgens> AsMut<$ftype> for $ttype {
        fn as_mut(&mut self) -> &mut $ftype {
            &mut self.$fname
        }
    }
  }}
  }}
}

define_derive_deftly! {
    use Transparent;

    /// Implement conversion traits for an arbitrary transparent newtype
    ///
    /// # Requirements
    ///
    ///  * Self should be a single-field struct
    ///  * Self should have no runtime invariants
    ///
    /// # Generated code
    ///
    $TRANSPARENT_DOCS_IMPLS
    ///  * impls of `AsMut<field>`, `AsRef<field>`
    ///
    /// # Guidelines
    ///
    ///  * the field should be `pub`, with `#[allow(clippy::exhaustive_structs)]`
    ///  * derive `Hash`, `Debug` and (usually) `Clone`
    ///  * consider deriving `PartialEq` and `Eq`
    ///    but for types containing bytes, use [`ConstantTimeEq`],
    ///    eg with [`#[derive_deftly(BytesTransparent)]`](derive_deftly_template_BytesTransparent)
    ///    (instead of `Transparent`).
    ///  * implement `FromStr`, `Display`, `NormalItemArgument`, as required
    Transparent for struct, beta_deftly:

    $TRANSPARENT_IMPLS
}

define_derive_deftly! {
    use Transparent;

    /// Implement `ConstantTimeEq`, `.as_bytes()`, etc., for a transparent newtype around bytes
    ///
    /// # Requirements
    ///
    ///  * Self should be a single-field struct
    ///  * Self should deref to `&[u8]` (and to `&mut [u8]`).
    ///  * (so Self should have no runtime invariants)
    ///
    /// # Generated code
    ///
    ///  * impls of `ConstantTimeEq`, `Eq`, `PartialEq`, `Ord`, `PartialOrd`
    ///  * `as_bytes()` method
    ${TRANSPARENT_DOCS_IMPLS}
    ///  * impls of `AsMut<field>`, `AsRef<field>`, `AsRef<[u8]>`, `AsMut<[u8]>`
    ///
    // We could derive Debug here but then we have to deal with the Fixed's N
    // which gets quite fiddly.
    //
    /// # Guidelines
    ///
    ///  * derive `Hash` and write `#[allow(clippy::derived_hash_with_manual_eq)]`
    ///  * impl `FromStr` and `Display` (if required, which they usually will be)
    ///  * derive `derive_more::Debug` eg with `#[debug(r#"B64("{self}")"#)]`
    ///  * `impl NormalItemArgument` if appropriate (ie the representation has no spaces)
    BytesTransparent for struct, beta_deftly:

    $TRANSPARENT_IMPLS

    impl<$tgens> ConstantTimeEq for $ttype {
        fn ct_eq(&self, other: &$ttype) -> Choice {
          $(
            self.$fname.ct_eq(&other.$fname)
          )
        }
    }
    $/// `$tname` is `Eq` via its constant-time implementation.
    impl<$tgens> PartialEq for $ttype {
        fn eq(&self, other: &$ttype) -> bool {
            self.ct_eq(other).into()
        }
    }
    impl<$tgens> Eq for $ttype {}
    impl<$tgens> PartialOrd for $ttype {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    impl<$tgens> Ord for $ttype {
        fn cmp(&self, other: &Self) -> Ordering {
          $(
            self.$fname.cmp(&other.$fname)
          )
        }
    }

    impl<$tgens> $ttype {
        /// Return the byte array from this object.
        pub fn as_bytes(&self) -> &[u8] {
          $(
            &self.$fname[..]
          )
        }
    }

    impl<$tgens> AsRef<[u8]> for $ttype {
        fn as_ref(&self) -> &[u8] {
          $(
            self.$fname.as_ref()
          )
        }
    }

    impl<$tgens> AsMut<[u8]> for $ttype {
        fn as_mut(&mut self) -> &mut [u8] {
          $(
            self.$fname.as_mut()
          )
        }
    }
}

/// Types for decoding base64-encoded values.
mod b64impl {
    use super::*;
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use base64ct::{Base64, Base64Unpadded, Encoding};
    use std::ops::RangeBounds;

    /// A byte array, encoded in base64 with optional padding.
    ///
    /// On output (`Display`), output is unpadded.
    #[derive(Clone, Hash, Deftly)]
    #[derive_deftly(BytesTransparent)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(derive_more::Debug)]
    #[debug(r#"B64("{self}")"#)]
    #[allow(clippy::exhaustive_structs)]
    pub struct B64(pub Vec<u8>);

    impl FromStr for B64 {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let v: core::result::Result<Vec<u8>, base64ct::Error> = match s.len() % 4 {
                0 => Base64::decode_vec(s),
                _ => Base64Unpadded::decode_vec(s),
            };
            let v = v.map_err(|_| {
                EK::BadArgument
                    .with_msg("Invalid base64")
                    .at_pos(Pos::at(s))
            })?;
            Ok(B64(v))
        }
    }

    impl Display for B64 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Display::fmt(&Base64Unpadded::encode_string(&self.0), f)
        }
    }

    impl B64 {
        /// Return this object if its length is within the provided bounds
        /// object, or an error otherwise.
        pub(crate) fn check_len<B: RangeBounds<usize>>(self, bounds: B) -> Result<Self> {
            if bounds.contains(&self.0.len()) {
                Ok(self)
            } else {
                Err(EK::BadObjectVal.with_msg("Invalid length on base64 data"))
            }
        }

        /// Try to convert this object into an array of N bytes.
        ///
        /// Return an error if the length is wrong.
        pub(crate) fn into_array<const N: usize>(self) -> Result<[u8; N]> {
            self.0
                .try_into()
                .map_err(|_| EK::BadObjectVal.with_msg("Invalid length on base64 data"))
        }
    }

    impl FromIterator<u8> for B64 {
        fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    impl NormalItemArgument for B64 {}

    /// A byte array encoded in a hexadecimal with a fixed length.
    #[derive(Clone, Hash, Deftly)]
    #[derive_deftly(BytesTransparent)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(derive_more::Debug)]
    #[debug(r#"FixedB64::<{N}>("{self}")"#)]
    #[allow(clippy::exhaustive_structs)]
    pub struct FixedB64<const N: usize>(pub [u8; N]);

    impl<const N: usize> Display for FixedB64<N> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Display::fmt(&B64(self.0.to_vec()), f)
        }
    }

    impl<const N: usize> FromStr for FixedB64<N> {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            Ok(Self(B64::from_str(s)?.0.try_into().map_err(|_| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("invalid length")
            })?))
        }
    }

    impl<const N: usize> NormalItemArgument for FixedB64<N> {}
}

// ============================================================

/// Types for decoding hex-encoded values.
mod b16impl {
    use super::*;
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};

    /// A byte array encoded in hexadecimal; prints in lowercase
    ///
    /// Both uppercase and lowercase are tolerated when parsing.
    #[derive(Clone, Hash, Deftly)]
    #[derive_deftly(BytesTransparent)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(derive_more::Debug)]
    #[debug(r#"B16("{self}")"#)]
    #[allow(clippy::exhaustive_structs)]
    pub struct B16(pub Vec<u8>);

    /// A byte array encoded in hexadecimal; prints in uppercase
    ///
    /// Both uppercase and lowercase are tolerated when parsing.
    #[derive(Clone, Hash, Deftly)]
    #[derive_deftly(BytesTransparent)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(derive_more::Debug)]
    #[debug(r#"B16U("{self}")"#)]
    #[allow(clippy::exhaustive_structs)]
    pub struct B16U(pub Vec<u8>);

    /// A fixed-length version of [`B16U`].
    #[derive(Clone, Hash, Deftly)]
    #[derive_deftly(BytesTransparent)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(derive_more::Debug)]
    #[debug(r#"FixedB16U("{self}")"#)]
    #[allow(clippy::exhaustive_structs)]
    pub struct FixedB16U<const N: usize>(pub [u8; N]);

    impl FromStr for B16 {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let bytes = hex::decode(s).map_err(|_| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("invalid hexadecimal")
            })?;
            Ok(B16(bytes))
        }
    }

    impl FromStr for B16U {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            Ok(B16U(B16::from_str(s)?.0))
        }
    }

    impl<const N: usize> FromStr for FixedB16U<N> {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            Ok(Self(B16U::from_str(s)?.0.try_into().map_err(|_| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("invalid length")
            })?))
        }
    }

    /// Write `b` to `f` in hex uppercase
    // `hex` has `hex::encode_upper` but that allocates a `String`
    fn write_b16u(b: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
        for c in b {
            write!(f, "{c:02X}")?;
        }
        Ok(())
    }

    impl Display for B16 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // `hex` has `hex::encode` but that allocates a `String`, which this approach doesn't
            for c in self.as_bytes() {
                write!(f, "{c:02x}")?;
            }
            Ok(())
        }
    }

    impl Display for B16U {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_b16u(self.as_bytes(), f)
        }
    }

    impl<const N: usize> Display for FixedB16U<N> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_b16u(self.as_bytes(), f)
        }
    }

    impl NormalItemArgument for B16 {}
    impl NormalItemArgument for B16U {}
    impl<const N: usize> NormalItemArgument for FixedB16U<N> {}
}

// ============================================================

/// Types for decoding curve25519 keys
mod curve25519impl {
    use super::*;

    use crate::{Error, NormalItemArgument, Result, types::misc::FixedB64};
    use tor_llcrypto::pk::curve25519::PublicKey;

    /// A Curve25519 public key, encoded in base64 with optional padding
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Curve25519Public(pub PublicKey);

    impl FromStr for Curve25519Public {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let pk: FixedB64<32> = s.parse()?;
            let pk: [u8; 32] = pk.into();
            Ok(Curve25519Public(pk.into()))
        }
    }

    impl Display for Curve25519Public {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            FixedB64::from(self.0.to_bytes()).fmt(f)
        }
    }

    impl NormalItemArgument for Curve25519Public {}
}

// ============================================================

/// Types for decoding ed25519 keys
mod ed25519impl {
    use super::*;

    use crate::{Error, NormalItemArgument, Result, types::misc::FixedB64};
    use derive_deftly::Deftly;
    use tor_llcrypto::pk::ed25519::{Ed25519Identity, Signature};

    /// An alleged ed25519 public key, encoded in base64 with optional
    /// padding.
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Ed25519Public(pub Ed25519Identity);

    impl FromStr for Ed25519Public {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let pk: FixedB64<32> = s.parse()?;
            Ok(Ed25519Public(Ed25519Identity::new(pk.into())))
        }
    }

    impl Display for Ed25519Public {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let pk: [u8; 32] = self.0.into();
            let pk = FixedB64::from(pk);
            pk.fmt(f)
        }
    }

    impl NormalItemArgument for Ed25519Public {}

    /// Helper that checks for the presence of `ed25519`.
    #[derive(Debug, Clone, PartialEq, Eq, derive_more::Display, derive_more::FromStr)]
    #[display(rename_all = "lowercase")]
    #[from_str(rename_all = "lowercase")]
    #[allow(clippy::exhaustive_enums)]
    pub enum Ed25519AlgorithmString {
        /// Ed25519 encoded as `ed25519`.
        Ed25519,
    }

    impl NormalItemArgument for Ed25519AlgorithmString {}

    /// Ed25519 public key in the form `<keyword> id <base64>`
    ///
    ///  * `id` in microdescriptors:
    ///    <https://spec.torproject.org/dir-spec/computing-microdescriptors.html>
    ///
    ///  * `identity-ed25519` in routerdescs:
    ///    <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:identity-ed25519>
    ///
    ///  * `id` in votes' routerstatus entries:
    ///    <https://spec.torproject.org/dir-spec/consensus-formats.html#item:id>
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueEncodable, ItemValueParseable)]
    #[non_exhaustive]
    pub struct Ed25519IdentityLine {
        /// Fixed magic identifier (`ed25519`) for this line.
        pub alg: Ed25519AlgorithmString,

        /// The actual Ed25519 identity.
        pub pk: Ed25519Public,
    }

    impl From<Ed25519Public> for Ed25519IdentityLine {
        fn from(pk: Ed25519Public) -> Self {
            Self {
                alg: Ed25519AlgorithmString::Ed25519,
                pk,
            }
        }
    }

    impl From<Ed25519Identity> for Ed25519IdentityLine {
        fn from(pk: Ed25519Identity) -> Self {
            Ed25519Public(pk).into()
        }
    }

    impl ItemArgument for Signature {
        fn write_arg_onto(&self, out: &mut ItemEncoder) -> StdResult<(), Bug> {
            FixedB64::from(self.to_bytes()).write_arg_onto(out)
        }
    }
}

// ============================================================

/// Dummy types like [`Ignored`]
mod ignored_impl {
    use super::*;

    use crate::parse2::ErrorProblem as EP;
    use ArgumentError as AE;

    /// Part of a network document, that isn't actually there.
    ///
    /// Used as a standin in `ns_type!` calls in various netstatus `each_variety.rs`.
    /// The effect is as if the field were omitted from the containing type.
    ///
    ///  * When used as item(s) (ie, a field type when deriving `NetdocParseable\[Fields\]`):
    ///    **ignores any number** of items with that field's keyword during parsing,
    ///    and emits none during encoding.
    ///
    ///    (To *reject* documents containing this item, use `Option<Void>`,
    ///    but note that the spec says unknown items should be ignored,
    ///    which would normally include items which are merely missing from one variety.)
    ///
    ///  * When used as an argument (ie, a field type when deriving `ItemValueParseable`,
    ///    or with `netdoc(single_arg)`  when deriving `NetdocParseable\[Fields\]`):
    ///    consumes **no arguments** during parsing, and emits none during encoding.
    ///
    ///  * When used as an object field (ie, `netdoc(object)` when deriving `ItemValueParseable`):
    ///    **rejects** an object - failing the parse if one is present.
    ///    (Functions similarly to `Option<Void>`, but prefer `NotPresent` as it's clearer.)
    ///
    ///  * When used as a sub-document (ie, `netdoc(flatten)` when deriving a document trait),
    ///    it recognises, and encodes as, no fields.
    ///
    /// There are bespoke impls of the multiplicity traits
    /// `ItemSetMethods` and `ObjectSetMethods`:
    /// don't wrap this type in `Option` or `Vec`.
    //
    // TODO we'll need to implement ItemArgument etc., for encoding, too.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
    #[allow(clippy::exhaustive_structs)]
    #[derive(Deftly)]
    #[derive_deftly(NetdocEncodableFields, NetdocParseableFields)]
    pub struct NotPresent;

    /// An individual value that is not present - placeholder type
    ///
    /// This is the "single" item type for encoding multiplicity
    /// (for Items, Arguments or Objects), for [`NotPresent`].
    ///
    /// It should not be used directly.
    ///
    /// During parsing, each "not present" item is ignored,
    /// but the multiplicity arrangements involve parsing each value
    /// and then passing the item value to [`ItemSetMethods::accumulate`]
    /// where (for [`NotPresentEachValue`]) it is discarded.
    /// Therefore this type must be inhabited; the item parser discards the unparsed item.
    ///
    /// During parsing of arguments, parsing is driven by
    /// [our `ArgumentSetMethods::parse_with`][`P2MultiplicitySelector::<NotPresent>::parse_with)
    /// which doesn't need to call any parser.
    /// So the [`ItemArgumentParseable`] implementation always throws an error.
    ///
    /// During parsing of objects, rejection is done by
    /// [`NotPresentEachValue::check_label`] (and `from_bytes`).
    ///
    /// For encoding, there is only one multiplicity system which
    /// will never call any encoding function, so the encoding functions all throw `Bug`.
    ///
    /// This type has a similar role to `IgnoredItemOrObjectValue`,
    /// but `NotPresentEachValue` is different in detail,
    /// and (unlike `Ignored`) must support arguments, not just items and objects.
    #[derive(Debug, Clone, Deftly)]
    #[non_exhaustive]
    #[derive_deftly(ItemValueParseable, NetdocParseableFields)]
    pub struct NotPresentEachValue;

    /// Ignored part of a network document.
    ///
    /// With `parse2`, can be used as an item, object, or even flattened-fields.
    ///
    /// When deriving `parse2` traits, and a field is absent in a particular netstatus variety,
    /// use `ns_type!` with [`NotPresent`], rather than `Ignored`.
    ///
    /// During encoding as an Items or Objects, will be entirely omitted,
    /// via the multiplicity arrangements.
    ///
    /// Cannot be encoded as an Argument: if this is not the last
    /// Argument, we need something to put into the output document to avoid generating
    /// a document with the arguments out of step.  If it *is* the last argument,
    /// it could simply be omitted, since additional arguments are in any case ignored.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default, Deftly)]
    #[derive_deftly(ItemValueParseable, NetdocParseableFields)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Ignored;

    /// An Item or Object that would be ignored during parsing and is omitted during encoding
    ///
    /// This is the "single" item type for encoding multiplicity for Items or Objects,
    /// for [`Ignored`].
    ///
    /// It should not be used directly.
    ///
    /// This type is uninhabited.
    pub struct IgnoredItemOrObjectValue(Void);

    /// Indicates that no further arguments are allowed in a network document Item line
    ///
    /// Unlike [`NotPresent`], this fails during parsing if there are any more arguments.
    ///
    /// Should appear only at the end of the argument list.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
    #[allow(clippy::exhaustive_structs)]
    pub struct NoMoreArguments;

    /// An item that only matters in terms of presence of absence.
    ///
    /// Useful for items such as `tunnelled-dir-server` where the mere presence
    /// implies a truthful value.
    ///
    /// This wrapper implements [`ItemValueParseable`] and [`ItemValueEncodable`]
    /// rejecting all arguments and objects and just expecting/emitting the
    /// keyword (or not).
    ///
    /// # Examples
    ///
    /// The following shows an except from a hypothetical netdoc with a
    /// [`ItemPresent`] item.
    ///
    /// ```
    /// use derive_deftly::Deftly;
    /// use tor_netdoc::types::*;
    /// use tor_netdoc::parse2::*;
    /// use tor_netdoc::*;
    ///
    /// #[derive(Debug, Default)]
    /// struct Hello;
    ///
    /// #[derive(Deftly, Debug)]
    /// #[derive_deftly(NetdocParseable)]
    /// struct TestDoc {
    ///     intro: Ignored,
    ///     hello: Option<ItemPresent<Hello>>,
    /// }
    ///
    /// // hello is not present.
    /// let doc = parse_netdoc::<TestDoc>(&ParseInput::new("intro\n", "")).unwrap();
    /// assert!(doc.hello.is_none());
    ///
    /// // hello is present.
    /// let doc = parse_netdoc::<TestDoc>(&ParseInput::new("intro\nhello\n", "")).unwrap();
    /// assert!(doc.hello.is_some());
    ///
    /// // hello has arguments which are ignored.
    /// let doc = parse_netdoc::<TestDoc>(&ParseInput::new("intro\nhello world\n", "")).unwrap();
    /// assert!(doc.hello.is_some());
    ///
    /// // hello is present twice which is not allowed.
    /// let doc = parse_netdoc::<TestDoc>(&ParseInput::new("intro\nhello\nhello\n", "")).unwrap_err();
    /// ```
    //
    // We cannot derive Transparent here, because it is not possible to
    // implement `From<ItemPresent<T>> for T` due to orphan rule.
    //
    // Otherwise, a downstream crate could for example implement
    // `From<ItemPresent<U>> for U` with `U` being a locally defined type,
    // leading to a conflicting implementation.  A solution would be to cover
    // `T` behind another generic type such as `PhantomData`, as this can't be
    // a type in a downstream crate, but that level of indirection feels wrong.
    #[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
    //
    #[derive(
        derive_more::From,
        derive_more::Deref,
        derive_more::DerefMut,
        derive_more::AsRef,
        derive_more::AsMut,
    )]
    #[allow(clippy::exhaustive_structs)]
    pub struct ItemPresent<T: Default>(pub T);

    impl ItemSetMethods for P2MultiplicitySelector<NotPresent> {
        type Each = NotPresentEachValue;
        type Field = NotPresent;
        fn can_accumulate(self, _acc: &Option<NotPresent>) -> Result<(), EP> {
            Ok(())
        }
        fn accumulate(self, _: &mut Option<NotPresent>, _: NotPresentEachValue) -> Result<(), EP> {
            Ok(())
        }
        fn finish(self, _acc: Option<NotPresent>, _: &'static str) -> Result<NotPresent, EP> {
            Ok(NotPresent)
        }
        fn debug_core(self) -> &'static str {
            "Ignored"
        }
    }

    impl ItemValueEncodable for NotPresentEachValue {
        fn write_item_value_onto(&self, _out: ItemEncoder) -> Result<(), Bug> {
            Err(internal!("NotPresentEachValue as ItemValueEncodable"))
        }
    }

    impl ArgumentSetMethods for P2MultiplicitySelector<NotPresent> {
        type Each = NotPresentEachValue;
        type Field = NotPresent;

        fn parse_with<P>(self, _: &mut ArgumentStream<'_>, _: P) -> Result<Self::Field, AE>
        where
            P: for<'s> Fn(&mut ArgumentStream<'s>) -> Result<Self::Each, AE>,
        {
            Ok(NotPresent)
        }

        fn debug_core(self) -> &'static str {
            "NotPresent"
        }
    }
    impl ItemArgument for NotPresentEachValue {
        fn write_arg_onto(&self, _out: &mut ItemEncoder) -> Result<(), Bug> {
            Err(internal!("NotPresentEachValue as ItemArgument"))
        }
    }
    impl ItemArgumentParseable for NotPresentEachValue {
        fn from_args<'s>(_: &mut ArgumentStream<'s>) -> Result<Self, ArgumentError> {
            // Not quite the right error, but we don't have an ArgumentError::Internal
            Err(AE::Unexpected)
        }
    }

    impl ItemObjectEncodable for NotPresentEachValue {
        fn label(&self) -> &str {
            "INTERNAL ERROR"
        }
        fn write_object_onto(&self, _b: &mut Vec<u8>) -> Result<(), Bug> {
            Err(internal!("NotPresentEachValue as ItemObjectEncodable"))
        }
    }

    impl ObjectSetMethods for P2MultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = NotPresentEachValue;
        fn resolve_option(self, _found: Option<NotPresentEachValue>) -> Result<NotPresent, EP> {
            Ok(NotPresent)
        }
        fn debug_core(self) -> &'static str {
            "NotPresent"
        }
    }
    impl ItemObjectParseable for NotPresentEachValue {
        fn check_label(_label: &str) -> Result<(), EP> {
            Err(EP::ObjectUnexpected)
        }
        fn from_bytes(_input: &[u8]) -> Result<Self, EP> {
            Err(EP::ObjectUnexpected)
        }
    }

    impl<'f> encode::MultiplicityMethods<'f> for EMultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = NotPresentEachValue;
        fn iter_ordered(self, _: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
            iter::empty()
        }
    }

    impl encode::OptionalityMethods for EMultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = NotPresentEachValue;
        fn as_option<'f>(self, _: &'f Self::Field) -> Option<&'f Self::Each> {
            None
        }
    }

    impl FromStr for Ignored {
        type Err = Void;
        fn from_str(_s: &str) -> Result<Ignored, Void> {
            Ok(Ignored)
        }
    }

    impl ItemArgumentParseable for Ignored {
        fn from_args(_: &mut ArgumentStream) -> Result<Ignored, ArgumentError> {
            Ok(Ignored)
        }
    }

    impl ItemObjectParseable for Ignored {
        fn check_label(_label: &str) -> Result<(), EP> {
            // allow any label
            Ok(())
        }
        fn from_bytes(_input: &[u8]) -> Result<Self, EP> {
            Ok(Ignored)
        }
    }

    impl ObjectSetMethods for P2MultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = Ignored;
        fn resolve_option(self, _found: Option<Ignored>) -> Result<Ignored, EP> {
            Ok(Ignored)
        }
        fn debug_core(self) -> &'static str {
            "Ignored"
        }
    }

    impl<'f> encode::MultiplicityMethods<'f> for EMultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = IgnoredItemOrObjectValue;
        fn iter_ordered(self, _: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
            iter::empty()
        }
    }

    impl encode::OptionalityMethods for EMultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = IgnoredItemOrObjectValue;
        fn as_option<'f>(self, _: &'f Self::Field) -> Option<&'f Self::Each> {
            None
        }
    }

    impl ItemValueEncodable for IgnoredItemOrObjectValue {
        fn write_item_value_onto(&self, _: ItemEncoder) -> Result<(), Bug> {
            void::unreachable(self.0)
        }
    }

    impl ItemObjectEncodable for IgnoredItemOrObjectValue {
        fn label(&self) -> &str {
            void::unreachable(self.0)
        }
        fn write_object_onto(&self, _: &mut Vec<u8>) -> Result<(), Bug> {
            void::unreachable(self.0)
        }
    }

    impl ItemArgumentParseable for NoMoreArguments {
        fn from_args(args: &mut ArgumentStream) -> Result<NoMoreArguments, ArgumentError> {
            Ok(args.reject_extra_args()?)
        }
    }

    impl ItemArgument for NoMoreArguments {
        fn write_arg_onto(&self, _: &mut ItemEncoder) -> Result<(), Bug> {
            Ok(())
        }
    }

    impl<T: Default> ItemValueParseable for ItemPresent<T> {
        fn from_unparsed(item: UnparsedItem<'_>) -> StdResult<Self, EP> {
            item.check_no_object()?;
            Ok(Self::default())
        }
    }

    impl<T: Default> ItemValueEncodable for ItemPresent<T> {
        fn write_item_value_onto(&self, out: ItemEncoder) -> StdResult<(), Bug> {
            out.finish();
            Ok(())
        }
    }
}

// ============================================================

/// Information about unknown values, which may have been retained as a `T`
///
/// Won't grow additional variants - but, `Retained` is only included conditionally.
///
/// Also used in the form `Unknown<()>` to indicate whether unknown values *should* be retained.
///
/// ### Example
///
/// ```
/// # {
/// #![cfg(feature = "retain-unknown")]
///
/// use tor_netdoc::types::Unknown;
///
/// let mut unk: Unknown<Vec<String>> = Unknown::new_retained_default();
/// unk.with_mut_unknown(|u| u.push("something-we-found".into()));
/// assert_eq!(unk.into_retained().unwrap(), ["something-we-found"]);
/// # }
/// ```
///
/// ### Equality comparison, semantics
///
/// Two `Unknown` are consider equal if both have the same record of unknown values,
/// or if neither records unknown values at all.
///
/// `Unknown` is not `Eq` or `Ord` because we won't want to relate a `Discarded`
/// to a `Retained`.  That would be a logic error.  `partial_cmp` gives `None` for this.
#[derive(Debug, PartialEq, Clone, Copy, Hash)]
#[allow(clippy::exhaustive_enums)] // this isn't going to change
pub enum Unknown<T> {
    /// The parsing discarded unknown values and they are no longer available.
    Discarded(PhantomData<T>),

    /// The document parsing retained (or should retain) unknown values.
    #[cfg(feature = "retain-unknown")]
    Retained(T),
}

impl<T> Unknown<T> {
    /// Create an `Unknown` which specifies that values were discarded (or should be)
    pub fn new_discard() -> Self {
        Unknown::Discarded(PhantomData)
    }

    /// Map the `Retained`, if there is one
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Unknown<U> {
        self.try_map(move |t| Ok::<_, Void>(f(t))).void_unwrap()
    }

    /// Map the `Retained`, fallibly
    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<Unknown<U>, E> {
        Ok(match self {
            Unknown::Discarded(_) => Unknown::Discarded(PhantomData),
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => Unknown::Retained(f(t)?),
        })
    }

    /// Obtain an `Unknown` containing (maybe) a reference
    pub fn as_ref(&self) -> Unknown<&T> {
        match self {
            Unknown::Discarded(_) => Unknown::Discarded(PhantomData),
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => Unknown::Retained(t),
        }
    }

    /// Return the retained unknown data, giving `None` if none was saved
    ///
    /// This is the function for disregarding the possible previously existence
    /// of now-discarded unknown (unrecognised) information.
    ///
    /// Use [`into_retained`](Self::into_retained) if it would be a bug
    /// if unrecognised information had been previously discarded.
    pub fn only_known(self) -> Option<T> {
        match self {
            Unknown::Discarded(_) => None,
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => Some(t),
        }
    }

    /// Obtain the `Retained` data
    ///
    /// Treats lack of retention as an internal error.
    pub fn into_retained(self) -> Result<T, Bug> {
        match self {
            Unknown::Discarded(_) => Err(internal!("Unknown::retained but data not collected")),
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => Ok(t),
        }
    }

    /// Start recording unknown information, with a default value for `T`
    #[cfg(feature = "retain-unknown")]
    pub fn new_retained_default() -> Self
    where
        T: Default,
    {
        Unknown::Retained(T::default())
    }

    /// Update the `Retained`, if there is one
    ///
    /// Intended for use in parsing, when we encounter an unknown value.
    ///
    /// Not provided in `try_` form.  If you think you need this, instead, unconditionally
    /// parse and verify the unknown value, and then conditionally insert it with this function.
    /// Don't parse it conditionally - that would skip some validation.
    pub fn with_mut_unknown(&mut self, f: impl FnOnce(&mut T)) {
        match self {
            Unknown::Discarded(_) => {}
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => f(t),
        }
    }
}

impl<T: PartialOrd> PartialOrd for Unknown<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        use Unknown::*;
        match (self, other) {
            (Discarded(_), Discarded(_)) => Some(cmp::Ordering::Equal),
            #[cfg(feature = "retain-unknown")]
            (Discarded(_), Retained(_)) | (Retained(_), Discarded(_)) => None,
            #[cfg(feature = "retain-unknown")]
            (Retained(a), Retained(b)) => a.partial_cmp(b),
        }
    }
}

// ============================================================

/// A finite floating point number
///
/// Suitable for `stats` items in voites' routerstatus entries:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:stats>
///
/// Invariants:
///
///  * Is finite.  (So not NaN or Inf.)  Might be denormal.
///
/// String representation:
///
///  * Parses any valid C-like notation.
///
///  * Never uses exponential notation to display.
///
///  * Output can be rather large, up to 326 characters!
///    This is a spec bug.  The spec forbids us from using exponential notation.
///    <https://gitlab.torproject.org/tpo/core/torspec/-/work_items/416>
///
/// We may to change this in the future to use exponentials notation for output.
/// See <https://gitlab.torproject.org/tpo/core/torspec/-/work_items/416>
//
// TODO torspec#416 Consider replacing our F64Finite with finite f64 newtype from some crate
//
// What a palaver!
//
// This type is here rather than in rs.rs, in case similar things appears in other documents.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)] //
#[derive(derive_more::Deref, derive_more::Into, derive_more::Display)]
pub struct F64Finite(f64);

/// Error converting an [`F64Finite`] from an `f64`: the value wasn't finite
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error, amplify::Getters)]
#[error("FP value {} ({bits:#x}) is not finite", f64::from_bits(self.bits))]
pub struct F64FiniteError {
    /// The raw bits (as from [`f64::to_bits`])
    //
    // We store it this way rather than as `f64` so that `Eq` etc. make sense.
    bits: u64,
}

impl TryFrom<f64> for F64Finite {
    type Error = F64FiniteError;

    fn try_from(v: f64) -> Result<Self, F64FiniteError> {
        v.is_finite()
            .then_some(F64Finite(v))
            .ok_or_else(|| F64FiniteError { bits: v.to_bits() })
    }
}

/// Error parsing [`F64Finite`] from a string
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum F64FiniteParseError {
    /// Syntax error
    #[error("syntax error")]
    Syntax(#[from] std::num::ParseFloatError),

    /// Value is not finite
    #[error("bad value")]
    NotFinite(#[from] F64FiniteError),
}

impl FromStr for F64Finite {
    type Err = F64FiniteParseError;

    fn from_str(s: &str) -> StdResult<Self, F64FiniteParseError> {
        Ok(s.parse::<f64>()?.try_into()?)
    }
}

impl Eq for F64Finite {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for F64Finite {
    fn cmp(&self, other: &F64Finite) -> cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("finite f64 partial_cmp gave None")
    }
}

impl NormalItemArgument for F64Finite {}

// ============================================================

/// Known keyword (enum) value, or arbitrary string
///
/// `T` should be a `Copy` enum with unit variants.
/// It should have appropriate `FromStr` and `Display`,
/// as well as [`NormalItemArgument`], impls.
///
/// Then `KeywordOrString` will implement the same traits.
///
/// Unlike [`Unknown`], unknown values are always retained as strings.
//
// `RelayFlags` has machinery for parsing flags and retaining unknown values,
// but it uses `Unknown` to maybe discard unknown flags,
// and it is generally quite a lot more complicated.
#[derive(Debug, PartialEq, Clone, Hash)]
#[allow(clippy::exhaustive_enums)] // this isn't going to change
pub enum KeywordOrString<T: Copy> {
    /// Known and recognised `T`
    Known(T),

    /// Unknown value in arbitrary syntax
    Unknown(String),
}

impl<T: Copy + NormalItemArgument> NormalItemArgument for KeywordOrString<T> {}

impl<T: Copy + Display> Display for KeywordOrString<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeywordOrString::Known(t) => Display::fmt(t, f),
            KeywordOrString::Unknown(s) => Display::fmt(s, f),
        }
    }
}

impl<T: Copy + FromStr> FromStr for KeywordOrString<T> {
    type Err = Void;
    fn from_str(s: &str) -> Result<Self, Void> {
        Ok(match s.parse() {
            Ok(y) => KeywordOrString::Known(y),
            Err(_) => KeywordOrString::Unknown(s.to_owned()),
        })
    }
}

// ============================================================

/// A sequence of `T` items, with their order retained
///
/// Normally when a `Vec<T>` appears in a network document,
/// we expect the items to be sortable - they must impl [`EncodeOrd`](encode::EncodeOrd).
/// When encoding, the output is always sorted.
///
/// *This* type retains the ordering.
///
/// Implements the [`encode`] and [`parse2`] item multiplicity traits.
#[derive(Debug, Clone, Hash, Deftly, Eq, PartialEq, Educe)]
#[educe(Default)]
#[derive_deftly(Transparent)]
#[allow(clippy::exhaustive_structs)]
pub struct RetainedOrderVec<T>(pub Vec<T>);

// ============================================================

/// Types for decoding times and dates
mod timeimpl {
    use super::*;
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use std::time::SystemTime;
    use time::{
        OffsetDateTime, PrimitiveDateTime, format_description::FormatItem,
        macros::format_description,
    };

    /// A wall-clock time, encoded in Iso8601 format with an intervening
    /// space between the date and time.
    ///
    /// (Example: "2020-10-09 17:38:12")
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Iso8601TimeSp(pub SystemTime);

    /// Formatting object for parsing the space-separated Iso8601 format.
    const ISO_8601SP_FMT: &[FormatItem] =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

    impl FromStr for Iso8601TimeSp {
        type Err = Error;
        fn from_str(s: &str) -> Result<Iso8601TimeSp> {
            let d = PrimitiveDateTime::parse(s, &ISO_8601SP_FMT).map_err(|e| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg(format!("invalid time: {}", e))
            })?;
            Ok(Iso8601TimeSp(d.assume_utc().into()))
        }
    }

    /// Formats a SystemTime according to the given format description
    ///
    /// Also converts any time::error::format to fmt::Error
    /// so that it can be unwrapped in the Display trait impl
    fn fmt_with(
        t: SystemTime,
        format_desc: &[FormatItem],
    ) -> core::result::Result<String, fmt::Error> {
        OffsetDateTime::from(t)
            .format(format_desc)
            .map_err(|_| fmt::Error)
    }

    impl Display for Iso8601TimeSp {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", fmt_with(self.0, ISO_8601SP_FMT)?)
        }
    }

    /// A wall-clock time, encoded in ISO8601 format without an intervening
    /// space.
    ///
    /// This represents a specific UTC instant (ie an instant in global civil time).
    /// But it may not be able to represent leap seconds.
    ///
    /// The timezone is not included in the string representation; `+0000` is implicit.
    ///
    /// (Example: "2020-10-09T17:38:12")
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Iso8601TimeNoSp(pub SystemTime);

    /// Formatting object for parsing the space-separated Iso8601 format.
    const ISO_8601NOSP_FMT: &[FormatItem] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

    impl FromStr for Iso8601TimeNoSp {
        type Err = Error;
        fn from_str(s: &str) -> Result<Iso8601TimeNoSp> {
            let d = PrimitiveDateTime::parse(s, &ISO_8601NOSP_FMT).map_err(|e| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg(format!("invalid time: {}", e))
            })?;
            Ok(Iso8601TimeNoSp(d.assume_utc().into()))
        }
    }

    impl Display for Iso8601TimeNoSp {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", fmt_with(self.0, ISO_8601NOSP_FMT)?)
        }
    }

    impl crate::NormalItemArgument for Iso8601TimeNoSp {}
}

/// Types for decoding RSA keys
mod rsa {
    use super::*;
    use crate::{NetdocErrorKind as EK, Pos, Result};
    use std::ops::RangeBounds;
    use tor_llcrypto::pk::rsa::PublicKey;
    use tor_llcrypto::{d::Sha1, pk::rsa::KeyPair};

    /// The fixed exponent which we require when parsing any RSA key in a netdoc
    //
    // TODO this value is duplicated a lot in the v1 parser
    pub(crate) const RSA_FIXED_EXPONENT: u32 = 65537;

    /// The fixed exponent which we require when parsing any RSA key in a netdoc
    //
    // TODO this value is duplicated a lot in the v1 parser
    pub(crate) const RSA_MIN_BITS: usize = 1024;

    /// RSA public key, partially processed by `crate::paarse`.
    ///
    /// As parsed from a base64-encoded object.
    /// They key's properties (exponent and size) haven't been checked.
    #[allow(non_camel_case_types)]
    #[derive(Clone, Debug)]
    pub(crate) struct RsaPublicParse1Helper(PublicKey, Pos);

    /// RSA signature using SHA-1 as per "Signing documents" in dir-spec
    ///
    /// <https://spec.torproject.org/dir-spec/netdoc.html#signing>
    ///
    /// Used for
    /// [`AuthCert::dir-key-certification`](crate::doc::authcert::AuthCert::dir-key-certification),
    /// for example.
    ///
    /// # Caveats
    ///
    /// This type MUST NOT be used for anomalous signatures
    /// such as
    /// [`AuthCert::dir_key_crosscert`](crate::doc::authcert::AuthCert::dir_key_crosscert);
    /// in that case because `dir_key_crosscert`'s
    /// set of allowed object labels includes `ID SIGNATURE` whereas this type
    /// is always `SIGNATURE`
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[deftly(netdoc(no_extra_args, signature(hash_accu = Sha1WholeKeywordLine)))]
    #[non_exhaustive]
    pub struct RsaSha1Signature {
        /// The bytes of the signature (base64-decoded).
        #[deftly(netdoc(object(label = "SIGNATURE"), with = crate::types::raw_data_object))]
        pub signature: Vec<u8>,
    }

    impl From<RsaPublicParse1Helper> for PublicKey {
        fn from(k: RsaPublicParse1Helper) -> PublicKey {
            k.0
        }
    }
    impl super::FromBytes for RsaPublicParse1Helper {
        fn from_bytes(b: &[u8], pos: Pos) -> Result<Self> {
            let key = PublicKey::from_der(b)
                .ok_or_else(|| EK::BadObjectVal.with_msg("unable to decode RSA public key"))?;
            Ok(RsaPublicParse1Helper(key, pos))
        }
    }
    impl RsaPublicParse1Helper {
        /// Give an error if the exponent of this key is not 'e'
        pub(crate) fn check_exponent(self, e: u32) -> Result<Self> {
            if self.0.exponent_is(e) {
                Ok(self)
            } else {
                Err(EK::BadObjectVal
                    .at_pos(self.1)
                    .with_msg("invalid RSA exponent"))
            }
        }
        /// Give an error if the length of this key's modulus, in
        /// bits, is not contained in 'bounds'
        pub(crate) fn check_len<B: RangeBounds<usize>>(self, bounds: B) -> Result<Self> {
            if bounds.contains(&self.0.bits()) {
                Ok(self)
            } else {
                Err(EK::BadObjectVal
                    .at_pos(self.1)
                    .with_msg("invalid RSA length"))
            }
        }
        /// Give an error if the length of this key's modulus, in
        /// bits, is not exactly `n`.
        pub(crate) fn check_len_eq(self, n: usize) -> Result<Self> {
            self.check_len(n..=n)
        }
    }

    impl RsaSha1Signature {
        /// Make a signature according to "Signing documents" in the netdoc spec
        ///
        /// <https://spec.torproject.org/dir-spec/netdoc.html#signing>
        ///
        /// `NetdocEncoder` should have had the body of the document
        /// (everything except the signatures) already encoded.
        ///
        /// `item_keyword` is the keyword for the signature item.
        /// This is needed because different documents use different keywords,
        /// and the keyword is covered by the signature (an annoying is a layering violation).
        /// See <https://gitlab.torproject.org/tpo/core/torspec/-/issues/322>.
        ///
        /// # Example
        ///
        /// ```
        /// use derive_deftly::Deftly;
        /// use tor_error::Bug;
        /// use tor_llcrypto::pk::rsa;
        /// use tor_netdoc::derive_deftly_template_NetdocEncodable;
        /// use tor_netdoc::encode::{NetdocEncodable, NetdocEncoder};
        /// use tor_netdoc::types::RsaSha1Signature;
        ///
        /// #[derive(Deftly, Default)]
        /// #[derive_deftly(NetdocEncodable)]
        /// pub struct Document {
        ///     pub document_intro_keyword: (),
        /// }
        /// #[derive(Deftly)]
        /// #[derive_deftly(NetdocEncodable)]
        /// pub struct DocumentSignatures {
        ///     pub document_signature: RsaSha1Signature,
        /// }
        /// impl Document {
        ///     pub fn encode_sign(&self, k: &rsa::KeyPair) -> Result<String, Bug> {
        ///         let mut encoder = NetdocEncoder::new();
        ///         self.encode_unsigned(&mut encoder)?;
        ///         let document_signature =
        ///             RsaSha1Signature::new_sign_netdoc(k, &encoder, "document-signature")?;
        ///         let sigs = DocumentSignatures { document_signature };
        ///         sigs.encode_unsigned(&mut encoder)?;
        ///         let encoded = encoder.finish()?;
        ///         Ok(encoded)
        ///     }
        /// }
        ///
        /// # fn main() -> Result<(), anyhow::Error> {
        /// let k = rsa::KeyPair::generate(&mut tor_basic_utils::test_rng::testing_rng())?;
        /// let doc = Document::default();
        /// let encoded = doc.encode_sign(&k)?;
        /// assert!(encoded.starts_with(concat!(
        ///     "document-intro-keyword\n",
        ///     "document-signature\n",
        ///     "-----BEGIN SIGNATURE-----\n",
        /// )));
        /// # Ok(())
        /// # }
        /// ```
        pub fn new_sign_netdoc(
            private_key: &KeyPair,
            encoder: &NetdocEncoder,
            item_keyword: &str,
        ) -> StdResult<Self, Bug> {
            let mut h = Sha1::new();
            h.update(encoder.text_sofar()?);
            h.update(item_keyword);
            h.update("\n");
            let h = h.finalize();
            let signature = private_key
                .sign(&h)
                .map_err(into_internal!("RSA signing failed"))?;
            Ok(RsaSha1Signature { signature })
        }
    }
}

/// Types for decoding Ed25519 certificates
mod edcert {
    use std::result::Result as StdResult;
    use std::time::SystemTime;

    use crate::types::EmbeddedCert;
    use crate::{
        NetdocErrorKind as EK, Pos, Result,
        parse2::{ErrorProblem, VerifyFailed},
        types::EmbeddableCertObject,
    };
    use tor_cert::{CertType, CertifiedKey, Ed25519Cert, KeyUnknownCert};
    use tor_checkable::signed::SignatureGated;
    use tor_checkable::timed::TimeRangeBound;
    use tor_checkable::{SelfSigned, TimeBound};
    use tor_error::{Bug, into_internal};
    use tor_llcrypto::pk::ed25519::{self, Ed25519PublicKey, ValidatableEd25519Signature};

    /// An ed25519 certificate as parsed from a directory object, with
    /// signature not validated.
    #[derive(Debug, Clone)]
    pub(crate) struct UnvalidatedEdCert(KeyUnknownCert, Pos);

    impl super::FromBytes for UnvalidatedEdCert {
        fn from_bytes(b: &[u8], p: Pos) -> Result<Self> {
            let cert = Ed25519Cert::decode(b).map_err(|e| {
                EK::BadObjectVal
                    .at_pos(p)
                    .with_msg("Bad certificate")
                    .with_source(e)
            })?;

            Ok(Self(cert, p))
        }
        fn from_vec(v: Vec<u8>, p: Pos) -> Result<Self> {
            Self::from_bytes(&v[..], p)
        }
    }
    impl UnvalidatedEdCert {
        /// Give an error if this certificate's type is not `desired_type`.
        pub(crate) fn check_cert_type(self, desired_type: CertType) -> Result<Self> {
            if self.0.peek_cert_type() != desired_type {
                return Err(EK::BadObjectVal.at_pos(self.1).with_msg(format!(
                    "bad certificate type {} (wanted {})",
                    self.0.peek_cert_type(),
                    desired_type
                )));
            }
            Ok(self)
        }
        /// Give an error if this certificate's subject_key is not `pk`
        pub(crate) fn check_subject_key_is(self, pk: &ed25519::Ed25519Identity) -> Result<Self> {
            if self.0.peek_subject_key().as_ed25519() != Some(pk) {
                return Err(EK::BadObjectVal
                    .at_pos(self.1)
                    .with_msg("incorrect subject key"));
            }
            Ok(self)
        }
        /// Consume this object and return the inner Ed25519 certificate.
        pub(crate) fn into_unchecked(self) -> KeyUnknownCert {
            self.0
        }
    }

    /// An Ed25519 identity certificate.
    ///
    /// This is a certificate of [`CertType::IDENTITY_V_SIGNING`] where the
    /// relay's long-term ed25519 identity key signs the relay's medium-term
    /// ed25519 signing key, used for signing almost all other certifications
    /// associated with a given relay.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Ed25519IdentityCert {
        /// The long-term ed25519 identity key of the relay
        pub id_ed25519: ed25519::Ed25519Identity,
        /// The medium-term ed25519 signing key of the relay.
        pub sign_ed25519: ed25519::Ed25519Identity,
    }

    impl EmbeddableCertObject<KeyUnknownCert> for Ed25519IdentityCert {
        const LABEL: &str = "ED25519 CERT";
    }

    impl Ed25519IdentityCert {
        /// Verifies the validity of an [`Ed25519IdentityCert`].
        ///
        /// # Requirements
        ///
        /// 1. MUST have the identity key in the `signed-with-ed25519-key` extension.
        /// 2. MUST have a valid signature by the identity key.
        /// 3. MUST be of [`CertType::IDENTITY_V_SIGNING`].
        /// 4. Certified key MUST BE of [`tor_cert::CertifiedKey::Ed25519`].
        /// 5. Both keys MUST be valid mappings to a [`ed25519::PublicKey`].
        pub fn verify(cert: KeyUnknownCert) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            let cert = cert
                // 1. MUST have the identity key in the `signed-with-ed25519-key` extension.
                .should_have_signing_key()
                .map_err(|_| VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData))?
                // 2. MUST have a valid signature by the identity key.
                .check_signature()?
                // Okay to call because we create TimeRangeBound later.
                // TODO DIRAUTH: Use TimeRangeBound instead.
                .dangerously_assume_timely();

            // 3. MUST be of [`CertType::IDENTITY_V_SIGNING`].
            if cert.cert_type() != CertType::IDENTITY_V_SIGNING {
                return Err(VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData));
            }

            // Bug is alright because .should_have_signing_key() assured us.
            let id_ed25519 = *cert.signing_key().ok_or(VerifyFailed::Bug)?;

            // 4. Certified key MUST BE of [`tor_cert::CertifiedKey::Ed25519`].
            let sign_ed25519 = *cert
                .subject_key()
                .as_ed25519()
                .ok_or(VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData))?;

            // 5. Both keys MUST be valid mappings to a [`ed25519::PublicKey`].
            // Unsure if this check is required or implied by (2) but defensive
            // programming does not hurt.
            if ed25519::PublicKey::try_from(id_ed25519).is_err()
                || ed25519::PublicKey::try_from(sign_ed25519).is_err()
            {
                return Err(VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData));
            }

            Ok(TimeRangeBound::new(
                Self {
                    id_ed25519,
                    sign_ed25519,
                },
                ..cert.expiry(),
            ))
        }

        /// Creates a new signed [`Ed25519IdentityCert`].
        pub fn new_signed(
            id_ed25519: &ed25519::Keypair,
            sign_ed25519: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            let cert = Ed25519Cert::builder()
                .expiration(expiry)
                .signing_key(id_ed25519.public_key().into())
                .cert_type(CertType::IDENTITY_V_SIGNING)
                .cert_key(sign_ed25519.into())
                .encode_and_sign(id_ed25519)
                .map_err(into_internal!("failed to encode and sign identity cert"))?;

            let cert =
                Ed25519Cert::decode(&cert).map_err(into_internal!("decode just encoded cert"))?;

            Ok(EmbeddedCert::new(
                Self {
                    id_ed25519: id_ed25519.public_key().into(),
                    sign_ed25519,
                },
                cert,
            ))
        }
    }

    /// An Ed25519 family certificate.
    ///
    /// This is a certificate of [`CertType::FAMILY_V_IDENTITY`] where the
    /// family key signs the long-term ed25519 identity key of the given relay.
    ///
    /// It purposely does not store the long-term ed25519 identity key of the
    /// relay because the idea of this type should be equal only to other types
    /// with the same family key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Ed25519FamilyCert {
        /// The public key of the family.
        // TODO: We probably want to add a getter for this returning the
        // family name as in:
        // <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:family-cert>
        pub family_ed25519: ed25519::Ed25519Identity,
    }

    impl EmbeddableCertObject<KeyUnknownCert> for Ed25519FamilyCert {
        const LABEL: &str = "FAMILY CERT";
    }

    impl Ed25519FamilyCert {
        /// Verifies the validity of an [`Ed25519FamilyCert`].
        ///
        /// For such a certificate to be valid, the caller must provide a
        /// known Ed25519 identity key of the relay beforehand.
        ///
        /// # Requirements
        ///
        /// 1. MUST have the `signed-with-ed25519-key` extension containing the family key.
        /// 2. MUST have a valid signature by the family key.
        /// 3. MUST be of of [`CertType::FAMILY_V_IDENTITY`].
        /// 4. Certified key MUST BE of [`tor_cert::CertifiedKey::Ed25519`].
        /// 5. `id_ed25519` MUST be the certified key.
        /// 6. Both keys MUST be valid mappings to a [`ed25519::PublicKey`].
        pub fn verify(
            id_ed25519: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            let cert = cert
                // 1. MUST have the `signed-with-ed25519-key` extension containing the family key.
                .should_have_signing_key()?
                // 2. MUST have a valid signature by the family key.
                .check_signature()?
                // Okay to call because we create TimeRangeBound later.
                // TODO DIRAUTH: Use TimeRangeBound instead.
                .dangerously_assume_timely();

            // 3. MUST be of of [`CertType::FAMILY_V_IDENTITY`].
            if cert.cert_type() != CertType::FAMILY_V_IDENTITY {
                return Err(ErrorProblem::ObjectInvalidData.into());
            }

            // Bug is alright because .should_have_signing_key() assured us.
            let family_ed25519 = *cert.signing_key().ok_or(VerifyFailed::Bug)?;

            // 4. Certified key MUST BE of [`tor_cert::CertifiedKey::Ed25519`].
            let certified_key = *cert
                .subject_key()
                .as_ed25519()
                .ok_or(VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData))?;

            // 5. `id_ed25519` MUST be the certified key.
            if certified_key != id_ed25519 {
                return Err(VerifyFailed::VerifyFailed);
            }

            // 6. Both keys MUST be valid mappings to a [`ed25519::PublicKey`].
            if ed25519::PublicKey::try_from(family_ed25519).is_err()
                || ed25519::PublicKey::try_from(id_ed25519).is_err()
            {
                return Err(VerifyFailed::ParseEmbedded(ErrorProblem::ObjectInvalidData));
            }

            Ok(TimeRangeBound::new(
                Self { family_ed25519 },
                ..cert.expiry(),
            ))
        }

        /// Creates a new signed [`Ed25519FamilyCert`].
        pub fn new_signed(
            family_ed25519: &ed25519::Keypair,
            id_ed25519: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            let cert = Ed25519Cert::builder()
                .expiration(expiry)
                .signing_key(family_ed25519.public_key().into())
                .cert_type(CertType::FAMILY_V_IDENTITY)
                .cert_key(id_ed25519.into())
                .encode_and_sign(family_ed25519)
                .map_err(into_internal!("failed to encode and sign family cert"))?;

            let cert =
                Ed25519Cert::decode(&cert).map_err(into_internal!("decode just encoded cert"))?;

            Ok(EmbeddedCert::new(
                Self {
                    family_ed25519: family_ed25519.public_key().into(),
                },
                cert,
            ))
        }
    }

    /// Verified reverse cert by K_ntor on KP_relayid_ed
    ///
    /// This certificate is signed by KS_ntor
    /// (the circuit extension key) and certifies
    /// KP_relayid_ed25519 ed25519 identity key of the relay.
    ///
    /// The type itself is zero-sized because it provides no new useful
    /// information that cannot be found elsewhere within the router descriptor.
    /// It is intended for use within
    /// [`EmbeddedCert`]`<Ed25519NtorCrossCert, KeyUnknownCert>`
    ///
    /// # Note on key conversion
    ///
    /// Keep in mind however that the ntor onion key is only provided as an
    /// X25519 key and *not* an Ed25519 key, meaning that interfacing
    /// applications have to convert it using a function such as
    /// [`tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public()`].
    /// This also requires obtaining the sign bit which is usually given as an
    /// argument in the `ntor-onion-key-crosscert` item.  However, this is
    /// outside of the scope of this struct and the code will assume that
    /// callers have already converted the X25519 public key to an Ed25519
    /// public key as outlined in the specifications.
    ///
    /// # See Also
    ///
    /// * <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:ntor-onion-key-crosscert>
    /// * <https://spec.torproject.org/dir-spec/converting-to-ed25519.html>
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Ed25519NtorCrossCert {
        /// Explicit field, to avoid constructing this accidentally without
        /// doing all the verification.
        _promise_we_verified: (),
    }

    impl EmbeddableCertObject<KeyUnknownCert> for Ed25519NtorCrossCert {
        const LABEL: &str = "ED25519 CERT";
    }

    impl Ed25519NtorCrossCert {
        /// Verifies the validity of an [`Ed25519NtorCrossCert`].
        ///
        /// For such a certificate to be valid, the caller must provide a known
        /// Ed25519 identity key and Ed25519 ntor onion key of the relay
        /// beforehand.
        ///
        /// # Requirements
        ///
        /// 1. MUST be of [`CertType::NTOR_CC_IDENTITY`].
        /// 2. Certified key MUST be of [`CertifiedKey::Ed25519`].
        /// 3. Certified key MUST be equal to `id_ed25519`.
        /// 4. MUST have a valid signature.
        pub fn verify(
            ntor_ed25519: ed25519::Ed25519Identity,
            id_ed25519: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            Ok(
                // .verify_inner() ensures 1-3.
                Self::verify_inner(ntor_ed25519, id_ed25519, cert)?
                    .0
                    // 4. MUST have a valid signature.
                    .check_signature()?,
            )
        }

        /// Creates a new signed [`Ed25519NtorCrossCert`].
        pub fn new_signed(
            ntor_ed25519: &ed25519::ExpandedKeypair,
            id_ed25519: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            let cert = Ed25519Cert::builder()
                .expiration(expiry)
                .cert_type(CertType::NTOR_CC_IDENTITY)
                .cert_key(id_ed25519.into())
                .encode_and_sign(ntor_ed25519)
                .map_err(into_internal!("failed to encode and sign ntor cert"))?;

            let cert =
                Ed25519Cert::decode(&cert).map_err(into_internal!("decode just encoded cert"))?;

            Ok(EmbeddedCert::new(
                Self {
                    _promise_we_verified: (),
                },
                cert,
            ))
        }

        /// Verifies the validity of a [`KeyUnknownCert`] believed to be a
        /// [`CertType::NTOR_CC_IDENTITY`].
        ///
        /// This function serves as glue between the legacy parser and
        /// [`Self::verify()`].
        ///
        /// # Requirements
        ///
        /// 1. MUST be of [`CertType::NTOR_CC_IDENTITY`].
        /// 2. Certified key MUST be of [`CertifiedKey::Ed25519`].
        /// 3. Certified key MUST be equal to `id_ed25519`.
        ///
        /// # Return Type
        ///
        /// Actual signature and time validation is done by the caller, hence
        /// why it returns a gated type as the first element of the tuple.
        /// The other elements constitute the inner signature plus the
        /// SystemTime denoting the expiry.  This is required for integration
        /// with legacy parser in order to enable pushing it to the verification
        /// batch, as the [`tor_checkable`] primitives do not provide access
        /// to the inner signatures/expiries and also do not support operations
        /// like cloning due to being dyn.
        pub(crate) fn verify_inner(
            ntor_ed25519: ed25519::Ed25519Identity,
            id_ed25519: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<
            (
                SignatureGated<TimeRangeBound<Self>>,
                ValidatableEd25519Signature,
                SystemTime,
            ),
            VerifyFailed,
        > {
            // 1. MUST be of [`CertType::NTOR_CC_IDENTITY`].
            if cert.peek_cert_type() != CertType::NTOR_CC_IDENTITY {
                return Err(ErrorProblem::ObjectInvalidData.into());
            }

            // 2. Certified key MUST be of [`CertifiedKey::Ed25519`].
            // 3. Certified key MUST be equal to `id_ed25519`.
            if cert.peek_subject_key() != &CertifiedKey::Ed25519(id_ed25519) {
                return Err(VerifyFailed::VerifyFailed);
            }

            // Fish out the signature from the certificate and verify it later.
            //
            // It may fail if ntor_ed25519 is not a valid mapping to a public
            // key.  This is okay.  The .should_be_signed_with() call is
            // tor_cert boilerplate and only required to obtain an
            // UncheckedCert, as ntor cross-certificates do not contain the
            // signed-with extension.
            let (cert, sig) = cert
                .should_be_signed_with(&ntor_ed25519)?
                .dangerously_split()?;

            // Fish out the expiration date from the certificate.
            //
            // Important: We must not set SystemTime::UNIX_EPOCH as the lower
            // bound, because with TimeRangeBound, a lower-bound of zero is not
            // equal to an absent lower bound!
            let cert = cert.dangerously_assume_timely();
            let expiration = ..cert.expiry();

            Ok((
                SignatureGated::new(
                    TimeRangeBound::new(
                        Self {
                            _promise_we_verified: (),
                        },
                        expiration,
                    ),
                    vec![Box::new(sig.clone())],
                ),
                sig,
                expiration.end,
            ))
        }

        /// Internal function for creating an unverified instance.
        ///
        /// This is only intended for testing and legacy parser compatibility
        /// purposes.
        pub(crate) fn dangerous_new_unverified() -> Self {
            Self {
                _promise_we_verified: (),
            }
        }
    }
}

/// Digest identifiers, and digests in the form `ALGORITHM=BASE64U`
///
/// As found in a vote's `m` line.
// TODO Use FixedB64 here.
mod identified_digest {
    use super::*;

    define_derive_deftly! {
        /// impl `FromStr` and `Display` for an enum with unit variants but also "unknown"
        ///
        /// Expected input: an enum whose variants are either
        ///  * unit variants, perhaps with `#[deftly(string_repr = "string")]`
        ///  * singleton tuple variant, containing `String` (or near equivalent)
        ///
        /// If `#[deftly(string_repro)]` is not specified,
        /// the default is snake case of the variant name.
        //
        // This macro may seem overkill, but open-coding these impls gives opportunities
        // for mismatches between FromStr, Display, and the variant name.
        //
        // TODO consider putting this in tor-basic-utils (maybe with a better name),
        // or possibly asking if derive_more want their FromStr to have this.
        StringReprUnitsOrUnknown for enum, expect items, beta_deftly:

        ${define STRING_REPR {
            ${vmeta(string_repr)
              as str,
              default { ${concat ${snake_case $vname}} }
            }
        }}

        impl FromStr for $ttype {
            type Err = Void;
            fn from_str(s: &str) -> Result<Self, Void> {
                $(
                    ${when v_is_unit}
                    if s == $STRING_REPR {
                        return Ok($vtype)
                    }
                )
                $(
                    ${when not(v_is_unit)} // anything else had better be Unknown
                    // not using `return ..;` makes this a syntax error if there are several.
                    Ok($vtype { 0: s.into() })
                )
            }
        }
        impl AsRef<str> for $ttype {
            fn as_ref(&self) -> &str {
                match self {
                    $(
                        ${when v_is_unit}
                        $vtype => $STRING_REPR,
                    )
                    $(
                        ${when not(v_is_unit)}
                        $vpat => f_0,
                    )
                }
            }
        }
        impl Display for $ttype {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let s: &str = self.as_ref();
                Display::fmt(s, f)
            }
        }
    }

    /// The name of a digest algorithm.
    ///
    /// Can represent an unrecognised algorithm, so it's parsed and reproduced.
    #[derive(Debug, Clone, Eq, PartialEq, Hash, Deftly)]
    #[derive_deftly(StringReprUnitsOrUnknown)]
    #[non_exhaustive]
    pub enum DigestName {
        /// SHA-256
        Sha256,
        /// Unknown
        Unknown(String),
    }

    /// A single digest made with a nominated digest algorithm, `ALGORITHM=DIGEST`
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Display)]
    #[display("{alg}={value}")]
    #[non_exhaustive]
    pub struct IdentifiedDigest {
        /// The algorithm name.
        alg: DigestName,

        /// The digest value.
        ///
        /// Invariant: length is correct for `alg`, assuming `alg` is known.
        value: B64,
    }

    impl NormalItemArgument for DigestName {}
    impl NormalItemArgument for IdentifiedDigest {}

    /// Invalid syntax parsing an `IdentifiedDigest`
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, thiserror::Error)]
    #[error("invalid syntax, expected ALGORITHM=DIGEST: {0}")]
    pub struct IdentifiedDigestParseError(String);

    impl Ord for DigestName {
        fn cmp(&self, other: &Self) -> Ordering {
            self.as_ref().cmp(other.as_ref())
        }
    }
    impl PartialOrd for DigestName {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl FromStr for IdentifiedDigest {
        type Err = IdentifiedDigestParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            (|| {
                let (alg, value) = s.split_once('=').ok_or("missing equals sign")?;

                let alg = alg.parse().void_unwrap();
                let value = value
                    .parse::<B64>()
                    .map_err(|e| format!("bad value: {}", e.report()))?;

                if let Some(exp_len) = (|| {
                    Some({
                        use DigestName::*;
                        match alg {
                            Sha256 => 32,
                            Unknown(_) => None?,
                        }
                    })
                })() {
                    let val_len = value.as_bytes().len();
                    if val_len != exp_len {
                        return Err(format!("got {val_len} bytes, expected {exp_len}"));
                    }
                }

                Ok(IdentifiedDigest { alg, value })
            })()
            .map_err(IdentifiedDigestParseError)
        }
    }
}

/// Types for decoding RSA fingerprints
mod fingerprint {
    use super::*;
    use crate::parse2::{ArgumentError, ArgumentStream, ItemArgumentParseable};
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use base64ct::{Base64Unpadded, Encoding as _};
    use itertools::Itertools;
    use tor_llcrypto::pk::rsa::RsaIdentity;

    /// A hex-encoded RSA key identity (fingerprint) with spaces in it.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html?highlight=fingerprint#item:fingerprint>
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct SpFingerprint(pub RsaIdentity);

    /// A hex-encoded fingerprint with no spaces.
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Fingerprint(pub RsaIdentity);

    /// A base64-encoded fingerprint (unpadded)
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Base64Fingerprint(pub RsaIdentity);

    /// A "long identity" in the format used for Family members.
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub(crate) struct LongIdent(pub RsaIdentity);

    /// Helper: parse an identity from a hexadecimal string
    fn parse_hex_ident(s: &str) -> Result<RsaIdentity> {
        RsaIdentity::from_hex(s).ok_or_else(|| {
            EK::BadArgument
                .at_pos(Pos::at(s))
                .with_msg("wrong length on fingerprint")
        })
    }

    impl FromStr for SpFingerprint {
        type Err = Error;
        fn from_str(s: &str) -> Result<SpFingerprint> {
            let ident = parse_hex_ident(&s.replace(' ', "")).map_err(|e| e.at_pos(Pos::at(s)))?;
            Ok(SpFingerprint(ident))
        }
    }

    impl ItemArgumentParseable for SpFingerprint {
        fn from_args<'s>(
            args: &mut ArgumentStream<'s>,
        ) -> std::result::Result<Self, ArgumentError> {
            // Take the first 10 arguments because an SpFingerprint consists of
            // 10 x 4 = 40 characters.
            let fp = args.take(10).collect::<Vec<_>>();

            // Less than 10 means missing arguments.
            if fp.len() < 10 {
                return Err(ArgumentError::Missing);
            }

            // More than 10 should be impossible due to .take(10).
            debug_assert_eq!(fp.len(), 10);

            // All arguments must be 4 characters long.
            if fp.iter().any(|arg| arg.len() != 4) {
                return Err(ArgumentError::Invalid);
            }

            // Convert it to a string without spaces, RsaIdentity::from_hex will
            // verify the rest.
            Ok(Self(
                RsaIdentity::from_hex(fp.join("").as_str()).ok_or(ArgumentError::Invalid)?,
            ))
        }
    }

    impl encode::ItemArgument for SpFingerprint {
        fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> StdResult<(), Bug> {
            let res = self
                .0
                .to_bytes()
                .chunks(2)
                .map(|b| format!("{:02X}{:02X}", b[0], b[1]))
                .join(" ");
            debug_assert_eq!(res.len(), 4 * 10 + 9);
            out.args_raw_string(&res);
            Ok(())
        }
    }

    impl FromStr for Base64Fingerprint {
        type Err = Error;
        fn from_str(s: &str) -> Result<Base64Fingerprint> {
            let b = s.parse::<super::B64>()?;
            let ident = RsaIdentity::from_bytes(b.as_bytes()).ok_or_else(|| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("Wrong identity length")
            })?;
            Ok(Base64Fingerprint(ident))
        }
    }

    impl Display for Base64Fingerprint {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Display::fmt(&Base64Unpadded::encode_string(self.as_bytes()), f)
        }
    }

    impl FromStr for Fingerprint {
        type Err = Error;
        fn from_str(s: &str) -> Result<Fingerprint> {
            let ident = parse_hex_ident(s).map_err(|e| e.at_pos(Pos::at(s)))?;
            Ok(Fingerprint(ident))
        }
    }

    impl Display for Fingerprint {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Display::fmt(&hex::encode_upper(self.as_bytes()), f)
        }
    }

    impl FromStr for LongIdent {
        type Err = Error;
        fn from_str(mut s: &str) -> Result<LongIdent> {
            s = s.strip_prefix('$').unwrap_or(s);
            // Strip at '=' or '~' if found.
            s = s.split_once(['=', '~']).map(|(a, _)| a).unwrap_or(s);
            let ident = parse_hex_ident(s)?;
            Ok(LongIdent(ident))
        }
    }

    impl Display for LongIdent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "${}", self.0.as_hex_upper())
        }
    }

    impl crate::NormalItemArgument for Fingerprint {}
    impl crate::NormalItemArgument for Base64Fingerprint {}
    impl crate::NormalItemArgument for LongIdent {}
}

/// A type for relay nicknames
mod nickname {
    use super::*;
    use tinystr::TinyAsciiStr;

    /// This is a strange limit, but it comes from Tor.
    const MAX_NICKNAME_LEN: usize = 19;

    /// The nickname for a Tor relay.
    ///
    /// These nicknames are legacy mechanism that's occasionally useful in
    /// debugging. They should *never* be used to uniquely identify relays;
    /// nothing prevents two relays from having the same nickname.
    ///
    /// Nicknames are required to be ASCII, alphanumeric, and between 1 and 19
    /// characters inclusive.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Nickname(tinystr::TinyAsciiStr<MAX_NICKNAME_LEN>);

    /// Invalid nickname
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("invalid nickname")]
    #[non_exhaustive]
    pub struct InvalidNickname {}

    impl Nickname {
        /// Return a view of this nickname as a string slice.
        pub(crate) fn as_str(&self) -> &str {
            self.0.as_str()
        }
    }

    impl Display for Nickname {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.as_str().fmt(f)
        }
    }

    impl FromStr for Nickname {
        type Err = InvalidNickname;

        fn from_str(s: &str) -> Result<Self, InvalidNickname> {
            let tiny = TinyAsciiStr::from_str(s).map_err(|_| InvalidNickname {})?;

            if tiny.is_ascii_alphanumeric() && !tiny.is_empty() {
                Ok(Nickname(tiny))
            } else {
                Err(InvalidNickname {})
            }
        }
    }

    impl crate::NormalItemArgument for Nickname {}
}

/// Hostnames etc.
//
// TODO maybe move all this to tor-basic-utils
mod hostname {
    use super::*;
    use std::net::IpAddr;

    /// Internet hostname
    ///
    /// Valid according to Internet RFC1123,
    /// with the additional restriction that there must be at least one letter.
    /// (That means that anything accepted as a `Hostname`
    /// won't be accepted as an address even by very relaxed IPv4 address parsers.
    /// We presume that no TLD will ever exist that is entirely decimal digits.)
    ///
    /// Preserves case.
    ///
    /// Reserved hostname such as `example.come`, `tor.invalid` and `localhost`
    /// are accepted.
    ///
    /// # Comparisons; `PartialEq`, `Eq`
    ///
    /// The `PartialEq` and `Eq` implementations are case sensitive,
    /// even though internet hostnames are not case-sensitive.
    ///
    /// Comparing hostnames for identical apparent meaning is complicated.
    /// If you need to do that, you (may) need to engage with punycode (IDN),
    /// as well as arranging for a case-insensitive comparison.
    ///
    /// And of course, hostnames reference to the DNS.
    /// A single host may have multiple names and it may change its address.
    #[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)] //
    #[derive(derive_more::Into, derive_more::Deref, derive_more::AsRef, derive_more::Display)]
    pub struct Hostname(String);

    /// Hostname, or IP address (v4 or v6)
    ///
    /// Preserves hostname case.  See [`Hostname`].
    ///
    /// Reserved hostnames and addresses (eg `0.0.0.0` or `tor.invalid`) are accepted.
    ///
    /// IPv6 addresses are represented *without* surrounding `[ ]`.
    ///
    /// Therefore, you cannot make this into a host-and-port by appending `:port`.
    /// To process name-and-port is complex.  `SRV` (or `MX`) records might be involved.
    //
    // This type is called `InternetHost` to emphasise that it is primarily for
    // hosts on the public internet and, unlike arti-client's `Host`,
    // has special handling of `.onion` addresses.
    #[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)] //
    #[derive(derive_more::Display)]
    #[allow(clippy::exhaustive_enums)]
    // TODO derive .as_hostname(), .as_ip_addr(), From<Hostname>, From<IpAddr>
    pub enum InternetHost {
        /// Hostname
        #[display("{_0}")]
        Name(Hostname),
        /// IP address (v4 or v6)
        #[display("{_0}")]
        IpAddr(IpAddr),
    }

    /// Invalid hostname
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("invalid hostname")]
    #[non_exhaustive]
    pub struct InvalidHostname {}

    /// Invalid Internet hostname/address
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("invalid: not a valid hostname, nor a valid IPv4 or IPv6 address")]
    #[non_exhaustive]
    pub struct InvalidInternetHost {}

    impl Hostname {
        /// Obtain this hostname as a `str`
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl AsRef<str> for Hostname {
        fn as_ref(&self) -> &str {
            self.as_str()
        }
    }

    impl TryFrom<String> for Hostname {
        type Error = InvalidHostname;
        fn try_from(s: String) -> Result<Self, InvalidHostname> {
            if hostname_validator::is_valid(&s) &&
                // Reject hostnames that consist only of decimal digits and full stops.
                // Some of those are accepted by some old IPv4 address parsers.
                // If any fool makes a TLD that is only digits, they deserve everything they get.
                !s.chars().all(|c| c.is_ascii_digit() || c == '.')
            {
                Ok(Hostname(s))
            } else {
                Err(InvalidHostname {})
            }
        }
    }

    impl FromStr for Hostname {
        type Err = InvalidHostname;
        fn from_str(s: &str) -> Result<Self, InvalidHostname> {
            s.to_owned().try_into()
        }
    }

    impl FromStr for InternetHost {
        type Err = InvalidInternetHost;
        fn from_str(s: &str) -> Result<Self, InvalidInternetHost> {
            if let Ok(y) = s.parse() {
                Ok(InternetHost::IpAddr(y))
            } else if let Ok(y) = s.parse() {
                Ok(InternetHost::Name(y))
            } else {
                // For simplicity, we  discard the errors from parsing the options
                // rather than trying to reproduce them.  Why something isn't a valid
                // address or hostname ought to be fairly obvious.
                Err(InvalidInternetHost {})
            }
        }
    }

    impl NormalItemArgument for Hostname {}
    impl NormalItemArgument for InternetHost {}
}

/// Contact information of the relay operator.
mod contact_info {
    use super::*;

    /// `contact` item: contact information (eg of a relay dirauth operator)
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:contact>
    ///
    /// Also used for authority entries in netstatus documents.
    #[derive(Clone, Debug, PartialEq, Eq, Deftly)] //
    #[derive(derive_more::Into, derive_more::AsRef, derive_more::Deref, derive_more::Display)]
    #[derive_deftly(ItemValueEncodable)]
    #[non_exhaustive]
    pub struct ContactInfo(#[deftly(netdoc(rest))] String);

    /// Contact information (`contact` item value) has invalid syntax
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("contact information (`contact` item value) has invalid syntax")]
    #[non_exhaustive]
    pub struct InvalidContactInfo {}

    impl FromStr for ContactInfo {
        type Err = InvalidContactInfo;

        fn from_str(s: &str) -> Result<Self, InvalidContactInfo> {
            // TODO torspec#396 we should probably impose more restrictions
            // For now we forbid `\n` and initial whitespace, which is enough to ensure
            // that all values will roundtrip unchanged through netdoc encoding and parsing.
            if s.contains('\n') || s.starts_with(char::is_whitespace) {
                Err(InvalidContactInfo {})
            } else {
                Ok(ContactInfo(s.to_owned()))
            }
        }
    }

    impl ItemValueParseable for ContactInfo {
        fn from_unparsed(mut item: UnparsedItem<'_>) -> Result<Self, parse2::ErrorProblem> {
            item.check_no_object()?;
            item.args_mut()
                .into_remaining()
                .parse()
                .map_err(|_e| item.args().handle_error("info", ArgumentError::Invalid))
        }
    }
}

/// Types for boolean-like types.
mod boolean {
    use derive_deftly::Deftly;
    use std::{
        fmt::Display,
        ops::{Deref, DerefMut},
        str::FromStr,
    };

    use crate::{Error, NetdocErrorKind as EK, NormalItemArgument, Pos};

    /// A boolean that is represented by a `0` (false) or `1` (true).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deftly)]
    #[derive_deftly(Transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct NumericBoolean(pub bool);

    impl FromStr for NumericBoolean {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "0" => Ok(Self(false)),
                "1" => Ok(Self(true)),
                _ => Err(EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("Invalid numeric boolean")),
            }
        }
    }

    impl Display for NumericBoolean {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", u8::from(self.0))
        }
    }

    impl NormalItemArgument for NumericBoolean {}
}

/// Types for router descriptors.
pub mod routerdesc {
    use crate::types::EmbeddedCert;

    use super::*;
    use parse2::ErrorProblem as EP;
    use tor_cert::KeyUnknownCert;
    use tor_llcrypto::pk::ed25519;

    /// Version argument found in an `overload-general` item.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:overload-general>
    #[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, strum::EnumString, strum::Display)]
    #[non_exhaustive]
    pub enum OverloadGeneralVersion {
        /// Version 1, currently the only supported and specified one.
        #[strum(serialize = "1")]
        V1,
    }

    impl NormalItemArgument for OverloadGeneralVersion {}

    /// The overload general type found in router descriptors.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:overload-general>
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[non_exhaustive]
    pub struct OverloadGeneral {
        /// The version of the item.
        pub version: OverloadGeneralVersion,
        /// The timestamp since when the relay is overloaded.
        pub since: Iso8601TimeSp,
    }

    /// Introduction line of a router descriptor.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:router>
    #[derive(Clone, Debug, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[non_exhaustive]
    pub struct RouterDescIntroItem {
        /// A valid router [`Nickname`].
        pub nickname: Nickname,

        /// An IPv4 address in dotted-squad format.
        pub address: std::net::Ipv4Addr,

        /// The TCP port of the onion router.
        pub orport: u16,

        /// Legacy.
        pub socksport: u16,

        /// Legacy.
        pub dirport: u16,
    }

    /// Digest identifying the extra-info document.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:extra-info-digest>
    #[derive(Clone, Debug, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[non_exhaustive]
    pub struct ExtraInfoDigests {
        /// Mandatory SHA-1 of the signed data in base 16.
        pub sha1: FixedB16U<20>,

        /// Optional SHA-256 of the entire extra-info in base 64.
        pub sha2: Option<FixedB64<32>>,
    }

    /// Accumulator for router descriptor hash signatures.
    #[derive(Debug, Clone, Default, Deftly)]
    #[derive_deftly(AsMutSelf)]
    #[allow(clippy::exhaustive_structs)]
    pub struct RouterHashAccu {
        /// Potentially the SHA-1 for the signature.
        pub sha1: Option<[u8; 20]>,
        /// Potentially the SHA-256 for the signature.
        pub sha256: Option<[u8; 32]>,
    }

    /// SHA-256 router descriptor signature including magic and the keyword.
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueEncodable)]
    #[allow(clippy::exhaustive_structs)]
    // TODO SPEC is RouterSigEd25519 not a standard-ish kind of signature?
    // TODO DIRAUTH is RouterSigEd25519 not a standard-ish kind of signature?
    pub struct RouterSigEd25519(pub ed25519::Signature);

    impl RouterSigEd25519 {
        /// The magic prefix for hashing this type of signature.
        const HASH_PREFIX_MAGIC: &str = "Tor router descriptor signature v1";

        /// Calculate the hash for signature
        ///
        /// `signature_item_kw_spc` is the keyword *with a trailing space*.
        /// It's `&[&str]` for the convenience of the two call sites.
        fn hash(document_sofar: &str, signature_item_kw_spc: &[&str]) -> [u8; 32] {
            debug_assert!(
                signature_item_kw_spc
                    .last()
                    .expect("signature_item_kw_spc")
                    .ends_with(" ")
            );
            let mut h = tor_llcrypto::d::Sha256::new();
            h.update(Self::HASH_PREFIX_MAGIC);
            h.update(document_sofar);
            for b in signature_item_kw_spc {
                h.update(b);
            }
            h.finalize().into()
        }

        /// Make a signature during document encoding
        ///
        /// `item_keyword` is the keyword for the signature item.
        ///
        /// # Example
        ///
        /// ```
        /// use derive_deftly::Deftly;
        /// use tor_error::Bug;
        /// use tor_llcrypto::pk::ed25519;
        /// use tor_netdoc::derive_deftly_template_NetdocEncodable;
        /// use tor_netdoc::encode::{NetdocEncodable, NetdocEncoder};
        /// use tor_netdoc::types::routerdesc::RouterSigEd25519;
        ///
        /// #[derive(Deftly, Default)]
        /// #[derive_deftly(NetdocEncodable)]
        /// pub struct Document {
        ///     pub document_intro_keyword: (),
        /// }
        /// #[derive(Deftly)]
        /// #[derive_deftly(NetdocEncodable)]
        /// pub struct DocumentSignatures {
        ///     pub document_signature: RouterSigEd25519,
        /// }
        /// impl Document {
        ///     pub fn encode_sign(&self, k: &ed25519::Keypair) -> Result<String, Bug> {
        ///         let mut encoder = NetdocEncoder::new();
        ///         self.encode_unsigned(&mut encoder)?;
        ///         let document_signature =
        ///             RouterSigEd25519::new_sign_netdoc(k, &encoder, "document-signature")?;
        ///         let sigs = DocumentSignatures { document_signature };
        ///         sigs.encode_unsigned(&mut encoder)?;
        ///         let encoded = encoder.finish()?;
        ///         Ok(encoded)
        ///     }
        /// }
        ///
        /// # fn main() -> Result<(), anyhow::Error> {
        /// let k = ed25519::Keypair::generate(&mut tor_basic_utils::test_rng::testing_rng());
        /// let doc = Document::default();
        /// let encoded = doc.encode_sign(&k)?;
        /// assert!(encoded.starts_with(concat!(
        ///     "document-intro-keyword\n",
        ///     "document-signature ",
        /// )));
        /// # Ok(())
        /// # }
        /// ```
        pub fn new_sign_netdoc(
            private_key: &ed25519::Keypair,
            encoder: &NetdocEncoder,
            item_keyword: &str,
        ) -> StdResult<Self, Bug> {
            let signature = private_key
                .sign(&Self::hash(encoder.text_sofar()?, &[item_keyword, " "]))
                .to_bytes()
                .into();
            Ok(RouterSigEd25519(signature))
        }
    }

    impl SignatureItemParseable for RouterSigEd25519 {
        type HashAccu = RouterHashAccu;

        fn from_unparsed_and_body(
            mut item: UnparsedItem<'_>,
            hash_inputs: &SignatureHashInputs<'_>,
            hash: &mut Self::HashAccu,
        ) -> Result<Self, EP> {
            // TODO DIRMIRROR break this out into impl ItemArgumentParseable for Signature
            let args = item.args_mut();
            let sig = FixedB64::<64>::from_args(args)
                .map_err(|e| args.handle_error("router-sig-ed25519", e))?
                .0;
            let sig = ed25519::Signature::from(sig);
            hash.sha256 = Some(Self::hash(
                hash_inputs.document_sofar,
                &[hash_inputs.signature_item_kw_spc],
            ));
            Ok(Self(sig))
        }
    }

    /// SHA-1 router descriptor signature over `router-sig-ed25519`.
    // TODO DIRMIRROR Is this not the same as RsaSha1Signature ?
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueEncodable)]
    #[allow(clippy::exhaustive_structs)]
    pub struct RouterSignature(
        #[deftly(netdoc(object(label = "SIGNATURE"), with = crate::types::raw_data_object))]
        pub  Vec<u8>,
    );

    impl SignatureItemParseable for RouterSignature {
        type HashAccu = RouterHashAccu;

        fn from_unparsed_and_body(
            mut item: UnparsedItem<'_>,
            hash_inputs: &SignatureHashInputs<'_>,
            hash: &mut Self::HashAccu,
        ) -> Result<Self, EP> {
            // There must be no additonal arguments.
            let args = item.args_mut();
            if args.next().is_some() {
                return Err(EP::UnexpectedArgument {
                    column: args.prev_arg_column(),
                });
            }
            let obj = item.object().ok_or(EP::MissingObject)?.decode_data()?;

            let mut h = tor_llcrypto::d::Sha1::new();
            h.update(hash_inputs.document_sofar);
            h.update(hash_inputs.signature_item_line);
            h.update("\n");
            hash.sha1 = Some(h.finalize().into());

            Ok(Self(obj))
        }
    }

    /// Estimated bandwidth for a router.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:bandwidth>
    // Does not derive Ord because it only makes sense to order on a single
    // field but not all.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deftly)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[non_exhaustive]
    pub struct Bandwidth {
        /// The volume that the relay is willing to sustain over long periods.
        pub average: u64,

        /// The volume that the relay is willing to sustain in very short intervals.
        pub burst: u64,

        /// The estimate of the capacity this relay can handle.
        pub observed: u64,
    }

    /// Ntor onion key cross-certificate.
    ///
    /// This struct contains an [`Ed25519NtorCrossCert`] alongside the `bit`
    /// field required for converting the ntor X25519 key to an Ed25519 key.
    ///
    /// # See Also
    ///
    /// * [`Ed25519NtorCrossCert`]
    /// * <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:ntor-onion-key-crosscert>
    #[derive(Debug, Clone, Deftly, PartialEq)]
    #[derive_deftly(ItemValueParseable, ItemValueEncodable)]
    #[deftly(netdoc(no_extra_args))]
    #[non_exhaustive]
    pub struct NtorOnionKeyCrossCert {
        /// True if X coordinate of the ntor onion key is negative, false if
        /// positive.
        // TODO spec: This name is very unfortunate, how about we change it
        // to `is_negative`.  Also, using a boolean for storing a sign bit feels
        // wrong to me due to the zero edge case, which would not be negative,
        // but also not positive either.
        pub bit: NumericBoolean,

        /// The actual embedded ntor onion key certificate.
        #[deftly(netdoc(object))]
        pub cert: EmbeddedCert<Ed25519NtorCrossCert, KeyUnknownCert>,
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::{
        fmt::Debug,
        time::{Duration, SystemTime},
    };

    use itertools::Itertools;

    use base64ct::Encoding;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cert::{CertType, CertifiedKey, Ed25519Cert, KeyUnknownCert};
    use tor_checkable::{TimeBound, timed::TimeRangeBound};
    use tor_llcrypto::pk::ed25519::{self, Ed25519Identity, Ed25519PublicKey, ExpandedKeypair};

    use super::*;
    use crate::{
        Pos, Result,
        encode::{NetdocEncodable, encode_netdoc_unsigned},
        parse2::{ErrorProblem, ParseInput, VerifyFailed},
        types::{
            EmbeddedCert,
            routerdesc::{NtorOnionKeyCrossCert, RouterDescIntroItem},
        },
    };

    /// Decode s as a multi-line base64 string, ignoring ascii whitespace.
    fn base64_decode_ignore_ws(s: &str) -> std::result::Result<Vec<u8>, base64ct::Error> {
        let mut s = s.to_string();
        s.retain(|c| !c.is_ascii_whitespace());
        base64ct::Base64::decode_vec(s.as_str())
    }

    #[test]
    fn base64() -> Result<()> {
        // Test parsing success:
        // Unpadded:
        assert_eq!("Mi43MTgyOA".parse::<B64>()?.as_bytes(), &b"2.71828"[..]);
        assert!("Mi43MTgyOA".parse::<B64>()?.check_len(7..8).is_ok());
        assert_eq!("Mg".parse::<B64>()?.as_bytes(), &b"2"[..]);
        assert!("Mg".parse::<B64>()?.check_len(1..2).is_ok());
        assert_eq!(
            "8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S"
                .parse::<B64>()?
                .as_bytes(),
            "🍒🍒🍒🍒🍒🍒".as_bytes()
        );
        assert!(
            "8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S"
                .parse::<B64>()?
                .check_len(24..25)
                .is_ok()
        );
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxKkz8="
                .parse::<B64>()?
                .check_len(32..33)
                .is_ok()
        );
        // Padded:
        assert_eq!("Mi43MTgyOA==".parse::<B64>()?.as_bytes(), &b"2.71828"[..]);
        assert!("Mi43MTgyOA==".parse::<B64>()?.check_len(7..8).is_ok());
        assert_eq!("Mg==".parse::<B64>()?.as_bytes(), &b"2"[..]);
        assert!("Mg==".parse::<B64>()?.check_len(1..2).is_ok());

        // Test parsing failures:
        // Invalid character.
        assert!("Mi43!!!!!!".parse::<B64>().is_err());
        // Invalid last character.
        assert!("Mi".parse::<B64>().is_err());
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxaaaa"
                .parse::<B64>()
                .is_err()
        );
        // Invalid length.
        assert!("Mi43MTgyOA".parse::<B64>()?.check_len(8..).is_err());
        Ok(())
    }

    #[test]
    fn base64_lengths() -> Result<()> {
        assert_eq!("".parse::<B64>()?.as_bytes(), b"");
        assert!("=".parse::<B64>().is_err());
        assert!("==".parse::<B64>().is_err());
        assert!("B".parse::<B64>().is_err());
        assert!("B=".parse::<B64>().is_err());
        assert!("B==".parse::<B64>().is_err());
        assert!("Bg=".parse::<B64>().is_err());
        assert_eq!("Bg".parse::<B64>()?.as_bytes(), b"\x06");
        assert_eq!("Bg==".parse::<B64>()?.as_bytes(), b"\x06");
        assert_eq!("BCg".parse::<B64>()?.as_bytes(), b"\x04\x28");
        assert_eq!("BCg=".parse::<B64>()?.as_bytes(), b"\x04\x28");
        assert!("BCg==".parse::<B64>().is_err());
        assert_eq!("BCDE".parse::<B64>()?.as_bytes(), b"\x04\x20\xc4");
        assert!("BCDE=".parse::<B64>().is_err());
        assert!("BCDE==".parse::<B64>().is_err());
        Ok(())
    }

    #[test]
    fn base64_rev() {
        use base64ct::{Base64, Base64Unpadded};

        // Check that strings that we accept are precisely ones which
        // can be generated by either Base64 or Base64Unpadded
        for n in 0..=5 {
            for c_vec in std::iter::repeat_n("ACEQg/=".chars(), n).multi_cartesian_product() {
                let s: String = c_vec.into_iter().collect();
                #[allow(clippy::print_stderr)]
                let b = match s.parse::<B64>() {
                    Ok(b) => {
                        eprintln!("{:10} {:?}", s, b.as_bytes());
                        b
                    }
                    Err(_) => {
                        eprintln!("{:10} Err", s);
                        continue;
                    }
                };
                let b = b.as_bytes();

                let ep = Base64::encode_string(b);
                let eu = Base64Unpadded::encode_string(b);

                assert!(
                    s == ep || s == eu,
                    "{:?} decoded to {:?} giving neither {:?} nor {:?}",
                    s,
                    b,
                    ep,
                    eu
                );
            }
        }
    }

    #[test]
    fn base16() -> anyhow::Result<()> {
        let chk = |s: &str, b: &[u8]| -> anyhow::Result<()> {
            let parsed = s.parse::<B16>()?;
            assert_eq!(parsed.as_bytes(), b, "{s:?}");
            assert_eq!(parsed.to_string(), s.to_ascii_lowercase());

            let parsed = s.parse::<B16U>()?;
            assert_eq!(parsed.as_bytes(), b, "{s:?}");
            assert_eq!(parsed.to_string(), s.to_ascii_uppercase());
            Ok(())
        };

        chk("332e313432", b"3.142")?;
        chk("332E313432", b"3.142")?;
        chk("332E3134", b"3.14")?;

        assert!("332E313".parse::<B16>().is_err());
        assert!("332G3134".parse::<B16>().is_err());
        Ok(())
    }

    #[test]
    fn curve25519() -> Result<()> {
        use tor_llcrypto::pk::curve25519::PublicKey;
        let k1 = "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxKkz8=";
        let k2 = hex::decode("a69c2d8475d6f245c3d1ff5f13b50f62c38002ee2e8f9391c12a2608cc4a933f")
            .unwrap();
        let k2: &[u8; 32] = &k2[..].try_into().unwrap();

        let k1: PublicKey = k1.parse::<Curve25519Public>()?.into();
        assert_eq!(k1, (*k2).into());

        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxKkz"
                .parse::<Curve25519Public>()
                .is_err()
        );
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORSomCMxKkz"
                .parse::<Curve25519Public>()
                .is_err()
        );
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5wSomCMxKkz"
                .parse::<Curve25519Public>()
                .is_err()
        );
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4ORwSomCMxKkz"
                .parse::<Curve25519Public>()
                .is_err()
        );

        Ok(())
    }

    #[test]
    fn ed25519() -> Result<()> {
        use tor_llcrypto::pk::ed25519::Ed25519Identity;
        let k1 = "WVIPQ8oArAqLY4XzkcpIOI6U8KsUJHBQhG8SC57qru0";
        let k2 = hex::decode("59520f43ca00ac0a8b6385f391ca48388e94f0ab14247050846f120b9eeaaeed")
            .unwrap();

        let k1: Ed25519Identity = k1.parse::<Ed25519Public>()?.into();
        assert_eq!(k1, Ed25519Identity::from_bytes(&k2).unwrap());

        assert!(
            "WVIPQ8oArAqLY4Xzk0!!!!8KsUJHBQhG8SC57qru"
                .parse::<Ed25519Public>()
                .is_err()
        );
        assert!(
            "WVIPQ8oArAqLY4XzkcpIU8KsUJHBQhG8SC57qru"
                .parse::<Ed25519Public>()
                .is_err()
        );
        assert!(
            "WVIPQ8oArAqLY4XzkcpIU8KsUJHBQhG8SC57qr"
                .parse::<Ed25519Public>()
                .is_err()
        );
        // right length, bad key:
        assert!(
            "ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxaaaa"
                .parse::<Curve25519Public>()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn time() -> Result<()> {
        use humantime::parse_rfc3339;
        use std::time::SystemTime;

        let t = "2020-09-29 13:36:33".parse::<Iso8601TimeSp>()?;
        let t: SystemTime = t.into();
        assert_eq!(t, parse_rfc3339("2020-09-29T13:36:33Z").unwrap());

        assert!("2020-FF-29 13:36:33".parse::<Iso8601TimeSp>().is_err());
        assert!("2020-09-29Q13:99:33".parse::<Iso8601TimeSp>().is_err());
        assert!("2020-09-29".parse::<Iso8601TimeSp>().is_err());
        assert!("too bad, waluigi time".parse::<Iso8601TimeSp>().is_err());

        assert_eq!(
            "2020-09-29 13:36:33",
            "2020-09-29 13:36:33".parse::<Iso8601TimeSp>()?.to_string()
        );

        let t = "2020-09-29T13:36:33".parse::<Iso8601TimeNoSp>()?;
        let t: SystemTime = t.into();
        assert_eq!(t, parse_rfc3339("2020-09-29T13:36:33Z").unwrap());

        assert!("2020-09-29 13:36:33".parse::<Iso8601TimeNoSp>().is_err());
        assert!("2020-09-29Q13:99:33".parse::<Iso8601TimeNoSp>().is_err());
        assert!("2020-09-29".parse::<Iso8601TimeNoSp>().is_err());
        assert!("too bad, waluigi time".parse::<Iso8601TimeNoSp>().is_err());

        assert_eq!(
            "2020-09-29T13:36:33",
            "2020-09-29T13:36:33"
                .parse::<Iso8601TimeNoSp>()?
                .to_string()
        );

        Ok(())
    }

    #[test]
    fn rsa_public_key() {
        // Taken from a chutney network.
        let key_b64 = r#"
        MIIBigKCAYEAsDkzTcKS4kAF56R2ijb9qCek53tKC1EwMdpWMk58bB28fY6kHc55
        E7n1hB+LC5neZlx88GKuZ9k8P3g0MlO5ejalcfBdIIm28Nz86JXf/L23YnEpxnG/
        IpxZEcmx/EYN+vwp72W3DGuzyntaoaut6lGJk+O/aRCLLcTm4MNznvN1ackK2H6b
        Xm2ejRwtVRLoPKODJiPGl43snCfXXWsMH3IALFOgm0szPLv2fAJzBI8VWrUN81M/
        lgwJhG6+xbr1CkrXI5fKs/TNr0B0ydC9BIZplmPrnXaeNklnw1cqUJ1oxDSgBrvx
        rpDo7paObjSPV26opa68QKGa7Gu2MZQC3RzViNCbawka/108g6hSUkoM+Om2oivr
        DvtMOs10MjsfibEBVnwEhqnlb/gj3hJkYoGRsCwAyMIaMObHcmAevMJRWAjGCc8T
        GMS9dSmg1IZst+U+V2OCcIHXT6wZ1zPsBM0pYKVLCwtewaq1306k0n+ekriEo7eI
        FS3Dd/Dx/a6jAgMBAAE=
        "#;
        let key_bytes = base64_decode_ignore_ws(key_b64).unwrap();
        let rsa = RsaPublicParse1Helper::from_vec(key_bytes, Pos::None).unwrap();

        let bits = tor_llcrypto::pk::rsa::PublicKey::from(rsa.clone()).bits();
        assert_eq!(bits, 3072);

        // tests on a valid key
        assert!(rsa.clone().check_exponent(65537).is_ok());
        assert!(rsa.clone().check_exponent(1337).is_err());
        assert!(rsa.clone().check_len_eq(3072).is_ok());
        assert!(rsa.clone().check_len(1024..=4096).is_ok());
        assert!(rsa.clone().check_len(1024..=1024).is_err());
        assert!(rsa.check_len(4096..).is_err());

        // A string of bytes that is not an RSA key.
        let failure = RsaPublicParse1Helper::from_vec(vec![1, 2, 3], Pos::None);
        assert!(failure.is_err());
    }

    #[test]
    fn ed_cert() {
        use tor_llcrypto::pk::ed25519::Ed25519Identity;

        // From a chutney network.
        let cert_b64 = r#"
        AQQABwRNAR6m3kq5h8i3wwac+Ti293opoOP8RKGP9MT0WD4Bbz7YAQAgBACGCdys
        G7AwsoYMIKenDN6In6ReiGF8jaYoGqmWKDVBdGGMDIZyNIq+VdhgtAB1EyNFHJU1
        jGM0ir9dackL+PIsHbzJH8s/P/8RfUsKIL6/ZHbn3nKMxLH/8kjtxp5ScAA=
        "#;
        let cert_bytes = base64_decode_ignore_ws(cert_b64).unwrap();
        // From the cert above.
        let right_subject_key: Ed25519Identity = "HqbeSrmHyLfDBpz5OLb3eimg4/xEoY/0xPRYPgFvPtg"
            .parse::<Ed25519Public>()
            .unwrap()
            .into();
        // From `ed25519()` test above.
        let wrong_subject_key: Ed25519Identity = "WVIPQ8oArAqLY4XzkcpIOI6U8KsUJHBQhG8SC57qru0"
            .parse::<Ed25519Public>()
            .unwrap()
            .into();

        // decode and check correct type and key
        let cert = UnvalidatedEdCert::from_vec(cert_bytes, Pos::None)
            .unwrap()
            .check_cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)
            .unwrap()
            .check_subject_key_is(&right_subject_key)
            .unwrap();
        // check wrong type.
        assert!(
            cert.clone()
                .check_cert_type(tor_cert::CertType::RSA_ID_X509)
                .is_err()
        );
        // check wrong key.
        assert!(cert.check_subject_key_is(&wrong_subject_key).is_err());

        // Try an invalid object that isn't a certificate.
        let failure = UnvalidatedEdCert::from_vec(vec![1, 2, 3], Pos::None);
        assert!(failure.is_err());
    }

    #[test]
    fn fingerprint() -> Result<()> {
        use tor_llcrypto::pk::rsa::RsaIdentity;
        let fp1 = "7467 A97D 19CD 2B4F 2BC0 388A A99C 5E67 710F 847E";
        let fp2 = "7467A97D19CD2B4F2BC0388AA99C5E67710F847E";
        let fp3 = "$7467A97D19CD2B4F2BC0388AA99C5E67710F847E";
        let fp4 = "$7467A97D19CD2B4F2BC0388AA99C5E67710F847E=fred";

        let k = hex::decode(fp2).unwrap();
        let k = RsaIdentity::from_bytes(&k[..]).unwrap();

        assert_eq!(RsaIdentity::from(fp1.parse::<SpFingerprint>()?), k);
        assert_eq!(RsaIdentity::from(fp2.parse::<SpFingerprint>()?), k);
        assert!(fp3.parse::<SpFingerprint>().is_err());
        assert!(fp4.parse::<SpFingerprint>().is_err());

        assert!(fp1.parse::<Fingerprint>().is_err());
        assert_eq!(RsaIdentity::from(fp2.parse::<Fingerprint>()?), k);
        assert!(fp3.parse::<Fingerprint>().is_err());
        assert!(fp4.parse::<Fingerprint>().is_err());
        assert_eq!(Fingerprint(k).to_string(), fp2);

        assert!(fp1.parse::<LongIdent>().is_err());
        assert_eq!(RsaIdentity::from(fp2.parse::<LongIdent>()?), k);
        assert_eq!(RsaIdentity::from(fp3.parse::<LongIdent>()?), k);
        assert_eq!(RsaIdentity::from(fp4.parse::<LongIdent>()?), k);

        assert!("xxxx".parse::<Fingerprint>().is_err());
        assert!("ffffffffff".parse::<Fingerprint>().is_err());

        let fp_b64 = "dGepfRnNK08rwDiKqZxeZ3EPhH4";
        assert_eq!(RsaIdentity::from(fp_b64.parse::<Base64Fingerprint>()?), k);
        assert_eq!(Base64Fingerprint(k).to_string(), fp_b64);

        Ok(())
    }

    #[test]
    fn nickname() -> anyhow::Result<()> {
        let n: Nickname = "Foo".parse()?;
        assert_eq!(n.as_str(), "Foo");
        assert_eq!(n.to_string(), "Foo");

        let word = "Untr1gonometr1cally";
        assert_eq!(word.len(), 19);
        let long: Nickname = word.parse()?;
        assert_eq!(long.as_str(), word);

        let too_long = "abcdefghijklmnopqrstuvwxyz";
        let not_ascii = "Eyjafjallajökull";
        let too_short = "";
        let other_invalid = "contains space";
        assert!(not_ascii.len() <= 19);
        assert!(too_long.parse::<Nickname>().is_err());
        assert!(not_ascii.parse::<Nickname>().is_err());
        assert!(too_short.parse::<Nickname>().is_err());
        assert!(other_invalid.parse::<Nickname>().is_err());

        Ok(())
    }

    /// Test for both `Hostname` and `InternetHost`
    #[test]
    fn hostname() {
        use std::net::IpAddr;

        // Test a string that we should treat as a valid hostname.
        let chk_name = |s: &str| {
            let n: Hostname = s.parse().expect(s);
            assert_eq!(n.as_str(), s);
            assert_eq!(n.to_string(), s);
            assert_eq!(s.parse::<InternetHost>().expect(s), InternetHost::Name(n));
        };

        // Test a string that looks like it could be an address or a hostname.
        // We parse those as addresses.
        let chk_either = |s: &str| {
            let h: InternetHost = s.parse().expect(s);
            let a: IpAddr = s.parse().expect(s);
            assert_eq!(h, InternetHost::IpAddr(a), "{s:?}");
            assert_eq!(h.to_string(), a.to_string(), "{s:?}");
        };

        // Test a string that's an address, and isn't a valid hostname.
        let chk_addr = |s: &str| {
            let _: InvalidHostname = s.parse::<Hostname>().expect_err(s);
            chk_either(s);
        };

        // Test a string that we should reject.
        let chk_bad = |s: &str| {
            let _: InvalidHostname = s.parse::<Hostname>().expect_err(s);
            let _: InvalidInternetHost = s.parse::<InternetHost>().expect_err(s);
        };

        chk_name("foo.bar");
        chk_name("localhost");
        chk_name("tor.invalid");
        chk_name("example.com");

        // Unarguably invalid.
        chk_bad("");
        chk_bad("foo bar");
        chk_bad("foo..bar");
        chk_bad("foo.-bar");
        chk_bad(" foo.bar ");
        chk_bad("[::1]");

        // Strings that some IP address parsers accept as addresses,
        // but which are also valid hostnames according to RFC1123.
        //
        // We reject them rather than processing of them as hostnames,
        // exposing downstream software to possible strangeness.
        chk_bad("1");
        chk_bad("127.0.0.023");

        // No-one thinks this is a valid IP address but we reject it as a hostname too,
        // even though it's syntactically legal per RFC1123, because it's quite bad.
        chk_bad("1.2.3.4.5");

        chk_either("0.0.0.0");
        chk_either("127.0.0.1");
        chk_addr("::");
        chk_addr("::1");
        chk_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        chk_addr("::ffff:192.0.2.3"); // IPv6-mapped IPv4 address
    }

    #[test]
    fn contact_info() -> anyhow::Result<()> {
        use parse2::{ParseInput, parse_netdoc};

        const S: &str = "some relay operator";
        let n: ContactInfo = S.parse()?;
        assert_eq!(n.as_str(), S);
        assert_eq!(n.to_string(), S);

        let bad = |s: &str| {
            let _: InvalidContactInfo = s.parse::<ContactInfo>().unwrap_err();
        };

        bad(" starts with space");
        bad("contains\nnewline");

        #[derive(PartialEq, Debug, Deftly)]
        #[derive_deftly(NetdocParseable, NetdocEncodable)]
        struct TestDoc {
            pub intro: (),
            pub contact: ContactInfo,
        }

        let roundtrip = |s: &str| -> anyhow::Result<()> {
            let doc = TestDoc {
                intro: (),
                contact: s.parse()?,
            };
            let enc = encode_netdoc_unsigned([&doc])?;
            let reparsed = parse_netdoc::<TestDoc>(&ParseInput::new(&enc, "<test>"))?;
            assert_eq!(doc, reparsed);
            Ok(())
        };

        roundtrip("normal")?;
        roundtrip("trailing  white space  ")?;
        roundtrip("wtf is this allowed in \x03 netdocs\r")?; // TODO torspec#396

        Ok(())
    }

    /// Round trip test for [`NumericBoolean`] ensuring that `0` is false,
    /// `1` is true, and other things fail.
    #[test]
    fn numeric_boolean() {
        let chk = |s: &str| {
            assert_eq!(NumericBoolean::from_str(s).expect(s).to_string(), s);
        };
        chk("0");
        chk("1");
        // Testing this because it is not a u8.
        assert!(NumericBoolean::from_str("10000").is_err());
    }

    #[test]
    fn f64_finite() {
        let normalise_string = |i: &str, o: &str| {
            let v: F64Finite = i.parse().expect(i);
            assert_eq!(v.to_string(), o, "i={i:?}");
        };
        let roundtrip_string = |s: &str| normalise_string(s, s);
        let roundtrip_value = |i: f64| {
            let v: F64Finite = i.try_into().unwrap();
            let s = v.to_string();
            let o: F64Finite = s.parse().expect(&s);
            assert_eq!(v, o, "{i:?} {s}");
            assert_eq!(v.to_bits(), o.to_bits(), "{i:?} {s}");
        };
        let error_string = |s: &str| {
            let _: F64FiniteParseError = s.parse::<F64Finite>().expect_err(s);
        };

        roundtrip_string("0");
        roundtrip_string("0.5");
        roundtrip_string("1");
        roundtrip_string("42");
        roundtrip_string("9007199254740991"); // f64::MAX_EXACT_INTEGER (as per Rust 1.96.0)
        normalise_string("1e3", "1000");

        roundtrip_value(f64::EPSILON);
        roundtrip_value(f64::EPSILON + 1.0);
        roundtrip_value(f64::MIN);
        roundtrip_value(f64::MIN_POSITIVE);
        roundtrip_value(-f64::MIN_POSITIVE);
        roundtrip_value(f64::MAX);

        error_string(&f64::NAN.to_string());
        error_string(&f64::INFINITY.to_string());
        error_string("");
        error_string("garbage");

        // TODO torspec#416 these ought to be more reasonable, but this is what it does now:
        roundtrip_string(
            "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022250738585072014",
        ); // MIN_POSITIVE
        roundtrip_string(
            "179769313486231570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ); // MAX
    }

    /// Test that ensures SpFingerprint matches the 10x4 requirement.
    #[test]
    fn sp_fingerprint() {
        use derive_deftly::Deftly;
        use tor_llcrypto::pk::rsa::RsaIdentity;

        use crate::parse2::ErrorProblem;

        #[derive(Deftly)]
        #[derive_deftly(NetdocParseable, NetdocEncodable)]
        struct Wrapper {
            #[deftly(netdoc(single_arg))]
            fingerprint: SpFingerprint,
        }

        /// Small helper to parse an [`SpFingerprint`].
        ///
        /// In the case the parsing went successful, it also performs a
        /// round-trip encoding test.
        fn parse2(s: &str) -> std::result::Result<SpFingerprint, ErrorProblem> {
            use crate::parse2::{self, ParseInput};

            let input = format!("fingerprint {s}\n");
            let res = parse2::parse_netdoc::<Wrapper>(&ParseInput::new(&input, ""))
                .map_err(|x| x.problem)?;

            // Round-trip encoding; we only do .starts_with() because input
            // may contain trailing parameters which will obviously not be
            // encoded; trimming to remove the trailing "\n" afterwards.
            let mut enc = NetdocEncoder::default();
            res.encode_unsigned(&mut enc).unwrap();
            assert!(input.starts_with(enc.finish().unwrap().trim_end()));

            Ok(res.fingerprint)
        }

        // Test a valid one.
        assert_eq!(
            parse2(&vec!["ABAB"; 10].join(" ")).unwrap(),
            SpFingerprint(RsaIdentity::from_bytes(&[0xAB; 20]).unwrap())
        );

        // Test a valid one with tail.
        assert_eq!(
            parse2(&vec!["ABAB"; 11].join(" ")).unwrap(),
            SpFingerprint(RsaIdentity::from_bytes(&[0xAB; 20]).unwrap())
        );

        // Missing argument
        assert!(matches!(
            parse2(&vec!["ABAB"; 9].join(" ")).unwrap_err(),
            ErrorProblem::MissingArgument { .. }
        ));

        // Invalid argument.
        // In this case, we have string with a total length of 40 but with
        // one pair having 6 characters and another one having 2 as a proof
        // of that.
        assert!(matches!(
            parse2("0000 000000 00 0000 0000 0000 0000 0000 0000 0000").unwrap_err(),
            ErrorProblem::InvalidArgument { .. }
        ));

        // And of course invalid hex should fail too.
        assert!(matches!(
            parse2(&vec!["ZZZZ"; 10].join(" ")).unwrap_err(),
            ErrorProblem::InvalidArgument { .. }
        ));
    }

    /// Verifies the parsing of [`ItemPresent`].
    #[test]
    fn item_present_parse2() {
        #[derive(Default)]
        struct Token;

        #[derive(Deftly)]
        #[derive_deftly(NetdocParseable)]
        struct TestDoc {
            #[allow(unused)]
            intro: Ignored,
            foo: Option<ItemPresent<Token>>,
        }

        // The test cases with their respective result; boolean indicating that
        // it was present.
        let tests = [
            // Test valid present.
            ("intro\nfoo\n", Ok(true)),
            // Test valid absent.
            ("intro\n", Ok(false)),
            // Test repeated.
            ("intro\nfoo\nfoo\n", Err(ErrorProblem::ItemRepeated)),
            // Test repeated with unknown.
            ("intro\nbar\nfoo\nfoo\n", Err(ErrorProblem::ItemRepeated)),
            // Test with argument.
            ("intro\nfoo bar\n", Ok(true)),
            // Test with two arguments.
            ("intro\nfoo bar baz\n", Ok(true)),
            // Test with object.
            (
                "intro\nfoo\n-----BEGIN RSA PUBLIC KEY-----\n-----END RSA PUBLIC KEY-----\n",
                Err(ErrorProblem::ObjectUnexpected),
            ),
        ];

        for (input, expect) in tests {
            println!("{input:?}, {expect:?}");

            // Convert the result by calling .is_present() and extracting EP.
            let got = parse2::parse_netdoc::<TestDoc>(&ParseInput::new(input, ""))
                .map(|x| x.foo.is_some())
                .map_err(|e| e.problem);
            assert_eq!(got, expect);
        }
    }

    #[test]
    fn item_present_encode() {
        #[derive(Default)]
        struct Token;

        #[derive(Deftly)]
        #[derive_deftly(NetdocEncodable)]
        struct TestDoc {
            #[allow(unused)]
            intro: (),
            foo: Option<ItemPresent<Token>>,
        }

        let tests = [
            (Some(ItemPresent(Token)), "intro\nfoo\n"),
            (None, "intro\n"),
        ];

        for (present, output) in tests {
            let re_encoded = encode_netdoc_unsigned([&TestDoc {
                intro: (),
                foo: present,
            }])
            .unwrap();
            assert_eq!(re_encoded, output);
        }
    }

    #[test]
    fn ntor_onion_key_cross_cert() {
        // Dummy helper for parsing a subset of a router desc.
        #[derive(Debug, Deftly)]
        #[derive_deftly(NetdocParseable)]
        #[allow(unused)]
        struct TestDoc {
            /// Intro item.
            router: RouterDescIntroItem,

            /// Timestamp used for `now` in certificate validation.
            #[deftly(netdoc(single_arg))]
            published: Iso8601TimeSp,

            /// Required to ensure certified key of the crosscert.
            #[deftly(netdoc(single_arg))]
            master_key_ed25519: Ed25519Public,

            /// Required to obtain the key signing the crosscert.
            #[deftly(netdoc(single_arg))]
            ntor_onion_key: Curve25519Public,

            /// The actual crosscert.
            ntor_onion_key_crosscert: NtorOnionKeyCrossCert,
        }

        impl TestDoc {
            // Quick verify helper.
            fn verify(&self, now: SystemTime) {
                Ed25519NtorCrossCert::verify(
                    // Converts X25519 to Ed25519.
                    tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public(
                        &self.ntor_onion_key.0,
                        self.ntor_onion_key_crosscert.bit.0.into(),
                    )
                    .unwrap()
                    .into(),
                    self.master_key_ed25519.0,
                    self.ntor_onion_key_crosscert.cert.raw_unverified().clone(),
                )
                .unwrap()
                .check_valid_at(&now)
                .unwrap();
            }
        }

        let descs = include_str!("../../testdata2/cached-descriptors.new");
        let descs = parse2::parse_netdoc_multiple::<TestDoc>(&ParseInput::new(
            descs,
            "cached-descriptors.new",
        ))
        .unwrap();

        // Find the first with negative and first with positive X coordinate.
        let negative_rd = descs
            .iter()
            .find(|rd| rd.ntor_onion_key_crosscert.bit.0)
            .unwrap();
        let positive_rd = descs
            .iter()
            .find(|rd| !rd.ntor_onion_key_crosscert.bit.0)
            .unwrap();

        negative_rd.verify(negative_rd.published.0);
        positive_rd.verify(positive_rd.published.0);
    }

    /// Helper to call methods for edcerts.
    trait Ed25519CertTest: Sized + PartialEq + Eq + Debug {
        /// Creates a new instance.
        ///
        /// Used to create a struct in ad-hoc fashion for Eq comparison.
        fn new(
            signing_key: ed25519::Ed25519Identity,
            certified_key: ed25519::Ed25519Identity,
        ) -> Self;

        /// Returns the expected [`CertType`].
        fn cert_type() -> CertType;

        /// Calls .new_signed().
        ///
        /// This method is used to create an [`EmbeddedCert`] with a given
        /// signing key and a key that shall be certified.
        fn new_signed(
            signing_key: &ed25519::Keypair,
            certified_key: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug>;

        /// Calls .verify().
        ///
        /// The method verifies a certificate given a pre-known certified key,
        /// the actual certificate, and a timestamp.
        fn verify(
            signing_key: Option<ed25519::Ed25519Identity>,
            certified_key: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed>;
    }

    impl Ed25519CertTest for Ed25519IdentityCert {
        fn new(
            signing_key: ed25519::Ed25519Identity,
            certified_key: ed25519::Ed25519Identity,
        ) -> Self {
            Self {
                id_ed25519: signing_key,
                sign_ed25519: certified_key,
            }
        }

        fn cert_type() -> CertType {
            CertType::IDENTITY_V_SIGNING
        }

        fn new_signed(
            signing_key: &ed25519::Keypair,
            certified_key: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            Self::new_signed(signing_key, certified_key, expiry)
        }

        fn verify(
            _signing_key: Option<ed25519::Ed25519Identity>,
            _certified_key: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            Self::verify(cert)
        }
    }

    impl Ed25519CertTest for Ed25519FamilyCert {
        fn new(
            signing_key: ed25519::Ed25519Identity,
            _certified_key: ed25519::Ed25519Identity,
        ) -> Self {
            Self {
                family_ed25519: signing_key,
            }
        }

        fn cert_type() -> CertType {
            CertType::FAMILY_V_IDENTITY
        }

        fn new_signed(
            signing_key: &ed25519::Keypair,
            certified_key: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            Self::new_signed(signing_key, certified_key, expiry)
        }

        fn verify(
            _signing_key: Option<ed25519::Ed25519Identity>,
            certified_key: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            Self::verify(certified_key, cert)
        }
    }

    impl Ed25519CertTest for Ed25519NtorCrossCert {
        fn new(
            _signing_key: ed25519::Ed25519Identity,
            _certified_key: ed25519::Ed25519Identity,
        ) -> Self {
            Self::dangerous_new_unverified()
        }

        fn cert_type() -> CertType {
            CertType::NTOR_CC_IDENTITY
        }

        fn new_signed(
            signing_key: &ed25519::Keypair,
            certified_key: ed25519::Ed25519Identity,
            expiry: SystemTime,
        ) -> StdResult<EmbeddedCert<Self, KeyUnknownCert>, Bug> {
            Self::new_signed(&ExpandedKeypair::from(signing_key), certified_key, expiry)
        }

        fn verify(
            signing_key: Option<ed25519::Ed25519Identity>,
            certified_key: ed25519::Ed25519Identity,
            cert: KeyUnknownCert,
        ) -> StdResult<TimeRangeBound<Self>, VerifyFailed> {
            Self::verify(signing_key.unwrap(), certified_key, cert)
        }
    }

    /// Converts from [`Iso8601TimeSp`] to [`SystemTime`]
    fn str_to_st(s: &str) -> SystemTime {
        Iso8601TimeSp::from_str(s).unwrap().0
    }

    /// Tests a valid ad-hoc generated certificate.
    fn ed25519_cert_rng<T: Ed25519CertTest>() {
        let mut rng = testing_rng();
        let signing_key = ed25519::Keypair::generate(&mut rng);
        let certified_key = ed25519::Keypair::generate(&mut rng);
        let now = str_to_st("2000-01-01 06:00:00");
        let expiry = str_to_st("2000-01-01 12:00:00");

        // Test ad-hoc generation.
        let embedded_cert =
            T::new_signed(&signing_key, certified_key.public_key().into(), expiry).unwrap();
        assert_eq!(
            *embedded_cert.get().unwrap(),
            T::new(
                signing_key.public_key().into(),
                certified_key.public_key().into()
            )
        );

        // Verify ad-hoc certificate generation.
        let unverified = embedded_cert.raw_unverified().clone();
        assert_eq!(T::cert_type(), unverified.peek_cert_type());
        match unverified.peek_subject_key() {
            CertifiedKey::Ed25519(x) => assert_eq!(
                *x,
                ed25519::Ed25519Identity::from(certified_key.public_key())
            ),
            _ => panic!(),
        }

        // Finally, see if .verify() agrees.
        T::verify(
            Some(signing_key.public_key().into()),
            certified_key.public_key().into(),
            unverified.clone(),
        )
        .unwrap()
        .check_valid_at(&now)
        .unwrap();

        // See if .verify() also agrees when expired but with toleration.
        T::verify(
            Some(signing_key.public_key().into()),
            certified_key.public_key().into(),
            unverified,
        )
        .unwrap()
        .extend_end_bound(Duration::from_secs(60 * 60))
        .check_valid_at(&now)
        .unwrap();
    }

    /// Tests invalid Ed25519 certificates by violating various constraints.
    fn ed25519_cert_invalid<T: Ed25519CertTest + 'static>(requires_signed_with_ext: bool) {
        let mut rng = testing_rng();
        let now = str_to_st("2000-01-01 06:00:00");
        let expiry = str_to_st("2000-01-01 12:00:00");
        let signing_key = ed25519::Keypair::generate(&mut rng);
        let signing_pk = ed25519::Ed25519Identity::from(signing_key.public_key());
        let certified_key = ed25519::Keypair::generate(&mut rng);
        let certified_pk = ed25519::Ed25519Identity::from(certified_key.public_key());

        let mut tests: Vec<(_, _, CertifiedKey, _, _)> = vec![
            // Testing a violation of the signature is hard because the encoder
            // refuses to emit such a thing.
            // ---
            // Violate timestamp.
            (
                T::cert_type(),
                // We achieve this by setting expiry to now - 1 day.
                now - Duration::from_secs(64 * 64 * 24),
                certified_pk.into(),
                Some(&signing_pk),
                &signing_key,
            ),
            // Violate cert type.
            (
                // Just picking something completely out of place here.
                CertType::LINK_AUTH_X509,
                expiry,
                certified_pk.into(),
                Some(&signing_pk),
                &signing_key,
            ),
            // Violate certified key type.
            (
                T::cert_type(),
                expiry,
                // Just pass a different CertifiedKey variant here.
                CertifiedKey::RsaSha256Digest(certified_pk.into()),
                Some(&signing_pk),
                &signing_key,
            ),
            // ---
            // Missing test for violating both keys MUST be valid mappings to a
            // [`ed25519::PublicKey`].  I was unable to find a single test
            // vector for this, even in curve25591-dalek. :/
        ];

        // Violate absence of `signed-with-ed25519-key`.
        // This is not a violation in Ed25519NtorCrossCert.
        if requires_signed_with_ext {
            tests.push((
                T::cert_type(),
                expiry,
                certified_pk.into(),
                None,
                &signing_key,
            ));
        }

        for (ctype, expiry, certified_key, signing_key, signing_kp) in tests {
            let mut builder = Ed25519Cert::builder()
                .cert_type(ctype)
                .expiration(expiry)
                .cert_key(certified_key.clone())
                .clone();
            if let Some(signing_key) = signing_key {
                builder = builder.signing_key(*signing_key).clone();
            }
            let cert = Ed25519Cert::decode(&builder.encode_and_sign(signing_kp).unwrap()).unwrap();

            // We purposely always create an Ed25519Identity here from the bytes
            // in order to make it possible to test for invalid certified
            // key types.
            T::verify(
                signing_key.copied(),
                Ed25519Identity::from_bytes(certified_key.as_bytes()).unwrap(),
                cert,
            )
            .and_then(|expired| expired.check_valid_at(&now).map_err(|e| e.into()))
            .unwrap_err();
        }
    }

    #[test]
    fn ed25519_cert_rng_test() {
        ed25519_cert_rng::<Ed25519IdentityCert>();
        ed25519_cert_rng::<Ed25519FamilyCert>();
        ed25519_cert_rng::<Ed25519NtorCrossCert>();
    }

    #[test]
    fn ed25519_cert_invalid_test() {
        ed25519_cert_invalid::<Ed25519IdentityCert>(true);
        ed25519_cert_invalid::<Ed25519FamilyCert>(true);
        ed25519_cert_invalid::<Ed25519NtorCrossCert>(false);
    }
}
