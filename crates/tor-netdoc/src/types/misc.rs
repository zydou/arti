//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub(crate) use b16impl::*;
pub use b64impl::*;
pub(crate) use curve25519impl::*;
pub(crate) use ed25519impl::*;
#[cfg(any(feature = "routerdesc", feature = "hs-common"))]
pub(crate) use edcert::*;
pub(crate) use fingerprint::*;
pub(crate) use rsa::*;
pub use timeimpl::*;

#[cfg(feature = "encode")]
use {
    crate::encode::{
        self,
        ItemEncoder,
        ItemObjectEncodable,
        ItemValueEncodable,
        // `E` for "encode`; different from `parse2::MultiplicitySelector`
        MultiplicitySelector as EMultiplicitySelector,
    },
    std::iter,
};
#[cfg(feature = "parse2")]
use {
    crate::parse2::multiplicity::{
        ItemSetMethods,
        // `P2` for "parse2`; different from `encode::MultiplicitySelector`
        MultiplicitySelector as P2MultiplicitySelector,
        ObjectSetMethods,
    },
    crate::parse2::{ArgumentError, ArgumentStream, ItemArgumentParseable, ItemObjectParseable}, //
};

pub use nickname::Nickname;

pub use fingerprint::{Base64Fingerprint, Fingerprint};

pub use identified_digest::{DigestName, IdentifiedDigest};

pub use ignored_impl::{Ignored, IgnoredItemOrObjectValue, NotPresent};

use crate::NormalItemArgument;
use derive_deftly::{Deftly, define_derive_deftly};
use std::cmp::{self, PartialOrd};
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::str::FromStr;
use tor_error::{Bug, ErrorReport as _, internal};
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

/// Types for decoding base64-encoded values.
mod b64impl {
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use base64ct::{Base64, Base64Unpadded, Encoding};
    use std::fmt::{self, Display};
    use std::ops::RangeBounds;
    use subtle::{Choice, ConstantTimeEq};

    /// A byte array, encoded in base64 with optional padding.
    ///
    /// On output (`Display`), output is unpadded.
    #[derive(Clone)]
    #[allow(clippy::derived_hash_with_manual_eq)]
    #[derive(Hash, derive_more::Debug, derive_more::From, derive_more::Into)]
    #[debug(r#"B64("{self}")"#)]
    pub struct B64(Vec<u8>);

    impl ConstantTimeEq for B64 {
        fn ct_eq(&self, other: &B64) -> Choice {
            self.0.ct_eq(&other.0)
        }
    }
    /// `B64` is `Eq` via its constant-time implementation.
    impl PartialEq for B64 {
        fn eq(&self, other: &B64) -> bool {
            self.ct_eq(other).into()
        }
    }
    impl Eq for B64 {}

    impl std::str::FromStr for B64 {
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
        /// Return the byte array from this object.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0[..]
        }
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
        pub fn into_array<const N: usize>(self) -> Result<[u8; N]> {
            self.0
                .try_into()
                .map_err(|_| EK::BadObjectVal.with_msg("Invalid length on base64 data"))
        }
    }
}

// ============================================================

/// Types for decoding hex-encoded values.
mod b16impl {
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};

    /// A byte array encoded in hexadecimal.
    pub(crate) struct B16(Vec<u8>);

    impl std::str::FromStr for B16 {
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

    impl B16 {
        /// Return the underlying byte array.
        #[allow(unused)]
        pub(crate) fn as_bytes(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl From<B16> for Vec<u8> {
        fn from(w: B16) -> Vec<u8> {
            w.0
        }
    }
}

// ============================================================

/// Types for decoding curve25519 keys
mod curve25519impl {
    use super::B64;
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use tor_llcrypto::pk::curve25519::PublicKey;

    /// A Curve25519 public key, encoded in base64 with optional padding
    pub(crate) struct Curve25519Public(PublicKey);

    impl std::str::FromStr for Curve25519Public {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let b64: B64 = s.parse()?;
            let array: [u8; 32] = b64.as_bytes().try_into().map_err(|_| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("bad length for curve25519 key.")
            })?;
            Ok(Curve25519Public(array.into()))
        }
    }

    impl From<Curve25519Public> for PublicKey {
        fn from(w: Curve25519Public) -> PublicKey {
            w.0
        }
    }
}

// ============================================================

/// Types for decoding ed25519 keys
mod ed25519impl {
    use super::B64;
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;

    /// An alleged ed25519 public key, encoded in base64 with optional
    /// padding.
    pub(crate) struct Ed25519Public(Ed25519Identity);

    impl std::str::FromStr for Ed25519Public {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self> {
            let b64: B64 = s.parse()?;
            if b64.as_bytes().len() != 32 {
                return Err(EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("bad length for ed25519 key."));
            }
            let key = Ed25519Identity::from_bytes(b64.as_bytes()).ok_or_else(|| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("bad value for ed25519 key.")
            })?;
            Ok(Ed25519Public(key))
        }
    }

    impl From<Ed25519Public> for Ed25519Identity {
        fn from(pk: Ed25519Public) -> Ed25519Identity {
            pk.0
        }
    }
}

// ============================================================

/// Dummy types like [`Ignored`]
mod ignored_impl {
    use super::*;

    #[cfg(feature = "parse2")]
    use crate::parse2::ErrorProblem as EP;

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
    /// There are bespoke impls of the multiplicity traits
    /// `ItemSetMethods` and `ObjectSetMethods`:
    /// don't wrap this type in `Option` or `Vec`.
    //
    // TODO we'll need to implement ItemArgument etc., for encoding, too.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
    #[allow(clippy::exhaustive_structs)]
    #[cfg_attr(
        feature = "parse2",
        derive(Deftly),
        derive_deftly(NetdocParseableFields)
    )]
    pub struct NotPresent;

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
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
    #[cfg_attr(
        feature = "parse2",
        derive(Deftly),
        derive_deftly(ItemValueParseable, NetdocParseableFields)
    )]
    #[allow(clippy::exhaustive_structs)]
    pub struct Ignored;

    /// An Item or Object that would be ignored during parsing and is omitted during encoding
    ///
    /// This is the "single" item type for encoding multiplicity for Items or Objects,
    /// for [`Ignored`].
    ///
    /// This type is uninhabited.
    pub struct IgnoredItemOrObjectValue(Void);

    #[cfg(feature = "parse2")]
    impl ItemSetMethods for P2MultiplicitySelector<NotPresent> {
        type Each = Ignored;
        type Field = NotPresent;
        fn can_accumulate(self, _acc: &Option<NotPresent>) -> Result<(), EP> {
            Ok(())
        }
        fn accumulate(self, _acc: &mut Option<NotPresent>, _item: Ignored) -> Result<(), EP> {
            Ok(())
        }
        fn finish(self, _acc: Option<NotPresent>, _: &'static str) -> Result<NotPresent, EP> {
            Ok(NotPresent)
        }
    }

    #[cfg(feature = "parse2")]
    impl ItemArgumentParseable for NotPresent {
        fn from_args(_: &mut ArgumentStream) -> Result<NotPresent, ArgumentError> {
            Ok(NotPresent)
        }
    }

    #[cfg(feature = "parse2")]
    impl ObjectSetMethods for P2MultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = Void;
        fn resolve_option(self, _found: Option<Void>) -> Result<NotPresent, EP> {
            Ok(NotPresent)
        }
    }

    #[cfg(feature = "encode")]
    impl<'f> encode::MultiplicityMethods<'f> for EMultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = Void;
        fn iter_ordered(self, _: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
            iter::empty()
        }
    }

    #[cfg(feature = "encode")]
    impl encode::OptionalityMethods for EMultiplicitySelector<NotPresent> {
        type Field = NotPresent;
        type Each = Void;
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

    #[cfg(feature = "parse2")]
    impl ItemArgumentParseable for Ignored {
        fn from_args(_: &mut ArgumentStream) -> Result<Ignored, ArgumentError> {
            Ok(Ignored)
        }
    }

    #[cfg(feature = "parse2")]
    impl ItemObjectParseable for Ignored {
        fn check_label(_label: &str) -> Result<(), EP> {
            // allow any label
            Ok(())
        }
        fn from_bytes(_input: &[u8]) -> Result<Self, EP> {
            Ok(Ignored)
        }
    }

    #[cfg(feature = "parse2")]
    impl ObjectSetMethods for P2MultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = Ignored;
        fn resolve_option(self, _found: Option<Ignored>) -> Result<Ignored, EP> {
            Ok(Ignored)
        }
    }

    #[cfg(feature = "encode")]
    impl<'f> encode::MultiplicityMethods<'f> for EMultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = IgnoredItemOrObjectValue;
        fn iter_ordered(self, _: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
            iter::empty()
        }
    }

    #[cfg(feature = "encode")]
    impl encode::OptionalityMethods for EMultiplicitySelector<Ignored> {
        type Field = Ignored;
        type Each = IgnoredItemOrObjectValue;
        fn as_option<'f>(self, _: &'f Self::Field) -> Option<&'f Self::Each> {
            None
        }
    }

    #[cfg(feature = "encode")]
    impl ItemValueEncodable for IgnoredItemOrObjectValue {
        fn write_item_value_onto(&self, _: ItemEncoder) -> Result<(), Bug> {
            void::unreachable(self.0)
        }
    }

    #[cfg(feature = "encode")]
    impl ItemObjectEncodable for IgnoredItemOrObjectValue {
        fn label(&self) -> &str {
            void::unreachable(self.0)
        }
        fn write_object_onto(&self, _: &mut Vec<u8>) -> Result<(), Bug> {
            void::unreachable(self.0)
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
/// to a `Retained`.  That would be a a logic error.  `partial_cmp` gives `None` for this.
#[derive(Debug, PartialEq, Clone, Copy, Hash)]
#[non_exhaustive]
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
    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Unknown::Discarded(_) => None,
            #[cfg(feature = "retain-unknown")]
            Unknown::Retained(t) => Some(t),
        }
    }

    /// Obtain the `Retained` data
    ///
    /// Treats lack of retention as an internal error.
    #[cfg(feature = "retain-unknown")]
    pub fn into_retained(self) -> Result<T, Bug> {
        match self {
            Unknown::Discarded(_) => Err(internal!("Unknown::retained but data not collected")),
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

/// Types for decoding times and dates
mod timeimpl {
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
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)] //
    #[derive(derive_more::Into, derive_more::From, derive_more::Deref)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Iso8601TimeSp(pub SystemTime);

    /// Formatting object for parsing the space-separated Iso8601 format.
    const ISO_8601SP_FMT: &[FormatItem] =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

    impl std::str::FromStr for Iso8601TimeSp {
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
    /// Also converts any time::error::format to std::fmt::Error
    /// so that it can be unwrapped in the Display trait impl
    fn fmt_with(
        t: SystemTime,
        format_desc: &[FormatItem],
    ) -> core::result::Result<String, std::fmt::Error> {
        OffsetDateTime::from(t)
            .format(format_desc)
            .map_err(|_| std::fmt::Error)
    }

    impl std::fmt::Display for Iso8601TimeSp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)] //
    #[derive(derive_more::Into, derive_more::From, derive_more::Deref)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Iso8601TimeNoSp(pub SystemTime);

    /// Formatting object for parsing the space-separated Iso8601 format.
    const ISO_8601NOSP_FMT: &[FormatItem] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

    impl std::str::FromStr for Iso8601TimeNoSp {
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

    impl std::fmt::Display for Iso8601TimeNoSp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", fmt_with(self.0, ISO_8601NOSP_FMT)?)
        }
    }

    impl crate::NormalItemArgument for Iso8601TimeNoSp {}
}

/// Types for decoding RSA keys
mod rsa {
    use crate::{NetdocErrorKind as EK, Pos, Result};
    use std::ops::RangeBounds;
    use tor_llcrypto::pk::rsa::PublicKey;

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
}

/// Types for decoding Ed25519 certificates
#[cfg(any(feature = "routerdesc", feature = "hs-common"))]
mod edcert {
    use crate::{NetdocErrorKind as EK, Pos, Result};
    use tor_cert::{CertType, Ed25519Cert, KeyUnknownCert};
    #[cfg(feature = "routerdesc")]
    use tor_llcrypto::pk::ed25519;

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
        #[cfg(feature = "routerdesc")]
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
}

/// Digest identifeirs, and digests in the form `ALGORITHM=BASE64U`
///
/// As found in a vote's `m` line.
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
        impl Display for $ttype {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let s: &str = match self {
                    $(
                        ${when v_is_unit}
                        $vtype => $STRING_REPR,
                    )
                    $(
                        ${when not(v_is_unit)}
                        $vpat => f_0,
                    )
                };
                Display::fmt(s, f)
            }
        }
    }

    /// The name of a digest algorithm.
    ///
    /// Can represent an unrecognised algorithm, so it's parsed and reproduced.
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
    #[derive_deftly(StringReprUnitsOrUnknown)]
    #[non_exhaustive]
    pub enum DigestName {
        /// SHA-256
        Sha256,
        /// Unknown
        Unknown(String),
    }

    /// A single digest made with a nominated digest algorithm, `ALGORITHM=DIGEST`
    #[derive(Debug, Clone, Eq, PartialEq, Hash, derive_more::Display)]
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
    #[error("invalid syntax, espected ALGORITHM=DIGEST: {0}")]
    pub struct IdentifiedDigestParseError(String);

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
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use base64ct::{Base64Unpadded, Encoding as _};
    use std::fmt::{self, Display};
    use tor_llcrypto::pk::rsa::RsaIdentity;

    /// A hex-encoded RSA key identity (fingerprint) with spaces in it.
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Eq, PartialEq, derive_more::Deref, derive_more::Into)]
    #[allow(clippy::exhaustive_structs)]
    pub(crate) struct SpFingerprint(pub RsaIdentity);

    /// A hex-encoded fingerprint with no spaces.
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Eq, PartialEq, derive_more::Deref, derive_more::Into)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Fingerprint(pub RsaIdentity);

    /// A base64-encoded fingerprint (unpadded)
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Eq, PartialEq, derive_more::Deref, derive_more::Into)]
    #[allow(clippy::exhaustive_structs)]
    pub struct Base64Fingerprint(pub RsaIdentity);

    /// A "long identity" in the format used for Family members.
    ///
    /// Netdoc parsing adapter for [`RsaIdentity`]
    #[derive(Debug, Clone, Eq, PartialEq, derive_more::Deref, derive_more::Into)]
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

    impl std::str::FromStr for SpFingerprint {
        type Err = Error;
        fn from_str(s: &str) -> Result<SpFingerprint> {
            let ident = parse_hex_ident(&s.replace(' ', "")).map_err(|e| e.at_pos(Pos::at(s)))?;
            Ok(SpFingerprint(ident))
        }
    }

    impl std::str::FromStr for Base64Fingerprint {
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

    impl std::str::FromStr for Fingerprint {
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

    impl std::str::FromStr for LongIdent {
        type Err = Error;
        fn from_str(mut s: &str) -> Result<LongIdent> {
            if s.starts_with('$') {
                s = &s[1..];
            }
            if let Some(idx) = s.find(['=', '~']) {
                s = &s[..idx];
            }
            let ident = parse_hex_ident(s)?;
            Ok(LongIdent(ident))
        }
    }

    impl crate::NormalItemArgument for Fingerprint {}
    impl crate::NormalItemArgument for Base64Fingerprint {}
}

/// A type for relay nicknames
mod nickname {
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
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
    #[derive(Clone, Debug)]
    pub struct Nickname(tinystr::TinyAsciiStr<MAX_NICKNAME_LEN>);

    impl Nickname {
        /// Return a view of this nickname as a string slice.
        pub(crate) fn as_str(&self) -> &str {
            self.0.as_str()
        }
    }

    impl std::fmt::Display for Nickname {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.as_str().fmt(f)
        }
    }

    impl std::str::FromStr for Nickname {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self> {
            let tiny = TinyAsciiStr::from_str(s).map_err(|_| {
                EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("Invalid nickname")
            })?;

            if tiny.is_ascii_alphanumeric() && !tiny.is_empty() {
                Ok(Nickname(tiny))
            } else {
                Err(EK::BadArgument
                    .at_pos(Pos::at(s))
                    .with_msg("Invalid nickname"))
            }
        }
    }

    impl crate::NormalItemArgument for Nickname {}
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use itertools::Itertools;

    use base64ct::Encoding;

    use super::*;
    use crate::{Pos, Result};

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
                        eprintln!("{:10} {:?}", &s, b.as_bytes());
                        b
                    }
                    Err(_) => {
                        eprintln!("{:10} Err", &s);
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
    fn base16() -> Result<()> {
        assert_eq!("332e313432".parse::<B16>()?.as_bytes(), &b"3.142"[..]);
        assert_eq!("332E313432".parse::<B16>()?.as_bytes(), &b"3.142"[..]);
        assert_eq!("332E3134".parse::<B16>()?.as_bytes(), &b"3.14"[..]);
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

    #[cfg(feature = "routerdesc")]
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
    fn nickname() -> Result<()> {
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
}
