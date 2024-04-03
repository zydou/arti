//! Code to abstract over the notion of relays having one or more identities.
//!
//! Currently (2022), every Tor relay has exactly two identities: A legacy
//! identity that is based on the SHA-1 hash of an RSA-1024 public key, and a
//! modern identity that is an Ed25519 public key.  This code lets us abstract
//! over those types, and over other new types that may exist in the future.

use std::fmt;

use derive_deftly::Deftly;
use derive_more::{Display, From};
use safelog::Redactable;
use tor_llcrypto::pk::{
    ed25519::{Ed25519Identity, ED25519_ID_LEN},
    rsa::{RsaIdentity, RSA_ID_LEN},
};

pub(crate) mod by_id;
pub(crate) mod set;

/// The type of a relay identity.
///
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Display,
    strum::EnumIter,
    strum::EnumCount,
    Deftly,
)]
#[derive_deftly_adhoc]
#[non_exhaustive]
pub enum RelayIdType {
    /// An Ed25519 identity.
    ///
    /// Every relay (currently) has one of these identities. It is the same
    /// as the encoding of the relay's public Ed25519 identity key.
    #[display(fmt = "Ed25519")]
    Ed25519,
    /// An RSA identity.
    ///
    /// Every relay (currently) has one of these identities.  It is computed as
    /// a SHA-1 digest of the DER encoding of the relay's public RSA 1024-bit
    /// identity key.  Because of short key length, this type of identity should
    /// not be considered secure on its own.
    #[display(fmt = "RSA (legacy)")]
    Rsa,
}

impl fmt::Display for RelayId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.as_ref(), f)
    }
}

/// A single relay identity.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, From, Hash)]
#[non_exhaustive]
pub enum RelayId {
    /// An Ed25519 identity.
    Ed25519(Ed25519Identity),
    /// An RSA identity.
    Rsa(RsaIdentity),
}

/// A reference to a single relay identity.
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Display, From, derive_more::TryInto,
)]
#[non_exhaustive]
pub enum RelayIdRef<'a> {
    /// An Ed25519 identity.
    #[display(fmt = "ed25519:{}", _0)]
    Ed25519(&'a Ed25519Identity),
    /// An RSA identity.
    #[display(fmt = "{}", _0)]
    Rsa(&'a RsaIdentity),
}

impl RelayIdType {
    /// The number of distinct types currently implemented.
    pub const COUNT: usize = <RelayIdType as strum::EnumCount>::COUNT;

    /// Return an iterator over all
    pub fn all_types() -> RelayIdTypeIter {
        use strum::IntoEnumIterator;
        Self::iter()
    }

    /// Return the length of this identity, in bytes.
    pub fn id_len(&self) -> usize {
        match self {
            RelayIdType::Ed25519 => ED25519_ID_LEN,
            RelayIdType::Rsa => RSA_ID_LEN,
        }
    }
}

impl RelayId {
    /// Return a [`RelayIdRef`] pointing to the contents of this identity.
    pub fn as_ref(&self) -> RelayIdRef<'_> {
        match self {
            RelayId::Ed25519(key) => key.into(),
            RelayId::Rsa(key) => key.into(),
        }
    }

    /// Try to construct a RelayId of a provided `id_type` from a byte-slice.
    ///
    /// Return [`RelayIdError::BadLength`] if the slice is not the correct length for the key.
    pub fn from_type_and_bytes(id_type: RelayIdType, id: &[u8]) -> Result<Self, RelayIdError> {
        Ok(match id_type {
            RelayIdType::Rsa => RsaIdentity::from_bytes(id)
                .ok_or(RelayIdError::BadLength)?
                .into(),
            RelayIdType::Ed25519 => Ed25519Identity::from_bytes(id)
                .ok_or(RelayIdError::BadLength)?
                .into(),
        })
    }

    /// Return the type of this relay identity.
    pub fn id_type(&self) -> RelayIdType {
        self.as_ref().id_type()
    }

    /// Return a byte-slice corresponding to the contents of this identity.
    ///
    /// The return value discards the type of the identity, and so should be
    /// handled with care to make sure that it does not get confused with an
    /// identity of some other type.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}

impl<'a> RelayIdRef<'a> {
    /// Copy this reference into a new [`RelayId`] object.
    //
    // TODO(nickm): I wish I could make this a proper `ToOwned` implementation,
    // but I see no way to do as long as RelayIdRef<'a> implements Clone too.
    pub fn to_owned(&self) -> RelayId {
        match *self {
            RelayIdRef::Ed25519(key) => (*key).into(),
            RelayIdRef::Rsa(key) => (*key).into(),
        }
    }

    /// Return the type of this relay identity.
    pub fn id_type(&self) -> RelayIdType {
        match self {
            RelayIdRef::Ed25519(_) => RelayIdType::Ed25519,
            RelayIdRef::Rsa(_) => RelayIdType::Rsa,
        }
    }

    /// Return a byte-slice corresponding to the contents of this identity.
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            RelayIdRef::Ed25519(key) => key.as_bytes(),
            RelayIdRef::Rsa(key) => key.as_bytes(),
        }
    }

    /// Extract the RsaIdentity from a RelayIdRef that is known to hold one.
    ///
    /// # Panics
    ///
    /// Panics if this is not an RSA identity.
    pub(crate) fn unwrap_rsa(self) -> &'a RsaIdentity {
        match self {
            RelayIdRef::Rsa(rsa) => rsa,
            _ => panic!("Not an RSA identity."),
        }
    }

    /// Extract the Ed25519Identity from a RelayIdRef that is known to hold one.
    ///
    /// # Panics
    ///
    /// Panics if this is not an Ed25519 identity.
    pub(crate) fn unwrap_ed25519(self) -> &'a Ed25519Identity {
        match self {
            RelayIdRef::Ed25519(ed25519) => ed25519,
            _ => panic!("Not an Ed25519 identity."),
        }
    }
}

impl<'a> From<&'a RelayId> for RelayIdRef<'a> {
    fn from(ident: &'a RelayId) -> Self {
        ident.as_ref()
    }
}

impl Redactable for RelayId {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().display_redacted(f)
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().debug_redacted(f)
    }
}

impl<'a> Redactable for RelayIdRef<'a> {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayIdRef::Ed25519(k) => write!(f, "ed25519:{}", k.redacted()),
            RelayIdRef::Rsa(k) => write!(f, "${}", k.redacted()),
        }
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Debug as _;
        match self {
            RelayIdRef::Ed25519(k) => k.redacted().fmt(f),
            RelayIdRef::Rsa(k) => k.redacted().fmt(f),
        }
    }
}

/// Expand to an implementation for PartialEq for a given key type.
macro_rules! impl_eq_variant {
    { $var:ident($type:ty) } => {
        impl<'a> PartialEq<$type> for RelayIdRef<'a> {
            fn eq(&self, other: &$type) -> bool {
                matches!(self, RelayIdRef::$var(this) if this == &other)
            }
        }
        impl PartialEq<$type> for RelayId {
            fn eq(&self, other: &$type) -> bool {
                matches!(&self, RelayId::$var(this) if this == other)
            }
        }
    }
}

impl_eq_variant! { Rsa(RsaIdentity) }
impl_eq_variant! { Ed25519(Ed25519Identity) }

impl std::str::FromStr for RelayIdType {
    type Err = RelayIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("rsa") {
            Ok(RelayIdType::Rsa)
        } else if s.eq_ignore_ascii_case("ed25519") {
            Ok(RelayIdType::Ed25519)
        } else {
            Err(RelayIdError::UnrecognizedIdType)
        }
    }
}

impl std::str::FromStr for RelayId {
    type Err = RelayIdError;

    /// Try to parse `s` as a RelayId.
    ///
    /// We use the following format, based on the one used by C tor.
    ///
    /// * An optional `$` followed by a 40 byte hex string is always an RSA key.
    /// * A 43 character un-padded base-64 string is always an Ed25519 key.
    /// * The name of an algorithm ("rsa" or "ed25519"), followed by a colon and
    ///   and an un-padded base-64 string is a key of that type.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use base64ct::{Base64Unpadded, Encoding as _};
        if let Some((alg, key)) = s.split_once(':') {
            let alg: RelayIdType = alg.parse()?;
            let len = alg.id_len();
            let mut v = vec![0_u8; len];
            let bytes = Base64Unpadded::decode(key, &mut v[..])?;
            RelayId::from_type_and_bytes(alg, bytes)
        } else if s.len() == RSA_ID_LEN * 2 || s.starts_with('$') {
            let s = s.trim_start_matches('$');
            let bytes = hex::decode(s).map_err(|_| RelayIdError::BadHex)?;
            RelayId::from_type_and_bytes(RelayIdType::Rsa, &bytes)
        } else {
            let mut v = [0_u8; ED25519_ID_LEN];
            let bytes = Base64Unpadded::decode(s, &mut v[..])?;
            RelayId::from_type_and_bytes(RelayIdType::Ed25519, bytes)
        }
    }
}

impl serde::Serialize for RelayId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}
impl<'a> serde::Serialize for RelayIdRef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO(nickm): maybe encode this as bytes when dealing with
        // non-human-readable formats.
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RelayId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO(nickm): maybe allow bytes when dealing with non-human-readable
        // formats.
        use serde::de::Error as _;
        let s = <std::borrow::Cow<'_, str> as serde::Deserialize>::deserialize(deserializer)?;
        s.parse()
            .map_err(|e: RelayIdError| D::Error::custom(e.to_string()))
    }
}

/// An error returned while trying to parse a RelayId.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayIdError {
    /// We didn't recognize the type of a relay identity.
    ///
    /// This can happen when a type that we have never heard of is specified, or when a type
    #[error("Unrecognized type for relay identity")]
    UnrecognizedIdType,
    /// We encountered base64 data that we couldn't parse.
    #[error("Invalid base64 data")]
    BadBase64,
    /// We encountered hex data that we couldn't parse.
    #[error("Invalid hexadecimal data")]
    BadHex,
    /// We got a key that was the wrong length.
    #[error("Invalid length for relay identity")]
    BadLength,
}

impl From<base64ct::Error> for RelayIdError {
    fn from(err: base64ct::Error) -> Self {
        match err {
            base64ct::Error::InvalidEncoding => RelayIdError::BadBase64,
            base64ct::Error::InvalidLength => RelayIdError::BadLength,
        }
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
    use hex_literal::hex;
    use serde_test::{assert_tokens, Token};
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parse_and_display() -> Result<(), RelayIdError> {
        fn normalizes_to(s: &str, expected: &str) -> Result<(), RelayIdError> {
            let k: RelayId = s.parse()?;
            let s2 = k.to_string();
            assert_eq!(s2, expected);
            let k2: RelayId = s2.parse()?;
            let s3 = k2.to_string();
            assert_eq!(s3, s2);
            let s4 = k2.as_ref().to_string();
            assert_eq!(s4, s3);
            Ok(())
        }
        fn check(s: &str) -> Result<(), RelayIdError> {
            normalizes_to(s, s)
        }

        // Try a few RSA identities.
        check("$1234567812345678123456781234567812345678")?;
        normalizes_to(
            "abcdefabcdefabcdefabcdefabcdef1234567890",
            "$abcdefabcdefabcdefabcdefabcdef1234567890",
        )?;
        normalizes_to(
            "abcdefabcdefABCDEFabcdefabcdef1234567890",
            "$abcdefabcdefabcdefabcdefabcdef1234567890",
        )?;
        normalizes_to(
            "rsa:q83vq83vq83vq83vq83vEjRWeJA",
            "$abcdefabcdefabcdefabcdefabcdef1234567890",
        )?;

        // Try a few ed25519 identities
        check("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")?;
        normalizes_to(
            "dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
        )?;

        Ok(())
    }

    #[test]
    fn parse_fail() {
        use std::str::FromStr;
        let e = RelayId::from_str("tooshort").unwrap_err();
        assert!(matches!(e, RelayIdError::BadLength));

        let e = RelayId::from_str("this_string_is_40_bytes_but_it_isnt_hex!").unwrap_err();
        assert!(matches!(e, RelayIdError::BadHex));

        let e = RelayId::from_str("merkle-hellman:bestavoided").unwrap_err();
        assert!(matches!(e, RelayIdError::UnrecognizedIdType));

        let e = RelayId::from_str("ed25519:q83vq83vq83vq83vq83vEjRWeJA").unwrap_err();
        assert!(matches!(e, RelayIdError::BadLength));

        let e = RelayId::from_str("ed25519:🤨🤨🤨🤨🤨").unwrap_err();
        assert!(matches!(e, RelayIdError::BadBase64));
    }

    #[test]
    fn types() {
        assert_eq!(
            RelayId::from_str("$1234567812345678123456781234567812345678")
                .unwrap()
                .id_type(),
            RelayIdType::Rsa,
        );
        assert_eq!(
            RelayId::from_str("$1234567812345678123456781234567812345678")
                .unwrap()
                .as_ref()
                .id_type(),
            RelayIdType::Rsa,
        );

        assert_eq!(
            RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")
                .unwrap()
                .id_type(),
            RelayIdType::Ed25519,
        );

        assert_eq!(
            RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")
                .unwrap()
                .as_ref()
                .id_type(),
            RelayIdType::Ed25519,
        );
    }

    #[test]
    fn equals_other() {
        let rsa1 = RsaIdentity::from(*b"You just have to kno");
        let rsa2 = RsaIdentity::from(*b"w who you are and st");
        let ed1 = Ed25519Identity::from(*b"ay true to that. So I'm going to");
        let ed2 = Ed25519Identity::from(*b"keep fighting for people the onl");

        assert_eq!(RelayId::from(rsa1), rsa1);
        assert_ne!(RelayId::from(rsa1), rsa2);
        assert_ne!(RelayId::from(rsa1), ed1);

        assert_eq!(RelayId::from(ed1), ed1);
        assert_ne!(RelayId::from(ed1), ed2);
        assert_ne!(RelayId::from(ed1), rsa1);

        assert_eq!(RelayIdRef::from(&rsa1), rsa1);
        assert_ne!(RelayIdRef::from(&rsa1), rsa2);
        assert_ne!(RelayIdRef::from(&rsa1), ed1);

        assert_eq!(RelayIdRef::from(&ed1), ed1);
        assert_ne!(RelayIdRef::from(&ed1), ed2);
        assert_ne!(RelayIdRef::from(&ed1), rsa1);
    }
    #[test]
    fn as_bytes() {
        assert_eq!(
            RelayId::from_str("$1234567812345678123456781234567812345678")
                .unwrap()
                .as_bytes(),
            hex!("1234567812345678123456781234567812345678"),
        );
        assert_eq!(
            RelayId::from_str("$1234567812345678123456781234567812345678")
                .unwrap()
                .as_ref()
                .as_bytes(),
            hex!("1234567812345678123456781234567812345678"),
        );

        assert_eq!(
            RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")
                .unwrap()
                .as_bytes(),
            b"this is incredibly silly!!!!!!!!"
        );
        assert_eq!(
            RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")
                .unwrap()
                .as_ref()
                .as_bytes(),
            b"this is incredibly silly!!!!!!!!"
        );
    }

    #[test]
    fn unwrap_ok() {
        let rsa = RelayId::from_str("$1234567812345678123456781234567812345678").unwrap();
        assert_eq!(
            rsa.as_ref().unwrap_rsa(),
            &RsaIdentity::from_bytes(&hex!("1234567812345678123456781234567812345678")).unwrap()
        );

        let ed = RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE").unwrap();
        assert_eq!(
            ed.as_ref().unwrap_ed25519(),
            &Ed25519Identity::from_bytes(b"this is incredibly silly!!!!!!!!").unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn unwrap_rsa_panic() {
        if let Ok(ed) = RelayId::from_str("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE") {
            let _nope = RelayIdRef::from(&ed).unwrap_rsa();
        }
    }

    #[test]
    #[should_panic]
    fn unwrap_ed_panic() {
        if let Ok(ed) = RelayId::from_str("$1234567812345678123456781234567812345678") {
            let _nope = RelayIdRef::from(&ed).unwrap_ed25519();
        }
    }

    #[test]
    fn serde_owned() {
        let rsa1 = RsaIdentity::from(*b"You just have to kno");
        let ed1 = Ed25519Identity::from(*b"ay true to that. So I'm going to");
        let keys = vec![RelayId::from(rsa1), RelayId::from(ed1)];

        assert_tokens(
            &keys,
            &[
                Token::Seq { len: Some(2) },
                Token::String("$596f75206a757374206861766520746f206b6e6f"),
                Token::String("ed25519:YXkgdHJ1ZSB0byB0aGF0LiBTbyBJJ20gZ29pbmcgdG8"),
                Token::SeqEnd,
            ],
        );
    }
}
