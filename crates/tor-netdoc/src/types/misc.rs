//! Types used to parse arguments of entries in a directory document.
//!
//! There are some types that are pretty common, like "ISOTime",
//! "base64-encoded data", and so on.
//!
//! These types shouldn't be exposed outside of the netdoc crate.

pub(crate) use b16impl::*;
pub(crate) use b64impl::*;
pub(crate) use curve25519impl::*;
pub(crate) use ed25519impl::*;
#[cfg(any(feature = "routerdesc", feature = "hs-common"))]
pub(crate) use edcert::*;
pub(crate) use fingerprint::*;
pub(crate) use rsa::*;
pub(crate) use timeimpl::*;

#[cfg(feature = "dangerous-expose-struct-fields")]
pub use nickname::Nickname;
#[cfg(not(feature = "dangerous-expose-struct-fields"))]
pub(crate) use nickname::Nickname;

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
    use std::ops::RangeBounds;

    /// A byte array, encoded in base64 with optional padding.
    pub(crate) struct B64(Vec<u8>);

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

    impl B64 {
        /// Return the byte array from this object.
        pub(crate) fn as_bytes(&self) -> &[u8] {
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
        pub(crate) fn into_array<const N: usize>(self) -> Result<[u8; N]> {
            self.0
                .try_into()
                .map_err(|_| EK::BadObjectVal.with_msg("Invalid length on base64 data"))
        }
    }

    impl From<B64> for Vec<u8> {
        fn from(w: B64) -> Vec<u8> {
            w.0
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

/// Types for decoding times and dates
mod timeimpl {
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use std::time::SystemTime;
    use time::{
        format_description::FormatItem, macros::format_description, OffsetDateTime,
        PrimitiveDateTime,
    };

    /// A wall-clock time, encoded in Iso8601 format with an intervening
    /// space between the date and time.
    ///
    /// (Example: "2020-10-09 17:38:12")
    #[derive(derive_more::Into, derive_more::From)]
    pub(crate) struct Iso8601TimeSp(SystemTime);

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
    #[derive(derive_more::Into, derive_more::From)]
    pub(crate) struct Iso8601TimeNoSp(SystemTime);

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
}

/// Types for decoding RSA keys
mod rsa {
    use crate::{NetdocErrorKind as EK, Pos, Result};
    use std::ops::RangeBounds;
    use tor_llcrypto::pk::rsa::PublicKey;

    /// An RSA public key, as parsed from a base64-encoded object.
    #[allow(non_camel_case_types)]
    #[derive(Clone, Debug)]
    pub(crate) struct RsaPublic(PublicKey, Pos);

    impl From<RsaPublic> for PublicKey {
        fn from(k: RsaPublic) -> PublicKey {
            k.0
        }
    }
    impl super::FromBytes for RsaPublic {
        fn from_bytes(b: &[u8], pos: Pos) -> Result<Self> {
            let key = PublicKey::from_der(b)
                .ok_or_else(|| EK::BadObjectVal.with_msg("unable to decode RSA public key"))?;
            Ok(RsaPublic(key, pos))
        }
    }
    impl RsaPublic {
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

/// Types for decoding RSA fingerprints
mod fingerprint {
    use crate::{Error, NetdocErrorKind as EK, Pos, Result};
    use tor_llcrypto::pk::rsa::RsaIdentity;

    /// A hex-encoded fingerprint with spaces in it.
    pub(crate) struct SpFingerprint(RsaIdentity);

    /// A hex-encoded fingerprint with no spaces.
    pub(crate) struct Fingerprint(RsaIdentity);

    /// A "long identity" in the format used for Family members.
    pub(crate) struct LongIdent(RsaIdentity);

    impl From<SpFingerprint> for RsaIdentity {
        fn from(f: SpFingerprint) -> RsaIdentity {
            f.0
        }
    }

    impl From<LongIdent> for RsaIdentity {
        fn from(f: LongIdent) -> RsaIdentity {
            f.0
        }
    }

    impl From<Fingerprint> for RsaIdentity {
        fn from(f: Fingerprint) -> RsaIdentity {
            f.0
        }
    }

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

    impl std::str::FromStr for Fingerprint {
        type Err = Error;
        fn from_str(s: &str) -> Result<Fingerprint> {
            let ident = parse_hex_ident(s).map_err(|e| e.at_pos(Pos::at(s)))?;
            Ok(Fingerprint(ident))
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
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    #[cfg_attr(feature = "dangerous-expose-struct-fields", visibility::make(pub))]
    #[derive(Clone, Debug)]
    pub(crate) struct Nickname(tinystr::TinyAsciiStr<MAX_NICKNAME_LEN>);

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
    use itertools::Itertools;
    use std::iter;

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
        assert!("8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S"
            .parse::<B64>()?
            .check_len(24..25)
            .is_ok());
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxKkz8="
            .parse::<B64>()?
            .check_len(32..33)
            .is_ok());
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
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxaaaa"
            .parse::<B64>()
            .is_err());
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
            for c_vec in iter::repeat("ACEQg/=".chars())
                .take(n)
                .multi_cartesian_product()
            {
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

        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxKkz"
            .parse::<Curve25519Public>()
            .is_err());
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORSomCMxKkz"
            .parse::<Curve25519Public>()
            .is_err());
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5wSomCMxKkz"
            .parse::<Curve25519Public>()
            .is_err());
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4ORwSomCMxKkz"
            .parse::<Curve25519Public>()
            .is_err());

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

        assert!("WVIPQ8oArAqLY4Xzk0!!!!8KsUJHBQhG8SC57qru"
            .parse::<Ed25519Public>()
            .is_err());
        assert!("WVIPQ8oArAqLY4XzkcpIU8KsUJHBQhG8SC57qru"
            .parse::<Ed25519Public>()
            .is_err());
        assert!("WVIPQ8oArAqLY4XzkcpIU8KsUJHBQhG8SC57qr"
            .parse::<Ed25519Public>()
            .is_err());
        // right length, bad key:
        assert!("ppwthHXW8kXD0f9fE7UPYsOAAu4uj5ORwSomCMxaaaa"
            .parse::<Curve25519Public>()
            .is_err());
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
        let rsa = RsaPublic::from_vec(key_bytes, Pos::None).unwrap();

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
        let failure = RsaPublic::from_vec(vec![1, 2, 3], Pos::None);
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
        assert!(cert
            .clone()
            .check_cert_type(tor_cert::CertType::RSA_ID_X509)
            .is_err());
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

        assert!(fp1.parse::<LongIdent>().is_err());
        assert_eq!(RsaIdentity::from(fp2.parse::<LongIdent>()?), k);
        assert_eq!(RsaIdentity::from(fp3.parse::<LongIdent>()?), k);
        assert_eq!(RsaIdentity::from(fp4.parse::<LongIdent>()?), k);

        assert!("xxxx".parse::<Fingerprint>().is_err());
        assert!("ffffffffff".parse::<Fingerprint>().is_err());
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
