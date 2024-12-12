//! Key type wrappers of various kinds used in onion services.
//!
//! (We define wrappers here as a safety net against confusing one kind of
//! key for another: without a system like this, it can get pretty hard making
//! sure that each key is used only in the right way.)

use std::fmt::{self, Debug, Display};
use std::str::FromStr;

use digest::Digest;
use itertools::{chain, Itertools};
use thiserror::Error;
use tor_basic_utils::{impl_debug_hex, StrExt as _};
use tor_key_forge::ToEncodableKey;
use tor_llcrypto::d::Sha3_256;
use tor_llcrypto::pk::ed25519::{Ed25519PublicKey, Signer};
use tor_llcrypto::pk::{curve25519, ed25519, keymanip};
use tor_llcrypto::util::ct::CtByteArray;

use crate::macros::{define_bytes, define_pk_keypair};
use crate::time::TimePeriod;

#[allow(deprecated)]
pub use hs_client_intro_auth::{HsClientIntroAuthKey, HsClientIntroAuthKeypair};

define_bytes! {
/// The identity of a v3 onion service. (KP_hs_id)
///
/// This is the decoded and validated ed25519 public key that is encoded as a
/// `${base32}.onion` address.  When expanded, it is a public key whose
/// corresponding secret key is controlled by the onion service.
///
/// `HsId`'s `Display` and `FromStr` representation is the domain name
/// `"${base32}.onion"`.  (Without any subdomains.)
///
/// Note: This is a separate type from [`HsIdKey`] because it is about 6x
/// smaller.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct HsId([u8; 32]);
}

impl fmt::LowerHex for HsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HsId(0x")?;
        for v in self.0.as_ref() {
            write!(f, "{:02x}", v)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl Debug for HsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HsId({})", self)
    }
}

define_pk_keypair! {
/// The identity of a v3 onion service, expanded into a public key. (KP_hs_id)
///
/// This is the decoded and validated ed25519 public key that is encoded as
/// a `${base32}.onion` address.
///
/// This key is not used to sign or validate anything on its own; instead, it is
/// used to derive a [`HsBlindIdKey`].
///
/// Note: This is a separate type from [`HsId`] because it is about 6x
/// larger.  It is an expanded form, used for doing actual cryptography.
//
// NOTE: This is called the "master" key in rend-spec-v3, but we're deprecating
// that vocabulary generally.
pub struct HsIdKey(ed25519::PublicKey) /
    ///
    /// This is stored as an expanded secret key, for compatibility with the C
    /// tor implementation, and in order to support custom-generated addresses.
    ///
    /// (About custom generated addresses: When making a vanity onion address,
    /// it is inefficient to search for a compact secret key `s` and compute
    /// `SHA512(s)=(a,r)` and `A=aB` until you find an `s` that produces an `A`
    /// that you like.  Instead, most folks use the algorithm of
    /// rend-spec-v3.txt appendix C, wherein you search for a good `a` directly
    /// by repeatedly adding `8B` to A until you find an `A` you like.  The only
    /// major drawback is that once you have found a good `a`, you can't get an
    /// `s` for it, since you presumably can't find SHA512 preimages.  And that
    /// is why we store the private key in (a,r) form.)
    HsIdKeypair(ed25519::ExpandedKeypair);
}

impl HsIdKey {
    /// Return a representation of this key as an [`HsId`].
    ///
    /// ([`HsId`] is much smaller, and easier to store.)
    pub fn id(&self) -> HsId {
        HsId(self.0.to_bytes().into())
    }
}
impl TryFrom<HsId> for HsIdKey {
    type Error = signature::Error;

    fn try_from(value: HsId) -> Result<Self, Self::Error> {
        ed25519::PublicKey::from_bytes(value.0.as_ref()).map(HsIdKey)
    }
}
impl From<HsIdKey> for HsId {
    fn from(value: HsIdKey) -> Self {
        value.id()
    }
}

impl From<&HsIdKeypair> for HsIdKey {
    fn from(value: &HsIdKeypair) -> Self {
        Self(*value.0.public())
    }
}

impl From<HsIdKeypair> for HsIdKey {
    fn from(value: HsIdKeypair) -> Self {
        Self(*value.0.public())
    }
}

/// VERSION from rend-spec-v3 s.6 \[ONIONADDRESS]
const HSID_ONION_VERSION: u8 = 0x03;

/// The fixed string `.onion`
pub const HSID_ONION_SUFFIX: &str = ".onion";

impl Display for HsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // rend-spec-v3 s.6 [ONIONADDRESS]
        let checksum = self.onion_checksum();
        let binary = chain!(self.0.as_ref(), &checksum, &[HSID_ONION_VERSION],)
            .cloned()
            .collect_vec();
        let mut b32 = data_encoding::BASE32_NOPAD.encode(&binary);
        b32.make_ascii_lowercase();
        write!(f, "{}{}", b32, HSID_ONION_SUFFIX)
    }
}

impl safelog::Redactable for HsId {
    // We here display some of the end.  We don't want to display the
    // *start* because vanity domains, which would perhaps suffer from
    // reduced deniability.
    fn display_redacted(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let unredacted = self.to_string();
        /// Length of the base32 data part of the address
        const DATA: usize = 56;
        assert_eq!(unredacted.len(), DATA + HSID_ONION_SUFFIX.len());

        // We show this part of the domain:
        //     e     n     l     5     s     i     d     .onion
        //   KKKKK KKKKK KCCCC CCCCC CCCCC CCVVV VVVVV
        //                           ^^^^^^^^^^^^^^^^^ ^^^^^^^^^
        // This contains 3 characters of base32, which is 15 bits.
        // 8 of those bits are the version, which is currently always 0x03.
        // So we are showing 7 bits derived from the site key.

        write!(f, "???{}", &unredacted[DATA - 3..])
    }
}

impl FromStr for HsId {
    type Err = HsIdParseError;
    fn from_str(s: &str) -> Result<Self, HsIdParseError> {
        use HsIdParseError as PE;

        let s = s
            .strip_suffix_ignore_ascii_case(HSID_ONION_SUFFIX)
            .ok_or(PE::NotOnionDomain)?;

        if s.contains('.') {
            return Err(PE::HsIdContainsSubdomain);
        }

        // We must convert to uppercase because RFC4648 says so and that's what Rust
        // ecosystem libraries for base32 expect.  All this allocation and copying is
        // still probably less work than the SHA3 for the checksum.
        // However, we are going to use this function to *detect* and filter .onion
        // addresses, so it should have a fast path to reject thm.
        let mut s = s.to_owned();
        s.make_ascii_uppercase();

        // Ideally we'd have code here that would provide a clear error message if
        // we encounter an address with the wrong version.  But that is very complicated
        // because the encoding format does not make that at all convenient.
        // So instead our errors tell you what aspect of the parsing went wrong.
        let binary = data_encoding::BASE32_NOPAD.decode(s.as_bytes())?;
        let mut binary = tor_bytes::Reader::from_slice(&binary);

        let pubkey: [u8; 32] = binary.extract()?;
        let checksum: [u8; 2] = binary.extract()?;
        let version: u8 = binary.extract()?;
        let tentative = HsId(pubkey.into());

        // Check version before checksum; maybe a future version does checksum differently
        if version != HSID_ONION_VERSION {
            return Err(PE::UnsupportedVersion(version));
        }
        if checksum != tentative.onion_checksum() {
            return Err(PE::WrongChecksum);
        }
        Ok(tentative)
    }
}

/// Error that can occur parsing an `HsId` from a v3 `.onion` domain name
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum HsIdParseError {
    /// Supplied domain name string does not end in `.onion`
    #[error("Domain name does not end in .onion")]
    NotOnionDomain,

    /// Base32 decoding failed
    ///
    /// `position` is indeed the (byte) position in the input string
    #[error("Invalid base32 in .onion address")]
    InvalidBase32(#[from] data_encoding::DecodeError),

    /// Encoded binary data is invalid
    #[error("Invalid encoded binary data in .onion address")]
    InvalidData(#[from] tor_bytes::Error),

    /// Unsupported `.onion` address version
    #[error("Unsupported .onion address version, v{0}")]
    UnsupportedVersion(u8),

    /// Checksum failed
    #[error("Checksum failed, .onion address corrupted")]
    WrongChecksum,

    /// If you try to parse a domain with subdomains as an `HsId`
    #[error("`.onion` address with subdomain passed where not expected")]
    HsIdContainsSubdomain,
}

impl HsId {
    /// Calculates CHECKSUM rend-spec-v3 s.6 \[ONIONADDRESS]
    fn onion_checksum(&self) -> [u8; 2] {
        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(self.0.as_ref());
        h.update([HSID_ONION_VERSION]);
        h.finalize()[..2]
            .try_into()
            .expect("slice of fixed size wasn't that size")
    }
}

impl HsIdKey {
    /// Derive the blinded key and subcredential for this identity during `cur_period`.
    pub fn compute_blinded_key(
        &self,
        cur_period: TimePeriod,
    ) -> Result<(HsBlindIdKey, crate::Subcredential), keymanip::BlindingError> {
        // TODO: someday we might want to support this kinds of a shared secret
        // in our protocol. (C tor does not.)  If we did, it would be an
        // additional piece of information about an onion service that you would
        // need to know in order to connect to it.
        //
        // This is the "optional secret s" mentioned in the key-blinding
        // appendix to rend-spec.txt.
        let secret = b"";
        let h = self.blinding_factor(secret, cur_period);

        let blinded_key = keymanip::blind_pubkey(&self.0, h)?.into();
        // rend-spec-v3 section 2.1
        let subcredential = self.compute_subcredential(&blinded_key, cur_period);

        Ok((blinded_key, subcredential))
    }

    /// Given a time period and a blinded public key, compute the subcredential.
    pub fn compute_subcredential(
        &self,
        blinded_key: &HsBlindIdKey,
        cur_period: TimePeriod,
    ) -> crate::Subcredential {
        // rend-spec-v3 section 2.1
        let subcredential_bytes: [u8; 32] = {
            // N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key).
            // where
            //    N_hs_cred = H("credential" | public-identity-key)
            let n_hs_cred: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(b"credential");
                h.update(self.0.as_bytes());
                h.finalize().into()
            };
            let mut h = Sha3_256::new();
            h.update(b"subcredential");
            h.update(n_hs_cred);
            h.update(blinded_key.as_ref());
            h.finalize().into()
        };

        subcredential_bytes.into()
    }

    /// Compute the 32-byte "blinding factor" used to compute blinded public
    /// (and secret) keys.
    ///
    /// Returns the value `h = H(...)`, from rend-spec-v3 A.2., before clamping.
    fn blinding_factor(&self, secret: &[u8], cur_period: TimePeriod) -> [u8; 32] {
        // rend-spec-v3 appendix A.2
        // We generate our key blinding factor as
        //    h = H(BLIND_STRING | A | s | B | N)
        // Where:
        //    H is SHA3-256.
        //    A is this public key.
        //    BLIND_STRING = "Derive temporary signing key" | INT_1(0)
        //    s is an optional secret (not implemented here.)
        //    B is the ed25519 basepoint.
        //    N = "key-blind" || INT_8(period_num) || INT_8(period_length).

        /// String used as part of input to blinding hash.
        const BLIND_STRING: &[u8] = b"Derive temporary signing key\0";
        /// String representation of our Ed25519 basepoint.
        const ED25519_BASEPOINT: &[u8] =
            b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, \
               46316835694926478169428394003475163141307993866256225615783033603165251855960)";

        let mut h = Sha3_256::new();
        h.update(BLIND_STRING);
        h.update(self.0.as_bytes());
        h.update(secret);
        h.update(ED25519_BASEPOINT);
        h.update(b"key-blind");
        h.update(cur_period.interval_num.to_be_bytes());
        h.update((u64::from(cur_period.length.as_minutes())).to_be_bytes());

        h.finalize().into()
    }
}

impl HsIdKeypair {
    /// Derive the blinded key and subcredential for this identity during `cur_period`.
    pub fn compute_blinded_key(
        &self,
        cur_period: TimePeriod,
    ) -> Result<(HsBlindIdKey, HsBlindIdKeypair, crate::Subcredential), keymanip::BlindingError>
    {
        // TODO: as discussed above in `HsId::compute_blinded_key`, we might
        // someday want to implement nonempty values for this secret, if we
        // decide it would be good for something.
        let secret = b"";

        let public_key = HsIdKey(*self.0.public());

        // Note: This implementation is somewhat inefficient, as it recomputes
        // the PublicKey, and computes our blinding factor twice.  But we
        // only do this on an onion service once per time period: the
        // performance does not matter.
        let (blinded_public_key, subcredential) = public_key.compute_blinded_key(cur_period)?;

        let h = public_key.blinding_factor(secret, cur_period);

        let blinded_keypair = keymanip::blind_keypair(&self.0, h)?;

        Ok((blinded_public_key, blinded_keypair.into(), subcredential))
    }
}

define_pk_keypair! {
/// The "blinded" identity of a v3 onion service. (`KP_hs_blind_id`)
///
/// This key is derived via a one-way transformation from an
/// `HsIdKey` and the current time period.
///
/// It is used for two purposes: first, to compute an index into the HSDir
/// ring, and second, to sign a `DescSigningKey`.
///
/// Note: This is a separate type from [`HsBlindId`] because it is about 6x
/// larger.  It is an expanded form, used for doing actual cryptography.
pub struct HsBlindIdKey(ed25519::PublicKey) / HsBlindIdKeypair(ed25519::ExpandedKeypair);
}

impl From<HsBlindIdKeypair> for HsBlindIdKey {
    fn from(kp: HsBlindIdKeypair) -> HsBlindIdKey {
        HsBlindIdKey(kp.0.into())
    }
}

define_bytes! {
/// A blinded onion service identity, represented in a compact format. (`KP_hs_blind_id`)
///
/// Note: This is a separate type from [`HsBlindIdKey`] because it is about
/// 6x smaller.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct HsBlindId([u8; 32]);
}
impl_debug_hex! { HsBlindId .0 }

impl HsBlindIdKey {
    /// Return a representation of this key as a [`HsBlindId`].
    ///
    /// ([`HsBlindId`] is much smaller, and easier to store.)
    pub fn id(&self) -> HsBlindId {
        HsBlindId(self.0.to_bytes().into())
    }
}
impl TryFrom<HsBlindId> for HsBlindIdKey {
    type Error = signature::Error;

    fn try_from(value: HsBlindId) -> Result<Self, Self::Error> {
        ed25519::PublicKey::from_bytes(value.0.as_ref()).map(HsBlindIdKey)
    }
}

impl From<&HsBlindIdKeypair> for HsBlindIdKey {
    fn from(value: &HsBlindIdKeypair) -> Self {
        HsBlindIdKey(*value.0.public())
    }
}

impl From<HsBlindIdKey> for HsBlindId {
    fn from(value: HsBlindIdKey) -> Self {
        value.id()
    }
}
impl From<ed25519::Ed25519Identity> for HsBlindId {
    fn from(value: ed25519::Ed25519Identity) -> Self {
        Self(CtByteArray::from(<[u8; 32]>::from(value)))
    }
}

impl Signer<ed25519::Signature> for HsBlindIdKeypair {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        Ok(self.0.sign(msg))
    }
}

impl Ed25519PublicKey for HsBlindIdKeypair {
    fn public_key(&self) -> &ed25519::PublicKey {
        self.0.public()
    }
}

define_pk_keypair! {
/// A key used to sign onion service descriptors. (`KP_desc_sign`)
///
/// It is authenticated with a [`HsBlindIdKey`] to prove that it belongs to
/// the right onion service, and is used in turn to sign the descriptor that
/// tells clients what they need to know about contacting an onion service.
///
/// Onion services create a new `DescSigningKey` every time the
/// `HsBlindIdKey` rotates, to prevent descriptors made in one time period
/// from being linkable to those made in another.
///
/// Note: we use a separate signing key here, rather than using the
/// `HsBlindIdKey` directly, so that the [`HsBlindIdKeypair`]
/// can be kept offline.
pub struct HsDescSigningKey(ed25519::PublicKey) / HsDescSigningKeypair(ed25519::Keypair);
}

define_pk_keypair! {
/// A key used to identify and authenticate an onion service at a single
/// introduction point. (`KP_hs_ipt_sid`)
///
/// This key is included in the onion service's descriptor; a different one is
/// used at each introduction point.  Introduction points don't know the
/// relation of this key to the onion service: they only recognize the same key
/// when they see it again.
pub struct HsIntroPtSessionIdKey(ed25519::PublicKey) / HsIntroPtSessionIdKeypair(ed25519::Keypair);
}

define_pk_keypair! {
/// A key used in the HsNtor handshake between the client and the onion service.
/// (`KP_hss_ntor`)
///
/// The onion service chooses a different one of these to use with each
/// introduction point, though it does not need to tell the introduction points
/// about these keys.
pub struct HsSvcNtorKey(curve25519::PublicKey) / HsSvcNtorSecretKey(curve25519::StaticSecret);
curve25519_pair as HsSvcNtorKeypair;
}

mod hs_client_intro_auth {
    #![allow(deprecated)]
    //! Key type wrappers for the deprecated `HsClientIntroKey`/`HsClientIntroKeypair` types.

    use tor_llcrypto::pk::ed25519;

    use crate::macros::define_pk_keypair;

    define_pk_keypair! {
    /// First type of client authorization key, used for the introduction protocol.
    /// (`KP_hsc_intro_auth`)
    ///
    /// This is used to sign a nonce included in an extension in the encrypted
    /// portion of an introduce cell.
    #[deprecated(note = "This key type is not used in the protocol implemented today.")]
    pub struct HsClientIntroAuthKey(ed25519::PublicKey) /
    #[deprecated(note = "This key type is not used in the protocol implemented today.")]
    HsClientIntroAuthKeypair(ed25519::Keypair);
    }
}

define_pk_keypair! {
/// Client service discovery key, used for onion descriptor
/// decryption. (`KP_hsc_desc_enc`)
///
/// Any client who knows the secret key corresponding to this key can decrypt
/// the inner layer of the onion service descriptor.
///
/// The [`Display`] and [`FromStr`] representation of keys of this type is
/// `descriptor:x25519:<base32-encoded-x25519-public-key>`.
/// Note: the base32 encoding of the key is unpadded and case-insensitive,
/// for compatibility with the format accepted by C Tor.
/// See also `CLIENT AUTHORIZATION` in `tor(1)`.
///
/// # Example
///
/// ```rust
/// # use tor_hscrypto::pk::HsClientDescEncKey;
/// # use std::str::FromStr;
/// // A client service discovery key for connecting
/// // to a service running in restricted discovery mode,
/// // with an uppercase base32 encoding for the key material.
/// const CLIENT_KEY1: &str = "descriptor:x25519:ZPRRMIV6DV6SJFL7SFBSVLJ5VUNPGCDFEVZ7M23LTLVTCCXJQBKA";
/// // An identical key using lowercase base32 encoding for the key material.
/// const CLIENT_KEY2: &str = "descriptor:x25519:zprrmiv6dv6sjfl7sfbsvlj5vunpgcdfevz7m23ltlvtccxjqbka";
///
/// // Both key encodings parse successfully
/// let key1 = HsClientDescEncKey::from_str(CLIENT_KEY1).unwrap();
/// let key2 = HsClientDescEncKey::from_str(CLIENT_KEY2).unwrap();
/// // The keys are identical
/// assert_eq!(key1, key2);
/// ```
pub struct HsClientDescEncKey(curve25519::PublicKey) / HsClientDescEncSecretKey(curve25519::StaticSecret);
curve25519_pair as HsClientDescEncKeypair;
}

impl PartialEq for HsClientDescEncKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for HsClientDescEncKey {}

impl Display for HsClientDescEncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x25519_pk = data_encoding::BASE32_NOPAD.encode(&self.0.to_bytes());
        write!(f, "descriptor:x25519:{}", x25519_pk)
    }
}

impl FromStr for HsClientDescEncKey {
    type Err = HsClientDescEncKeyParseError;

    fn from_str(key: &str) -> Result<Self, HsClientDescEncKeyParseError> {
        let (auth_type, key_type, encoded_key) = key
            .split(':')
            .collect_tuple()
            .ok_or(HsClientDescEncKeyParseError::InvalidFormat)?;

        if auth_type != "descriptor" {
            return Err(HsClientDescEncKeyParseError::InvalidAuthType(
                auth_type.into(),
            ));
        }

        if key_type != "x25519" {
            return Err(HsClientDescEncKeyParseError::InvalidKeyType(
                key_type.into(),
            ));
        }

        // Note: Tor's base32 decoder is case-insensitive, so we can't assume the input
        // is all uppercase.
        //
        // TODO: consider using `data_encoding_macro::new_encoding` to create a new Encoding
        // with an alphabet that includes lowercase letters instead of to_uppercase()ing the string.
        let encoded_key = encoded_key.to_uppercase();
        let x25519_pk = data_encoding::BASE32_NOPAD.decode(encoded_key.as_bytes())?;
        let x25519_pk: [u8; 32] = x25519_pk
            .try_into()
            .map_err(|_| HsClientDescEncKeyParseError::InvalidKeyMaterial)?;

        Ok(Self(curve25519::PublicKey::from(x25519_pk)))
    }
}

/// Error that can occur parsing an `HsClientDescEncKey` from C Tor format.
#[derive(Error, Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum HsClientDescEncKeyParseError {
    /// The auth type is not "descriptor".
    #[error("Invalid auth type {0}")]
    InvalidAuthType(String),

    /// The key type is not "x25519".
    #[error("Invalid key type {0}")]
    InvalidKeyType(String),

    /// The key is not in the `<auth-type>:x25519:<base32-encoded-public-key>` format.
    #[error("Invalid key format")]
    InvalidFormat,

    /// The encoded key material is invalid.
    #[error("Invalid key material")]
    InvalidKeyMaterial,

    /// Base32 decoding failed.
    #[error("Invalid base32 in client key")]
    InvalidBase32(#[from] data_encoding::DecodeError),
}

define_pk_keypair! {
/// Server key, used for diffie hellman during onion descriptor decryption.
/// (`KP_hss_desc_enc`)
///
/// This key is created for a single descriptor, and then thrown away.
pub struct HsSvcDescEncKey(curve25519::PublicKey) / HsSvcDescEncSecretKey(curve25519::StaticSecret);
}

impl From<&HsClientDescEncSecretKey> for HsClientDescEncKey {
    fn from(ks: &HsClientDescEncSecretKey) -> Self {
        Self(curve25519::PublicKey::from(&ks.0))
    }
}

impl From<&HsClientDescEncKeypair> for HsClientDescEncKey {
    fn from(ks: &HsClientDescEncKeypair) -> Self {
        Self(**ks.public())
    }
}

/// An ephemeral x25519 keypair, generated by an onion service
/// and used to for onion service encryption.
#[allow(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct HsSvcDescEncKeypair {
    /// The public part of the key.
    pub public: HsSvcDescEncKey,
    /// The secret part of the key.
    pub secret: HsSvcDescEncSecretKey,
}

// TODO: let the define_ed25519_keypair/define_curve25519_keypair macros
// auto-generate these impls.
//
// For some of the keys here, this currently cannot be done
// because the macro doesn't support generating expanded ed25519 keys.

impl ToEncodableKey for HsClientDescEncKeypair {
    type Key = curve25519::StaticKeypair;
    type KeyPair = HsClientDescEncKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsClientDescEncKeypair::new(key.public.into(), key.secret.into())
    }
}

impl ToEncodableKey for HsBlindIdKeypair {
    type Key = ed25519::ExpandedKeypair;
    type KeyPair = HsBlindIdKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsBlindIdKeypair::from(key)
    }
}

impl ToEncodableKey for HsBlindIdKey {
    type Key = ed25519::PublicKey;
    type KeyPair = HsBlindIdKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsBlindIdKey::from(key)
    }
}

impl ToEncodableKey for HsIdKeypair {
    type Key = ed25519::ExpandedKeypair;
    type KeyPair = HsIdKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsIdKeypair::from(key)
    }
}

impl ToEncodableKey for HsIdKey {
    type Key = ed25519::PublicKey;
    type KeyPair = HsIdKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsIdKey::from(key)
    }
}

impl ToEncodableKey for HsDescSigningKeypair {
    type Key = ed25519::Keypair;
    type KeyPair = HsDescSigningKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsDescSigningKeypair::from(key)
    }
}

impl ToEncodableKey for HsIntroPtSessionIdKeypair {
    type Key = ed25519::Keypair;
    type KeyPair = HsIntroPtSessionIdKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        key.into()
    }
}

impl ToEncodableKey for HsSvcNtorKeypair {
    type Key = curve25519::StaticKeypair;
    type KeyPair = HsSvcNtorKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        key.into()
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
    use itertools::izip;
    use safelog::Redactable;
    use signature::Verifier;
    use std::time::{Duration, SystemTime};
    use tor_basic_utils::test_rng::testing_rng;

    use super::*;

    #[test]
    fn hsid_strings() {
        use HsIdParseError as PE;

        // From C Tor src/test/test_hs_common.c test_build_address
        let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let b32 = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid";

        let hsid: [u8; 32] = hex::decode(hex).unwrap().try_into().unwrap();
        let hsid = HsId::from(hsid);
        let onion = format!("{}.onion", b32);

        assert_eq!(onion.parse::<HsId>().unwrap(), hsid);
        assert_eq!(hsid.to_string(), onion);

        let weird_case: String = izip!(onion.chars(), [false, true].iter().cloned().cycle(),)
            .map(|(c, swap)| if swap { c.to_ascii_uppercase() } else { c })
            .collect();
        dbg!(&weird_case);
        assert_eq!(weird_case.parse::<HsId>().unwrap(), hsid);

        macro_rules! chk_err { { $s:expr, $($pat:tt)* } => {
            let e = $s.parse::<HsId>();
            assert!(matches!(e, Err($($pat)*)), "{:?}", &e);
        } }
        let edited = |i, c| {
            let mut s = b32.to_owned().into_bytes();
            s[i] = c;
            format!("{}.onion", String::from_utf8(s).unwrap())
        };

        chk_err!("wrong", PE::NotOnionDomain);
        chk_err!("@.onion", PE::InvalidBase32(..));
        chk_err!("aaaaaaaa.onion", PE::InvalidData(..));
        chk_err!(edited(55, b'E'), PE::UnsupportedVersion(4));
        chk_err!(edited(53, b'X'), PE::WrongChecksum);
        chk_err!(&format!("www.{}", &onion), PE::HsIdContainsSubdomain);

        assert_eq!(format!("{:x}", &hsid), format!("HsId(0x{})", hex));
        assert_eq!(format!("{:?}", &hsid), format!("HsId({})", onion));

        assert_eq!(format!("{}", hsid.redacted()), "???sid.onion");
    }

    #[test]
    fn key_blinding_blackbox() {
        let mut rng = testing_rng();
        let offset = Duration::new(12 * 60 * 60, 0);
        let when = TimePeriod::new(Duration::from_secs(3600), SystemTime::now(), offset).unwrap();
        let keypair = ed25519::Keypair::generate(&mut rng);
        let id_pub = HsIdKey::from(keypair.verifying_key());
        let id_keypair = HsIdKeypair::from(ed25519::ExpandedKeypair::from(&keypair));

        let (blinded_pub, subcred1) = id_pub.compute_blinded_key(when).unwrap();
        let (blinded_pub2, blinded_keypair, subcred2) =
            id_keypair.compute_blinded_key(when).unwrap();

        assert_eq!(subcred1.as_ref(), subcred2.as_ref());
        assert_eq!(blinded_pub.0.to_bytes(), blinded_pub2.0.to_bytes());
        assert_eq!(blinded_pub.id(), blinded_pub2.id());

        let message = b"Here is a terribly important string to authenticate.";
        let other_message = b"Hey, that is not what I signed!";
        let sign = blinded_keypair.sign(message);

        assert!(blinded_pub.as_ref().verify(message, &sign).is_ok());
        assert!(blinded_pub.as_ref().verify(other_message, &sign).is_err());
    }

    #[test]
    fn key_blinding_testvec() {
        // Test vectors generated with C tor.
        let id = HsId::from(hex!(
            "833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6"
        ));
        let id_pubkey = HsIdKey::try_from(id).unwrap();
        let id_seckey = HsIdKeypair::from(
            ed25519::ExpandedKeypair::from_secret_key_bytes(hex!(
                "D8C7FF0E31295B66540D789AF3E3DF992038A9592EEA01D8B7CBA06D6E66D159
                 4D6167696320576F7264733A20737065697373636F62616C742062697669756D"
            ))
            .unwrap(),
        );
        let time_period = TimePeriod::new(
            humantime::parse_duration("1 day").unwrap(),
            humantime::parse_rfc3339("1973-05-20T01:50:33Z").unwrap(),
            humantime::parse_duration("12 hours").unwrap(),
        )
        .unwrap();
        assert_eq!(time_period.interval_num, 1234);

        let h = id_pubkey.blinding_factor(b"", time_period);
        assert_eq!(
            h,
            hex!("379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287")
        );

        let (blinded_pub1, subcred1) = id_pubkey.compute_blinded_key(time_period).unwrap();
        assert_eq!(
            blinded_pub1.0.to_bytes(),
            hex!("3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5")
        );
        assert_eq!(
            subcred1.as_ref(),
            &hex!("635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D")
        );

        let (blinded_pub2, blinded_sec, subcred2) =
            id_seckey.compute_blinded_key(time_period).unwrap();
        assert_eq!(blinded_pub1.0.to_bytes(), blinded_pub2.0.to_bytes());
        assert_eq!(subcred1.as_ref(), subcred2.as_ref());
        assert_eq!(
            blinded_sec.0.to_secret_key_bytes(),
            hex!(
                "A958DC83AC885F6814C67035DE817A2C604D5D2F715282079448F789B656350B
                 4540FE1F80AA3F7E91306B7BF7A8E367293352B14A29FDCC8C19F3558075524B"
            )
        );
    }

    #[test]
    fn parse_client_desc_enc_key() {
        use HsClientDescEncKeyParseError::*;

        /// Valid base32-encoded x25519 public key.
        const VALID_KEY_BASE32: &str = "dz4q5xqlb4ldnbs72iarrml4ephk3du4i7o2cgiva5lwr6wkquja";

        // Some keys that are in the wrong format
        const WRONG_FORMAT: &[&str] = &["a:b:c:d:e", "descriptor:", "descriptor:x25519", ""];

        for key in WRONG_FORMAT {
            let err = HsClientDescEncKey::from_str(key).unwrap_err();

            assert_eq!(err, InvalidFormat);
        }

        let err =
            HsClientDescEncKey::from_str(&format!("foo:descriptor:x25519:{VALID_KEY_BASE32}"))
                .unwrap_err();

        assert_eq!(err, InvalidFormat);

        // A key with an invalid auth type
        let err = HsClientDescEncKey::from_str("bar:x25519:aa==").unwrap_err();
        assert_eq!(err, InvalidAuthType("bar".into()));

        // A key with an invalid key type
        let err = HsClientDescEncKey::from_str("descriptor:not-x25519:aa==").unwrap_err();
        assert_eq!(err, InvalidKeyType("not-x25519".into()));

        // A key with an invalid base32 part
        let err = HsClientDescEncKey::from_str("descriptor:x25519:aa==").unwrap_err();
        assert!(matches!(err, InvalidBase32(_)));

        // A valid client desc enc key
        let _key =
            HsClientDescEncKey::from_str(&format!("descriptor:x25519:{VALID_KEY_BASE32}")).unwrap();

        // Roundtrip
        let desc_enc_key = HsClientDescEncKey::from(curve25519::PublicKey::from(
            &curve25519::StaticSecret::random_from_rng(testing_rng()),
        ));

        assert_eq!(
            desc_enc_key,
            HsClientDescEncKey::from_str(&desc_enc_key.to_string()).unwrap()
        );
    }
}
