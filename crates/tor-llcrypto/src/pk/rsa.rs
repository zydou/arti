//! Re-exporting RSA implementations.
//!
//! This module can currently handle public keys and signature
//! verification used in the Tor directory protocol and
//! similar places.
//!
//! Currently, that means validating PKCSv1 signatures, and encoding
//! and decoding RSA public keys from DER.
//!
//! # Limitations:
//!
//! Currently missing are support for signing and RSA-OEAP.  In Tor,
//! RSA signing is only needed for relays and authorities, and
//! RSA-OAEP padding is only needed for the (obsolete) TAP protocol.
//!
//! This module should expose RustCrypto trait-based wrappers,
//! but the [`rsa`] crate didn't support them as of initial writing.
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "memquota-memcost")]
use {derive_deftly::Deftly, tor_memquota::derive_deftly_template_HasMemoryCost};

use crate::util::ct::CtByteArray;

/// How many bytes are in an "RSA ID"?  (This is a legacy tor
/// concept, and refers to identifying a relay by a SHA1 digest
/// of its RSA public identity key.)
pub const RSA_ID_LEN: usize = 20;

/// An identifier for an RSA key, based on SHA1 and DER.
///
/// These are used (for legacy purposes) all over the Tor protocol.
///
/// This object is an "identity" in the sense that it identifies (up to) one RSA
/// key.  It may also represent the identity for a particular entity, such as a
/// relay or a directory authority.
///
/// Note that for modern purposes, you should almost always identify a relay by
/// its [`Ed25519Identity`](crate::pk::ed25519::Ed25519Identity) instead of by
/// this kind of identity key.
#[derive(Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "memquota-memcost", derive(Deftly), derive_deftly(HasMemoryCost))]
pub struct RsaIdentity {
    /// SHA1 digest of a DER encoded public key.
    id: CtByteArray<RSA_ID_LEN>,
}

impl ConstantTimeEq for RsaIdentity {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.id.ct_eq(&other.id)
    }
}

impl fmt::Display for RsaIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}", hex::encode(&self.id.as_ref()[..]))
    }
}
impl fmt::Debug for RsaIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaIdentity {{ {} }}", self)
    }
}

impl safelog::Redactable for RsaIdentity {
    /// Warning: This displays 16 bits of the RSA identity, which is
    /// enough to narrow down a public relay by a great deal.
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}…", hex::encode(&self.id.as_ref()[..1]))
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaIdentity {{ {} }}", self.redacted())
    }
}

impl serde::Serialize for RsaIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&self.id.as_ref()[..]))
        } else {
            serializer.serialize_bytes(&self.id.as_ref()[..])
        }
    }
}

impl<'de> serde::Deserialize<'de> for RsaIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            /// Deserialization helper
            struct RsaIdentityVisitor;
            impl<'de> serde::de::Visitor<'de> for RsaIdentityVisitor {
                type Value = RsaIdentity;
                fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                    fmt.write_str("hex-encoded RSA identity")
                }
                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    RsaIdentity::from_hex(s)
                        .ok_or_else(|| E::custom("wrong encoding for RSA identity"))
                }
            }

            deserializer.deserialize_str(RsaIdentityVisitor)
        } else {
            /// Deserialization helper
            struct RsaIdentityVisitor;
            impl<'de> serde::de::Visitor<'de> for RsaIdentityVisitor {
                type Value = RsaIdentity;
                fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                    fmt.write_str("RSA identity")
                }
                fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    RsaIdentity::from_bytes(bytes)
                        .ok_or_else(|| E::custom("wrong length for RSA identity"))
                }
            }
            deserializer.deserialize_bytes(RsaIdentityVisitor)
        }
    }
}

impl RsaIdentity {
    /// Expose an RsaIdentity as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.id.as_ref()[..]
    }
    /// Construct an RsaIdentity from a slice of bytes.
    ///
    /// Returns None if the input is not of the correct length.
    ///
    /// ```
    /// use tor_llcrypto::pk::rsa::RsaIdentity;
    ///
    /// let bytes = b"xyzzyxyzzyxyzzyxyzzy";
    /// let id = RsaIdentity::from_bytes(bytes);
    /// assert_eq!(id.unwrap().as_bytes(), bytes);
    ///
    /// let truncated = b"xyzzy";
    /// let id = RsaIdentity::from_bytes(truncated);
    /// assert_eq!(id, None);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(RsaIdentity {
            id: CtByteArray::from(<[u8; RSA_ID_LEN]>::try_from(bytes).ok()?),
        })
    }
    /// Decode an `RsaIdentity` from a hexadecimal string.
    ///
    /// The string must have no spaces, or any extra characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        let mut array = [0_u8; 20];
        match hex::decode_to_slice(s, &mut array) {
            Err(_) => None,
            Ok(()) => Some(RsaIdentity::from(array)),
        }
    }

    /// Return true if this `RsaIdentity` is composed entirely of zero-valued
    /// bytes.
    ///
    /// Such all-zero values should not be used internally, since they are not
    /// the ID of any valid key.  Instead, they are used in some places in the
    /// Tor protocols.
    pub fn is_zero(&self) -> bool {
        // We do a constant-time comparison to avoid side-channels.
        self.id.ct_eq(&[0; RSA_ID_LEN].into()).into()
    }
}

impl From<[u8; 20]> for RsaIdentity {
    fn from(id: [u8; 20]) -> RsaIdentity {
        RsaIdentity { id: id.into() }
    }
}

/// An RSA public key.
///
/// This implementation is a simple wrapper so that we can define new
/// methods and traits on the type.
#[derive(Clone, Debug)]
pub struct PublicKey(rsa::RsaPublicKey);

/// An RSA private key.
///
/// This is not so useful at present, since Arti currently only has
/// client support, and Tor clients never actually need RSA private
/// keys.
pub struct PrivateKey(rsa::RsaPrivateKey);

impl PrivateKey {
    /// Return the public component of this key.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.to_public_key())
    }
    /// Construct a PrivateKey from DER pkcs1 encoding.
    pub fn from_der(der: &[u8]) -> Option<Self> {
        Some(PrivateKey(rsa::RsaPrivateKey::from_pkcs1_der(der).ok()?))
    }
    // ....
}
impl PublicKey {
    /// Return true iff the exponent for this key is the same
    /// number as 'e'.
    pub fn exponent_is(&self, e: u32) -> bool {
        use rsa::traits::PublicKeyParts;
        *self.0.e() == rsa::BigUint::new(vec![e])
    }
    /// Return the number of bits in the modulus for this key.
    pub fn bits(&self) -> usize {
        use rsa::traits::PublicKeyParts;
        self.0.n().bits()
    }
    /// Try to check a signature (as used in Tor.)  The signed hash
    /// should be in 'hashed', and the alleged signature in 'sig'.
    ///
    /// Tor uses RSA-PKCSv1 signatures, with hash algorithm OIDs
    /// omitted.
    pub fn verify(&self, hashed: &[u8], sig: &[u8]) -> Result<(), signature::Error> {
        let padding = rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed();
        self.0
            .verify(padding, hashed, sig)
            .map_err(|_| signature::Error::new())
    }
    /// Decode an alleged DER byte string into a PublicKey.
    ///
    /// Return None  if the DER string does not have a valid PublicKey.
    ///
    /// (This function expects an RsaPublicKey, as used by Tor.  It
    /// does not expect or accept a PublicKeyInfo.)
    pub fn from_der(der: &[u8]) -> Option<Self> {
        Some(PublicKey(rsa::RsaPublicKey::from_pkcs1_der(der).ok()?))
    }
    /// Encode this public key into the DER format as used by Tor.
    ///
    /// The result is an RsaPublicKey, not a PublicKeyInfo.
    pub fn to_der(&self) -> Vec<u8> {
        use der_parser::ber::BerObject;
        use rsa::traits::PublicKeyParts;

        let mut n = self.0.n().to_bytes_be();
        // prepend 0 if high bit is 1 to ensure correct signed encoding
        if n[0] & 0b10000000 != 0 {
            n.insert(0, 0_u8);
        }
        let n = BerObject::from_int_slice(&n);

        let mut e = self.0.e().to_bytes_be();
        // prepend 0 if high bit is 1 to ensure correct signed encoding
        if e[0] & 0b10000000 != 0 {
            e.insert(0, 0_u8);
        }
        let e = BerObject::from_int_slice(&e);

        let asn1 = BerObject::from_seq(vec![n, e]);
        asn1.to_vec().expect("RSA key not encodable as DER")
    }

    /// Compute the RsaIdentity for this public key.
    pub fn to_rsa_identity(&self) -> RsaIdentity {
        use crate::d::Sha1;
        use digest::Digest;
        let id: [u8; RSA_ID_LEN] = Sha1::digest(self.to_der()).into();
        RsaIdentity { id: id.into() }
    }
}

/// An RSA signature plus all the information needed to validate it.
pub struct ValidatableRsaSignature {
    /// The key that allegedly signed this signature
    key: PublicKey,
    /// The signature in question
    sig: Vec<u8>,
    /// The value we expect to find that the signature is a signature of.
    expected_hash: Vec<u8>,
}

impl ValidatableRsaSignature {
    /// Construct a new ValidatableRsaSignature.
    pub fn new(key: &PublicKey, sig: &[u8], expected_hash: &[u8]) -> Self {
        ValidatableRsaSignature {
            key: key.clone(),
            sig: sig.into(),
            expected_hash: expected_hash.into(),
        }
    }
}

impl super::ValidatableSignature for ValidatableRsaSignature {
    fn is_valid(&self) -> bool {
        self.key
            .verify(&self.expected_hash[..], &self.sig[..])
            .is_ok()
    }
}
