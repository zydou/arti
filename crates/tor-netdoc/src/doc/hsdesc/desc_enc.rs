//! Types and functions for onion service descriptor encryption.
//!
//! TODO hs: It's possible that this should move to tor-netdoc.

use rand::CryptoRng;
use tor_hscrypto::{pk::BlindedOnionId, RevisionCounter, Subcredential};

/// Parameters for encrypting or decrypting part of an onion service descriptor.
///
/// The algorithm is as described in section `[HS-DESC-ENCRYPTION-KEYS]` of
/// rend-spec-v3.txt
pub(super) struct HsDescEncryption<'a> {
    /// First half of the "SECRET_DATA" field.
    pub(super) blinded_id: &'a BlindedOnionId,
    /// Second half of the "SECRET_DATA" field.
    pub(super) encryption_cookie: Option<&'a DescEncryptionCookie>,
    /// The "subcredential" of the onion service.
    pub(super) subcredential: &'a Subcredential,
    /// The current revision of the onion service descriptor being decrypted.
    pub(super) revision: RevisionCounter,
    /// A personalization string.
    pub(super) string_const: &'a [u8],
}

/// A value used in deriving the encryption key for the inner layer of onion
/// service encryption.
pub(super) struct DescEncryptionCookie([u8; 32]);

impl<'a> HsDescEncryption<'a> {
    /// Encrypt a given bytestring using these encryption parameters.
    pub(super) fn encrypt<R: CryptoRng>(&self, rng: &mut R, data: &[u8]) -> Vec<u8> {
        todo!() // TODO hs
    }
    /// Decrypt a given bytestring that was first encrypted using these
    /// encryption parameters.
    pub(super) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        todo!() // TODO hs
    }
}

/// An error that occurs when decrypting an onion service decryptor.
///
/// This error is deliberately uninformative, to avoid side channels.
#[non_exhaustive]
#[derive(Clone, Debug, thiserror::Error)]
#[error("Unable to decrypt onion service decryptor.")]
pub struct DecryptionError {}
