//! Key type wrappers of various kinds used in onion services.
//
// NOTE: We define wrappers here as a safety net against confusing one kind of
// key for another: without a system like this, it can get pretty hard making
// sure that each key is used only in the right way.

// TODO hs: for each of these key types, we should impl AsRef<> to get at its inner type.
// We should impl From to convert to and from the inner types.
// TODO hs: These are so similar to one another that we probably want to define a local
// macro that declares them as appropriate.

// TODO hs: Maybe we want to remove some of these types as we build the
// implementation; for example, if we find that a single key type is visible
// only in a single module somewhere else, it would make sense to just use the
// underlying type.

use tor_llcrypto::pk::{curve25519, ed25519};

use crate::time::TimePeriod;

/// The identity of a v3 onion service.
///
/// This is the decoded and validated ed25519 public key that is encoded as a
/// `${base32}.onion` address.  When expanded, it is a public key whose
/// corresponding secret key is controlled by the onion service.
#[derive(Copy, Clone, Debug)]
pub struct OnionId([u8; 32]);

/// The identity of a v3 onion service, expanded into a public key.
///
/// This is the decoded and validated ed25519 public key that is encoded as
/// a `${base32}.onion` address.
///
/// This key is not used to sign or validate anything on its own; instead, it is
/// used to derive a `BlindedOnionIdKey`.
//
// NOTE: This is called the "master" key in rend-spec-v3, but we're deprecating
// that vocabulary generally.
//
// NOTE: This is a separate type from OnionId because it is about 6x larger.  It
// is an expanded form, used for doing actual cryptography.
#[derive(Clone, Debug)]
pub struct OnionIdKey(ed25519::PublicKey);

// TODO hs: implement TryFrom<OnionId> for OnionIdKey, and From<OnionIdKey> for OnionId.

impl OnionIdKey {
    /// Derive the blinded key and subcredential for this identity during `cur_period`.
    pub fn compute_blinded_key(
        &self,
        cur_period: &TimePeriod,
    ) -> (BlindedOnionIdKey, crate::Subcredential) {
        todo!() // TODO hs.  The underlying crypto is already done in tor_llcrypto::pk::keymanip
    }
}

/// The "blinded" identity of a v3 onion service.
///
/// This key is derived via a one-way transformation from an
/// `OnionIdKey` and the current time period.
///
/// It is used for two purposes: first, to compute an index into the HSDir
/// ring, and second, to sign a `DescSigningKey`.
#[derive(Clone, Debug)]
pub struct BlindedOnionIdKey(ed25519::PublicKey);

/// A blinded onion service identity, repreesented in a compact format.
#[derive(Copy, Clone, Debug)]
pub struct BlindedOnionId([u8; 32]);

// TODO hs: implement TryFrom<BlindedOnionId> for BlinedOnionIdKey, and
// From<BlindedOnionIdKey> for BlindedOnionId.

/// A key used to sign onion service descriptors.
///
/// It is authenticated with a `BlindedOnionIdKeys` to prove that it belongs to
/// the right onion service, and is used in turn to sign the descriptor that
/// tells clients what they need to know about contacting an onion service.
///
/// Onion services create a new `DescSigningKey` every time the
/// `BlindedOnionIdKeys` rotates, to prevent descriptors made in one time period
/// from being linkable to those made in another.
///
/// Note: we use a separate signing key here, rather than using the
/// BlidedOnionIdKey directly, so that the secret key for the BlindedOnionIdKey
/// can be kept offline.
#[derive(Clone, Debug)]
pub struct DescSigningKey(ed25519::PublicKey);

/// A key used to identify and authenticate an onion service at a single
/// introduction point.
///
/// This key is included in the onion service's descriptor; a different one is
/// used at each introduction point.  Introduction points don't know the
/// relation of this key to the onion service: they only recognize the same key
/// when they see it again.
#[derive(Clone, Debug)]
pub struct IntroPtAuthKey(ed25519::PublicKey);

/// A key used in the HsNtor handshake between the client and the onion service.
///
/// The onion service chooses a different one of these to use with each
/// introduction point, though it does not need to tell the introduction points
/// about these keys.
#[derive(Clone, Debug)]
pub struct IntroPtEncKey(curve25519::PublicKey);

/// First type of client authorization key, used for the introduction protocol.
///
/// This is used to sign a nonce included in an extension in the encrypted
/// portion of an introduce cell.
#[derive(Clone, Debug)]
pub struct ClientIntroAuthKey(ed25519::PublicKey);

/// Second type of client authorization key, used for onion descryptor
/// decryption.
///
/// Any client who knows the secret key corresponding to this key can decrypt
/// the inner layer of the onion service descriptor.
#[derive(Clone, Debug)]
pub struct ClientDescAuthKey(curve25519::PublicKey);

// TODO hs: For each of the above key types, we should have a correspondingly
// named private key type.  These private key types should be defined with the
// same macros that implement the other keys.
//
// The names should be something like these:
pub struct OnionIdSecretKey(ed25519::SecretKey);
pub struct ClientDescAuthSecretKey(curve25519::StaticSecret);
// ... and so on.
//
// NOTE: We'll have to use ExpandedSecretKey as the secret key
// for BlindedOnionIdSecretKey.
