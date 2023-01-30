//! Key type wrappers of various kinds used in onion services.
//!
//! (We define wrappers here as a safety net against confusing one kind of
//! key for another: without a system like this, it can get pretty hard making
//! sure that each key is used only in the right way.)

// TODO hs: Maybe we want to remove some of these types as we build the
// implementation; for example, if we find that a single key type is visible
// only in a single module somewhere else, it would make sense to just use the
// underlying type.

use digest::Digest;
use tor_llcrypto::d::Sha3_256;
use tor_llcrypto::pk::{curve25519, ed25519, keymanip};
use tor_llcrypto::util::ct::CtByteArray;

use crate::macros::{define_bytes, define_pk_keypair};
use crate::time::TimePeriod;

define_bytes! {
/// The identity of a v3 onion service. (KP_hs_id)
///
/// This is the decoded and validated ed25519 public key that is encoded as a
/// `${base32}.onion` address.  When expanded, it is a public key whose
/// corresponding secret key is controlled by the onion service.
///
/// Note: This is a separate type from [`OnionIdKey`] because it is about 6x
/// smaller.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OnionId([u8; 32]);
}

define_pk_keypair! {
/// The identity of a v3 onion service, expanded into a public key. (KP_hs_id)
///
/// This is the decoded and validated ed25519 public key that is encoded as
/// a `${base32}.onion` address.
///
/// This key is not used to sign or validate anything on its own; instead, it is
/// used to derive a `BlindedOnionIdKey`.
///
/// Note: This is a separate type from [`OnionId`] because it is about 6x
/// larger.  It is an expanded form, used for doing actual cryptography.
//
// NOTE: This is called the "master" key in rend-spec-v3, but we're deprecating
// that vocabulary generally.
pub struct OnionIdKey(ed25519::PublicKey) /
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
    OnionIdSecretKey(ed25519::ExpandedSecretKey);
}

impl OnionIdKey {
    /// Return a representation of this key as an [`OnionId`].
    ///
    /// ([`OnionId`] is much smaller, and easier to store.)
    pub fn id(&self) -> OnionId {
        OnionId(self.0.to_bytes().into())
    }
}
impl TryFrom<OnionId> for OnionIdKey {
    type Error = signature::Error;

    fn try_from(value: OnionId) -> Result<Self, Self::Error> {
        ed25519::PublicKey::from_bytes(value.0.as_ref()).map(OnionIdKey)
    }
}
impl From<OnionIdKey> for OnionId {
    fn from(value: OnionIdKey) -> Self {
        value.id()
    }
}

impl OnionIdKey {
    /// Derive the blinded key and subcredential for this identity during `cur_period`.
    pub fn compute_blinded_key(
        &self,
        cur_period: TimePeriod,
    ) -> Result<(BlindedOnionIdKey, crate::Subcredential), keymanip::BlindingError> {
        // TODO hs: decide whether we want to support this kind of shared secret; C Tor does not.
        let secret = b"";
        let param = self.blinding_parameter(secret, cur_period);

        let blinded_key = keymanip::blind_pubkey(&self.0, param)?;
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
            h.update(blinded_key.as_bytes());
            h.finalize().into()
        };

        Ok((blinded_key.into(), subcredential_bytes.into()))
    }

    /// Compute the 32-byte "blinding parameters" used to compute blinded public
    /// (and secret) keys.
    fn blinding_parameter(&self, secret: &[u8], cur_period: TimePeriod) -> [u8; 32] {
        // rend-spec-v3 appendix A.2
        // We generate our key blinding parameter as
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
        h.update(u64::from(cur_period.length_in_sec).to_be_bytes());

        h.finalize().into()
    }
}

impl OnionIdSecretKey {
    /// Derive the blinded key and subcredential for this identity during `cur_period`.
    pub fn compute_blinded_key(
        &self,
        cur_period: TimePeriod,
    ) -> Result<
        (
            BlindedOnionIdKey,
            BlindedOnionIdSecretKey,
            crate::Subcredential,
        ),
        keymanip::BlindingError,
    > {
        // TODO hs: as above, decide if we want this.
        let secret = b"";

        // Note: This implementation is somewhat inefficient, as it recomputes
        // the PublicKey, and computes our blinding parameters twice.  But we
        // only do this on an onion service once per time period: the
        // performance does not matter.

        let public_key: OnionIdKey = ed25519::PublicKey::from(&self.0).into();
        let (blinded_public_key, subcredential) = public_key.compute_blinded_key(cur_period)?;

        let param = public_key.blinding_parameter(secret, cur_period);
        let blinded_secret_key = keymanip::blind_seckey(&self.0, param)?;

        Ok((blinded_public_key, blinded_secret_key.into(), subcredential))
    }
}

define_pk_keypair! {
/// The "blinded" identity of a v3 onion service. (`KP_hs_blind_id`)
///
/// This key is derived via a one-way transformation from an
/// `OnionIdKey` and the current time period.
///
/// It is used for two purposes: first, to compute an index into the HSDir
/// ring, and second, to sign a `DescSigningKey`.
///
/// Note: This is a separate type from [`BlindedOnionId`] because it is about 6x
/// larger.  It is an expanded form, used for doing actual cryptography.
pub struct BlindedOnionIdKey(ed25519::PublicKey) / BlindedOnionIdSecretKey(ed25519::ExpandedSecretKey);
}

define_bytes! {
/// A blinded onion service identity, represented in a compact format. (`KP_hs_blind_id`)
///
/// Note: This is a separate type from [`BlindedOnionIdKey`] because it is about
/// 6x smaller.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct BlindedOnionId([u8; 32]);
}

impl BlindedOnionIdKey {
    /// Return a representation of this key as a [`BlindedOnionId`].
    ///
    /// ([`BlindedOnionId`] is much smaller, and easier to store.)
    pub fn id(&self) -> BlindedOnionId {
        BlindedOnionId(self.0.to_bytes().into())
    }
}
impl TryFrom<BlindedOnionId> for BlindedOnionIdKey {
    type Error = signature::Error;

    fn try_from(value: BlindedOnionId) -> Result<Self, Self::Error> {
        ed25519::PublicKey::from_bytes(value.0.as_ref()).map(BlindedOnionIdKey)
    }
}
impl From<BlindedOnionIdKey> for BlindedOnionId {
    fn from(value: BlindedOnionIdKey) -> Self {
        value.id()
    }
}
impl From<ed25519::Ed25519Identity> for BlindedOnionId {
    fn from(value: ed25519::Ed25519Identity) -> Self {
        Self(CtByteArray::from(<[u8; 32]>::from(value)))
    }
}

impl BlindedOnionIdSecretKey {
    /// Compute a signature of `message` with this key, using the corresponding `public_key`.
    pub fn sign(&self, message: &[u8], public_key: &BlindedOnionIdKey) -> ed25519::Signature {
        self.0.sign(message, &public_key.0)
    }
}

define_pk_keypair! {
/// A key used to sign onion service descriptors. (`KP_desc_sign`)
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
/// BlindedOnionIdKey directly, so that the secret key for the BlindedOnionIdKey
/// can be kept offline.
pub struct DescSigningKey(ed25519::PublicKey) / DescSigningSecretKey(ed25519::SecretKey);
}

define_pk_keypair! {
/// A key used to identify and authenticate an onion service at a single
/// introduction point. (`KP_hs_intro_tid`)
///
/// This key is included in the onion service's descriptor; a different one is
/// used at each introduction point.  Introduction points don't know the
/// relation of this key to the onion service: they only recognize the same key
/// when they see it again.
pub struct IntroPtAuthKey(ed25519::PublicKey) / IntroPtAuthSecretKey(ed25519::SecretKey);
}

define_pk_keypair! {
/// A key used in the HsNtor handshake between the client and the onion service.
/// (`KP_hs_into_ntor`)
///
/// The onion service chooses a different one of these to use with each
/// introduction point, though it does not need to tell the introduction points
/// about these keys.
pub struct IntroPtEncKey(curve25519::PublicKey) / IntroPtEncSecretKey(curve25519::StaticSecret);
}

define_pk_keypair! {
/// First type of client authorization key, used for the introduction protocol.
/// (`KP_hsc_intro_auth`)
///
/// This is used to sign a nonce included in an extension in the encrypted
/// portion of an introduce cell.
pub struct ClientIntroAuthKey(ed25519::PublicKey) / ClientIntroAuthSecretKey(ed25519::SecretKey);
}

define_pk_keypair! {
/// Second type of client authorization key, used for onion descriptor
/// decryption. (`KP_hsc_desc_enc`)
///
/// Any client who knows the secret key corresponding to this key can decrypt
/// the inner layer of the onion service descriptor.
pub struct ClientDescAuthKey(curve25519::PublicKey) / ClientDescAuthSecretKey(curve25519::StaticSecret);
}

/// A set of keys to tell the client to use when connecting to an onion service.
//
// TODO hs
pub struct ClientSecretKeys {
    /// Possibly, a key that is used to decrypt a descriptor.
    desc_auth: Option<ClientDescAuthSecretKey>,
    /// Possibly, a key that is used to authenticate while
    /// introducing.
    intro_auth: Option<ClientIntroAuthSecretKey>,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use hex_literal::hex;
    use signature::Verifier;
    use std::time::{Duration, SystemTime};
    use tor_basic_utils::test_rng::testing_rng;
    use tor_llcrypto::util::rand_compat::RngCompatExt as _;

    use super::*;

    #[test]
    fn key_blinding_blackbox() {
        let mut rng = testing_rng().rng_compat();
        let offset = Duration::new(12 * 60 * 60, 0);
        let when = TimePeriod::new(Duration::from_secs(3600), SystemTime::now(), offset).unwrap();
        let keypair = ed25519::Keypair::generate(&mut rng);
        let id_pub = OnionIdKey::from(keypair.public);
        let id_sec = OnionIdSecretKey::from(ed25519::ExpandedSecretKey::from(&keypair.secret));

        let (blinded_pub, subcred1) = id_pub.compute_blinded_key(when).unwrap();
        let (blinded_pub2, blinded_sec, subcred2) = id_sec.compute_blinded_key(when).unwrap();

        assert_eq!(subcred1.as_ref(), subcred2.as_ref());
        assert_eq!(blinded_pub.0.to_bytes(), blinded_pub2.0.to_bytes());
        assert_eq!(blinded_pub.id(), blinded_pub2.id());

        let message = b"Here is a terribly important string to authenticate.";
        let other_message = b"Hey, that is not what I signed!";
        let sign = blinded_sec.sign(message, &blinded_pub2);

        assert!(blinded_pub.as_ref().verify(message, &sign).is_ok());
        assert!(blinded_pub.as_ref().verify(other_message, &sign).is_err());
    }

    #[test]
    fn key_blinding_testvec() {
        // Test vectors generated with C tor.
        let id = OnionId::from(hex!(
            "833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6"
        ));
        let id_pubkey = OnionIdKey::try_from(id).unwrap();
        let id_seckey = OnionIdSecretKey::from(
            ed25519::ExpandedSecretKey::from_bytes(&hex!(
                "D8C7FF0E31295B66540D789AF3E3DF992038A9592EEA01D8B7CBA06D6E66D159
                 4D6167696320576F7264733A20737065697373636F62616C742062697669756D"
            ))
            .unwrap(),
        );
        let offset = Duration::new(12 * 60 * 60, 0);
        let time_period = TimePeriod::new(
            Duration::from_secs(1440),
            humantime::parse_rfc3339("1970-01-22T01:50:33Z").unwrap(),
            offset,
        )
        .unwrap();
        assert_eq!(time_period.interval_num, 1234);

        let param = id_pubkey.blinding_parameter(b"", time_period);
        assert_eq!(
            param,
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
            blinded_sec.0.to_bytes(),
            hex!(
                "A958DC83AC885F6814C67035DE817A2C604D5D2F715282079448F789B656350B
                 4540FE1F80AA3F7E91306B7BF7A8E367293352B14A29FDCC8C19F3558075524B"
            )
        );
    }
}
