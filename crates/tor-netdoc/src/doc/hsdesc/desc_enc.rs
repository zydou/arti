//! Types and functions for onion service descriptor encryption.

use tor_hscrypto::{pk::HsBlindId, RevisionCounter, Subcredential};
use tor_llcrypto::cipher::aes::Aes256Ctr as Cipher;
use tor_llcrypto::d::Sha3_256 as Hash;
use tor_llcrypto::d::Shake256 as KDF;

use cipher::{KeyIvInit, StreamCipher};
use digest::{ExtendableOutput, FixedOutput, Update, XofReader};
#[cfg(any(test, feature = "hs-service"))]
use rand::{CryptoRng, Rng};
use tor_llcrypto::pk::curve25519::PublicKey;
use tor_llcrypto::pk::curve25519::StaticSecret;
use tor_llcrypto::util::ct::CtByteArray;
use zeroize::Zeroizing as Z;

/// Parameters for encrypting or decrypting part of an onion service descriptor.
///
/// The algorithm is as described in section `[HS-DESC-ENCRYPTION-KEYS]` of
/// rend-spec-v3.txt
pub(super) struct HsDescEncryption<'a> {
    /// First half of the "SECRET_DATA" field.
    ///
    /// (See rend-spec v3 2.5.1.1 and 2.5.2.1.)
    pub(super) blinded_id: &'a HsBlindId,
    /// Second half of the "SECRET_DATA" field.
    ///
    /// This is absent when handling the superencryption layer (2.5.1.1).
    /// For the encryption layer, it is `descriptor_cookie` (2.5.2.1)
    /// which is present when descriptor-encryption authentication via
    /// `KP_hsc_desc_enc` is in use.
    pub(super) desc_enc_nonce: Option<&'a HsDescEncNonce>,
    /// The "subcredential" of the onion service.
    pub(super) subcredential: &'a Subcredential,
    /// The current revision of the onion service descriptor being decrypted.
    pub(super) revision: RevisionCounter,
    /// A "personalization string".
    ///
    /// This is set to one of two constants depending on the layer being
    /// decrypted.
    pub(super) string_const: &'a [u8],
}

/// The length of a client ID.
pub(crate) const HS_DESC_CLIENT_ID_LEN: usize = 8;

/// The length of the `AuthClient` IV.
pub(crate) const HS_DESC_IV_LEN: usize = 16;

/// The length of an `N_hs_desc_enc` nonce (also known as a "descriptor cookie").
pub(crate) const HS_DESC_ENC_NONCE_LEN: usize = 16;

/// A value used in deriving the encryption key for the inner (encryption) layer
/// of onion service encryption.
///
/// This is  `N_hs_desc_enc` in the spec, where sometimes we also call it a
/// "descriptor cookie".
#[derive(derive_more::AsRef, derive_more::From)]
pub(super) struct HsDescEncNonce([u8; HS_DESC_ENC_NONCE_LEN]);

/// Length of our cryptographic salt.
const SALT_LEN: usize = 16;
/// Length of our ersatz MAC.
const MAC_LEN: usize = 32;

impl<'a> HsDescEncryption<'a> {
    /// Length of our MAC key.
    const MAC_KEY_LEN: usize = 32;
    /// Length of the cipher key that we use.
    const CIPHER_KEY_LEN: usize = 32;
    /// Length of our cipher's IV.
    const IV_LEN: usize = 16;

    /// Encrypt a given bytestring using these encryption parameters.
    #[cfg(any(test, feature = "hs-service"))]
    pub(super) fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, data: &[u8]) -> Vec<u8> {
        let output_len = data.len() + SALT_LEN + MAC_LEN;
        let mut output = Vec::with_capacity(output_len);
        let salt: [u8; SALT_LEN] = rng.gen();

        let (mut cipher, mut mac) = self.init(&salt);

        output.extend_from_slice(&salt[..]);
        output.extend_from_slice(data);
        cipher.apply_keystream(&mut output[SALT_LEN..]);
        mac.update(&output[SALT_LEN..]);
        let mut mac_val = Default::default();
        mac.finalize_into(&mut mac_val);
        output.extend_from_slice(&mac_val);
        debug_assert_eq!(output.len(), output_len);

        output
    }
    /// Decrypt a given bytestring that was first encrypted using these
    /// encryption parameters.
    pub(super) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if data.len() < SALT_LEN + MAC_LEN {
            return Err(DecryptionError::default());
        }
        let msg_len = data.len() - SALT_LEN - MAC_LEN;

        let salt = data[0..SALT_LEN]
            .try_into()
            .expect("Failed try_into for 16-byte array.");
        let ciphertext = &data[SALT_LEN..(SALT_LEN + msg_len)];

        let expected_mac = CtByteArray::from(
            <[u8; MAC_LEN]>::try_from(&data[SALT_LEN + msg_len..SALT_LEN + msg_len + MAC_LEN])
                .expect("Failed try_into for 32-byte array."),
        );
        let (mut cipher, mut mac) = self.init(&salt);

        // check mac.
        mac.update(ciphertext);
        let mut received_mac = CtByteArray::from([0_u8; MAC_LEN]);
        mac.finalize_into(received_mac.as_mut().into());
        if received_mac != expected_mac {
            return Err(DecryptionError::default());
        }

        let mut decrypted = ciphertext.to_vec();
        cipher.apply_keystream(&mut decrypted[..]);

        Ok(decrypted)
    }

    /// Return the cryptographic objects that are used for en/decrypting and
    /// authenticating a HsDesc layer, given these parameters and a provided
    /// salt.
    ///
    /// Calculates `SECRET_KEY` and `SECRET_IV` (as `Cipher`) and `MAC_KEY` (as `Hash`)
    /// from rend-spec-v3 2.5.3 (`[HS-DESC-ENCRYPTION-KEYS]`).
    ///
    /// `Hash` is the required intermediate value in the calculation of `D_MAC`:
    /// It is in the state just after the `SALT` has been added;
    /// the ciphertext should be added, and then it should be finalized.
    fn init(&self, salt: &[u8; 16]) -> (Cipher, Hash) {
        let mut key_stream = self.get_kdf(salt).finalize_xof();

        let mut key = Z::new([0_u8; Self::CIPHER_KEY_LEN]);
        let mut iv = Z::new([0_u8; Self::IV_LEN]);
        let mut mac_key = Z::new([0_u8; Self::MAC_KEY_LEN]);
        key_stream.read(&mut key[..]);
        key_stream.read(&mut iv[..]);
        key_stream.read(&mut mac_key[..]);

        let cipher = Cipher::new(key.as_ref().into(), iv.as_ref().into());

        let mut mac = Hash::default();
        mac.update(&(Self::MAC_KEY_LEN as u64).to_be_bytes());
        mac.update(&mac_key[..]);
        mac.update(&(salt.len() as u64).to_be_bytes());
        mac.update(&salt[..]);

        (cipher, mac)
    }

    /// Return a KDF that can yield the keys to be used for encryption with
    /// these key parameters.
    ///
    /// Calculates `keys` from rend-spec-v3 2.5.3 (`[HS-DESC-ENCRYPTION-KEYS]`)
    /// as required for the two instantiations of `HS-DESC-ENCRYPTION-KEYS` in
    /// 2.5.1.1 ("First layer encryption logic") and 2.5.2.1 ("Second layer
    /// encryption logic").
    fn get_kdf(&self, salt: &[u8; 16]) -> KDF {
        let mut kdf = KDF::default();

        // secret_input = SECRET_DATA | N_hs_subcred | INT_8(revision_counter)
        //
        // (SECRET_DATA is always KP_blind_id (2.5.1.1), or KP_blind_id | N_hs_desc_nonce) (2.5.2.1).
        kdf.update(self.blinded_id.as_ref());
        if let Some(cookie) = self.desc_enc_nonce {
            kdf.update(cookie.as_ref());
        }
        kdf.update(self.subcredential.as_ref());
        kdf.update(&u64::from(self.revision).to_be_bytes());

        // keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
        kdf.update(salt);
        kdf.update(self.string_const);

        kdf
    }
}

/// An error that occurs when decrypting an onion service descriptor.
///
/// This error is deliberately uninformative, to avoid side channels.
#[non_exhaustive]
#[derive(Clone, Debug, Default, thiserror::Error)]
#[error("Unable to decrypt onion service descriptor.")]
pub struct DecryptionError {}

/// Create the CLIENT-ID and COOKIE-KEY required for hidden service client auth.
///
/// This is used by HS clients to decrypt the descriptor cookie from the onion service descriptor,
/// and by HS services to build the client-auth sections of descriptors.
///
/// Section 2.5.1.2. of rend-spec-v3 says:
/// ```text
///     SECRET_SEED = x25519(hs_y, client_X)
///                 = x25519(client_y, hs_X)
///     KEYS = KDF(N_hs_subcred | SECRET_SEED, 40)
///     CLIENT-ID = first 8 bytes of KEYS
///     COOKIE-KEY = last 32 bytes of KEYS
///
/// Where:
///     hs_{X,y} = K{P,S}_hss_desc_enc
///     client_{X,Y} = K{P,S}_hsc_desc_enc
/// ```
pub(crate) fn build_descriptor_cookie_key(
    our_secret_key: &StaticSecret,
    their_public_key: &PublicKey,
    subcredential: &Subcredential,
) -> (CtByteArray<8>, [u8; 32]) {
    let secret_seed = our_secret_key.diffie_hellman(their_public_key);
    let mut kdf = KDF::default();
    kdf.update(subcredential.as_ref());
    kdf.update(secret_seed.as_bytes());
    let mut keys = kdf.finalize_xof();
    let mut client_id = CtByteArray::from([0_u8; 8]);
    let mut cookie_key = [0_u8; 32];
    keys.read(client_id.as_mut());
    keys.read(&mut cookie_key);

    (client_id, cookie_key)
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

    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn roundtrip_basics() {
        let blinded_id = [7; 32].into();
        let subcredential = [11; 32].into();
        let revision = 13.into();
        let string_const = "greetings puny humans";
        let params = HsDescEncryption {
            blinded_id: &blinded_id,
            desc_enc_nonce: None,
            subcredential: &subcredential,
            revision,
            string_const: string_const.as_bytes(),
        };

        let mut rng = testing_rng();

        let bigmsg: Vec<u8> = (1..123).cycle().take(1021).collect();
        for message in [&b""[..], &b"hello world"[..], &bigmsg[..]] {
            let mut encrypted = params.encrypt(&mut rng, message);
            assert_eq!(encrypted.len(), message.len() + 48);
            let decrypted = params.decrypt(&encrypted[..]).unwrap();
            assert_eq!(message, &decrypted);

            // Make sure we can't decrypt a partial input.
            let decryption_err = params.decrypt(&encrypted[..encrypted.len() - 1]);
            assert!(decryption_err.is_err());
            // Frob a point in the encrypted form and ensure we won't decrypt.
            encrypted[7] ^= 3;
            let decryption_err = params.decrypt(&encrypted[..]);
            assert!(decryption_err.is_err());
        }
    }

    #[test]
    fn too_short() {
        let blinded_id = [7; 32].into();
        let subcredential = [11; 32].into();
        let revision = 13.into();
        let string_const = "greetings puny humans";
        let params = HsDescEncryption {
            blinded_id: &blinded_id,
            desc_enc_nonce: None,
            subcredential: &subcredential,
            revision,
            string_const: string_const.as_bytes(),
        };

        assert!(params.decrypt(b"").is_err());
        assert!(params.decrypt(&[0_u8; 47]).is_err());
    }
}
