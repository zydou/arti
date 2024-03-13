//! Key derivation functions
//!
//! Tor has three relevant key derivation functions that we use for
//! deriving keys used for relay encryption.
//!
//! The *KDF-TOR* KDF (implemented by `LegacyKdf`) is used with the old
//! TAP handshake.  It is ugly, it is based on SHA-1, and it should be
//! avoided for new uses.
//!
//! The *HKDF-SHA256* KDF (implemented by `Ntor1Kdf`) is used with the
//! Ntor handshake.  It is based on RFC5869 and SHA256.
//!
//! The *SHAKE* KDF (implemented by `ShakeKdf` is used with v3 onion
//! services, and is likely to be used by other places in the future.
//! It is based on SHAKE-256.

use crate::{Error, Result};
use digest::{ExtendableOutput, Update, XofReader};
use tor_bytes::SecretBuf;
use tor_llcrypto::d::{Sha1, Sha256, Shake256};
use zeroize::Zeroize;

/// A trait for a key derivation function.
pub(crate) trait Kdf {
    /// Derive `n_bytes` of key data from some secret `seed`.
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf>;
}

/// A legacy KDF, for use with TAP.
///
/// This KDF is based on SHA1.  Don't use this for anything new.
pub(crate) struct LegacyKdf {
    /// Starting index value for the TAP kdf.  should always be 1.
    idx: u8,
}

/// A parameterized KDF, for use with ntor.
///
/// This KDF is based on HKDF-SHA256.
pub(crate) struct Ntor1Kdf<'a, 'b> {
    /// A constant for parameterizing the kdf, during the key extraction
    /// phase.
    t_key: &'a [u8],
    /// Another constant for parameterizing the kdf, during the key
    /// expansion phase.
    m_expand: &'b [u8],
}

/// A modern KDF, for use with v3 onion services.
///
/// This KDF is based on SHAKE256
pub(crate) struct ShakeKdf();

impl LegacyKdf {
    /// Instantiate a LegacyKdf.
    pub(crate) fn new(idx: u8) -> Self {
        LegacyKdf { idx }
    }
}
impl Kdf for LegacyKdf {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf> {
        use digest::Digest;

        let mut result = SecretBuf::with_capacity(n_bytes + Sha1::output_size());
        let mut k = self.idx;
        if n_bytes > Sha1::output_size() * (256 - (k as usize)) {
            return Err(Error::InvalidKDFOutputLength);
        }

        let mut digest_output = Default::default();
        while result.len() < n_bytes {
            let mut d = Sha1::new();
            Digest::update(&mut d, seed);
            Digest::update(&mut d, [k]);
            d.finalize_into(&mut digest_output);
            result.extend_from_slice(&digest_output);
            k += 1;
        }
        digest_output.zeroize();

        result.truncate(n_bytes);
        Ok(result)
    }
}

impl<'a, 'b> Ntor1Kdf<'a, 'b> {
    /// Instantiate an Ntor1Kdf, with given values for t_key and m_expand.
    pub(crate) fn new(t_key: &'a [u8], m_expand: &'b [u8]) -> Self {
        Ntor1Kdf { t_key, m_expand }
    }
}

impl Kdf for Ntor1Kdf<'_, '_> {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf> {
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(self.t_key), seed);

        let mut result: SecretBuf = vec![0; n_bytes].into();
        hkdf.expand(self.m_expand, result.as_mut())
            .map_err(|_| Error::InvalidKDFOutputLength)?;
        Ok(result)
    }
}

impl ShakeKdf {
    /// Instantiate a ShakeKdf.
    pub(crate) fn new() -> Self {
        ShakeKdf()
    }
}
impl Kdf for ShakeKdf {
    fn derive(&self, seed: &[u8], n_bytes: usize) -> Result<SecretBuf> {
        let mut xof = Shake256::default();
        xof.update(seed);
        let mut result: SecretBuf = vec![0; n_bytes].into();
        xof.finalize_xof().read(result.as_mut());
        Ok(result)
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
    use super::*;
    use hex_literal::hex;

    #[test]
    fn clearbox_tap_kdf() {
        // Calculate an instance of the TAP KDF, based on its spec in
        // tor-spec.txt.
        use digest::Digest;
        let input = b"here is an example key seed that we will expand";
        let result = LegacyKdf::new(6).derive(input, 99).unwrap();

        let mut expect_result = Vec::new();
        let mut k0: Vec<u8> = Vec::new();
        k0.extend(&input[..]);
        for x in 6..11 {
            k0.push(x);
            expect_result.extend(Sha1::digest(&k0));
            k0.pop();
        }
        expect_result.truncate(99);

        assert_eq!(&result[..], &expect_result[..]);
    }

    #[test]
    fn testvec_tap_kdf() {
        // Taken from test_crypto.c in Tor, generated by a python script.
        fn expand(b: &[u8]) -> SecretBuf {
            LegacyKdf::new(0).derive(b, 100).unwrap()
        }

        let expect = hex!(
            "5ba93c9db0cff93f52b521d7420e43f6eda2784fbf8b4530d8
             d246dd74ac53a13471bba17941dff7c4ea21bb365bbeeaf5f2
             c654883e56d11e43c44e9842926af7ca0a8cca12604f945414
             f07b01e13da42c6cf1de3abfdea9b95f34687cbbe92b9a7383"
        );
        assert_eq!(&expand(&b""[..])[..], &expect[..]);

        let expect = hex!(
            "776c6214fc647aaa5f683c737ee66ec44f03d0372e1cce6922
             7950f236ddf1e329a7ce7c227903303f525a8c6662426e8034
             870642a6dabbd41b5d97ec9bf2312ea729992f48f8ea2d0ba8
             3f45dfda1a80bdc8b80de01b23e3e0ffae099b3e4ccf28dc28"
        );
        assert_eq!(&expand(&b"Tor"[..])[..], &expect[..]);

        let brunner_quote = b"AN ALARMING ITEM TO FIND ON A MONTHLY AUTO-DEBIT NOTICE";
        let expect = hex!(
            "a340b5d126086c3ab29c2af4179196dbf95e1c72431419d331
             4844bf8f6afb6098db952b95581fb6c33625709d6f4400b8e7
             ace18a70579fad83c0982ef73f89395bcc39493ad53a685854
             daf2ba9b78733b805d9a6824c907ee1dba5ac27a1e466d4d10"
        );
        assert_eq!(&expand(&brunner_quote[..])[..], &expect[..]);
    }

    #[test]
    fn fail_tap_kdf() {
        let result = LegacyKdf::new(6).derive(&b"x"[..], 10000);
        assert!(result.is_err());
    }

    #[test]
    fn clearbox_ntor1_kdf() {
        // Calculate Ntor1Kdf, and make sure we get the same result by
        // following the calculation in the spec.
        let input = b"another example key seed that we will expand";
        let result = Ntor1Kdf::new(&b"key"[..], &b"expand"[..])
            .derive(input, 99)
            .unwrap();

        let kdf = hkdf::Hkdf::<Sha256>::new(Some(&b"key"[..]), &input[..]);
        let mut expect_result = vec![0_u8; 99];
        kdf.expand(&b"expand"[..], &mut expect_result[..]).unwrap();

        assert_eq!(&expect_result[..], &result[..]);
    }

    #[test]
    fn testvec_ntor1_kdf() {
        // From Tor's test_crypto.c; generated with ntor_ref.py
        fn expand(b: &[u8]) -> SecretBuf {
            let t_key = b"ntor-curve25519-sha256-1:key_extract";
            let m_expand = b"ntor-curve25519-sha256-1:key_expand";
            Ntor1Kdf::new(&t_key[..], &m_expand[..])
                .derive(b, 100)
                .unwrap()
        }

        let expect = hex!(
            "5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6
             c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d
             66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3
             961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac"
        );
        assert_eq!(&expand(&b"Tor"[..])[..], &expect[..]);

        let brunner_quote = b"AN ALARMING ITEM TO FIND ON YOUR CREDIT-RATING STATEMENT";
        let expect = hex!(
            "a2aa9b50da7e481d30463adb8f233ff06e9571a0ca6ab6df0f
             b206fa34e5bc78d063fc291501beec53b36e5a0e434561200c
             5f8bd13e0f88b3459600b4dc21d69363e2895321c06184879d
             94b18f078411be70b767c7fc40679a9440a0c95ea83a23efbf"
        );
        assert_eq!(&expand(&brunner_quote[..])[..], &expect[..]);
    }

    #[test]
    fn testvec_shake_kdf() {
        // This is just one of the shake test vectors from tor-llcrypto
        let input = hex!(
            "76891a7bcc6c04490035b743152f64a8dd2ea18ab472b8d36ecf45
             858d0b0046"
        );
        let expected = hex!(
            "e8447df87d01beeb724c9a2a38ab00fcc24e9bd17860e673b02122
             2d621a7810e5d3"
        );

        let result = ShakeKdf::new().derive(&input[..], expected.len());
        assert_eq!(&result.unwrap()[..], &expected[..]);
    }
}
