//! Public-key cryptography for Tor.
//!
//! In old places, Tor uses RSA; newer Tor public-key cryptography is
//! based on curve25519 and ed25519.

pub mod ed25519;
pub mod keymanip;
pub mod rsa;

/// Re-exporting Curve25519 implementations.
///
/// *TODO*: Eventually we should probably recommend using this code via some
/// key-agreement trait, but for now we are just re-using the APIs from
/// [`x25519_dalek`].
pub mod curve25519 {
    use derive_deftly::Deftly;
    use educe::Educe;
    use subtle::ConstantTimeEq;

    use crate::util::ct::derive_deftly_template_PartialEqFromCtEq;
    use crate::util::rng::RngCompat;

    /// A keypair containing a [`StaticSecret`] and its corresponding public key.
    #[allow(clippy::exhaustive_structs)]
    #[derive(Clone, Educe)]
    #[educe(Debug)]
    pub struct StaticKeypair {
        /// The secret part of the key.
        #[educe(Debug(ignore))]
        pub secret: StaticSecret,
        /// The public part of this key.
        pub public: PublicKey,
    }

    /// A curve25519 secret key that can only be used once,
    /// and that can never be inspected.
    ///
    /// See [`x25519_dalek::EphemeralSecret`] for more information.
    pub struct EphemeralSecret(x25519_dalek::EphemeralSecret);

    /// A curve25519 secret key that can be used more than once,
    /// and whose value can be inspected.
    ///
    /// See [`x25519_dalek::StaticSecret`] for more information.
    //
    // TODO: We may want eventually want to expose ReusableSecret instead of
    // StaticSecret, for use in places where we need to use a single secret
    // twice in one handshake, but we do not need that secret to be persistent.
    //
    // The trouble here is that if we use ReusableSecret in these cases, we
    // cannot easily construct it for testing purposes.  We could in theory
    // kludge something together using a fake Rng, but that might be more
    // trouble than we want to go looking for.
    #[derive(Clone)]
    pub struct StaticSecret(x25519_dalek::StaticSecret);

    impl ConstantTimeEq for StaticSecret {
        fn ct_eq(&self, other: &Self) -> subtle::Choice {
            let Self { 0: self_secret } = self;
            let Self { 0: other_secret } = other;

            self_secret.as_bytes().ct_eq(other_secret.as_bytes())
        }
    }

    /// A curve15519 public key.
    ///
    /// See [`x25519_dalek::PublicKey`] for more information.
    #[derive(Clone, Copy, Debug, Eq, Deftly)]
    #[derive_deftly(PartialEqFromCtEq)]
    pub struct PublicKey(x25519_dalek::PublicKey);

    impl ConstantTimeEq for PublicKey {
        fn ct_eq(&self, other: &Self) -> subtle::Choice {
            let Self { 0: self_secret } = self;
            let Self { 0: other_secret } = other;

            self_secret.as_bytes().ct_eq(other_secret.as_bytes())
        }
    }

    /// A shared secret negotiated using curve25519.
    ///
    /// See [`x25519_dalek::SharedSecret`] for more information
    pub struct SharedSecret(x25519_dalek::SharedSecret);

    impl<'a> From<&'a EphemeralSecret> for PublicKey {
        fn from(secret: &'a EphemeralSecret) -> Self {
            Self((&secret.0).into())
        }
    }

    impl<'a> From<&'a StaticSecret> for PublicKey {
        fn from(secret: &'a StaticSecret) -> Self {
            Self((&secret.0).into())
        }
    }

    impl From<[u8; 32]> for StaticSecret {
        fn from(value: [u8; 32]) -> Self {
            Self(value.into())
        }
    }
    impl From<[u8; 32]> for PublicKey {
        fn from(value: [u8; 32]) -> Self {
            Self(value.into())
        }
    }

    impl EphemeralSecret {
        /// Return a new random ephemeral secret key.
        pub fn random_from_rng<R: rand_core::RngCore + rand_core::CryptoRng>(csprng: R) -> Self {
            Self(x25519_dalek::EphemeralSecret::random_from_rng(
                RngCompat::new(csprng),
            ))
        }
        /// Negotiate a shared secret using this secret key and a public key.
        pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
            SharedSecret(self.0.diffie_hellman(&their_public.0))
        }
    }
    impl StaticSecret {
        /// Return a new random static secret key.
        pub fn random_from_rng<R: rand_core::RngCore + rand_core::CryptoRng>(csprng: R) -> Self {
            Self(x25519_dalek::StaticSecret::random_from_rng(RngCompat::new(
                csprng,
            )))
        }
        /// Negotiate a shared secret using this secret key and a public key.
        pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
            SharedSecret(self.0.diffie_hellman(&their_public.0))
        }
        /// Return the bytes that represent this key.
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0.to_bytes()
        }
        /// Return a reference to the bytes that represent this key.
        pub fn as_bytes(&self) -> &[u8; 32] {
            self.0.as_bytes()
        }
    }
    impl SharedSecret {
        /// Return the shared secret as an array of bytes.
        pub fn as_bytes(&self) -> &[u8; 32] {
            self.0.as_bytes()
        }
        /// Return true if both keys contributed to this shared secret.
        ///
        /// See [`x25519_dalek::SharedSecret::was_contributory`] for more information.
        pub fn was_contributory(&self) -> bool {
            self.0.was_contributory()
        }
    }
    impl PublicKey {
        /// Return this public key as a reference to an array of bytes.
        pub fn as_bytes(&self) -> &[u8; 32] {
            self.0.as_bytes()
        }
        /// Return this public key as an array of bytes.
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0.to_bytes()
        }
    }
}

/// A type for a validatable signature.
///
/// It necessarily includes the signature, the public key, and (a hash
/// of?) the document being checked.
///
/// Having this trait enables us to write code for checking a large number
/// of validatable signatures in a way that permits batch signatures for
/// Ed25519.
///
/// To be used with [`validate_all_sigs`].
pub trait ValidatableSignature {
    /// Check whether this signature is a correct signature for the document.
    fn is_valid(&self) -> bool;

    /// Return this value as a validatable Ed25519 signature, if it is one.
    fn as_ed25519(&self) -> Option<&ed25519::ValidatableEd25519Signature> {
        None
    }
}

/// Check whether all of the signatures in this Vec are valid.
///
/// Return `true` if every signature is valid; return `false` if even
/// one is invalid.
///
/// This function should typically give the same result as just
/// calling `v.iter().all(ValidatableSignature::is_valid))`, while taking
/// advantage of batch verification to whatever extent possible.
///
/// (See [`ed25519::validate_batch`] for caveats.)
pub fn validate_all_sigs(v: &[Box<dyn ValidatableSignature>]) -> bool {
    // First we break out the ed25519 signatures (if any) so we can do
    // a batch-verification on them.
    let mut ed_sigs = Vec::new();
    let mut non_ed_sigs = Vec::new();
    for sig in v.iter() {
        match sig.as_ed25519() {
            Some(ed_sig) => ed_sigs.push(ed_sig),
            None => non_ed_sigs.push(sig),
        }
    }

    // Find out if the ed25519 batch is valid.
    let ed_batch_is_valid = crate::pk::ed25519::validate_batch(&ed_sigs[..]);

    // if so, verify the rest.
    ed_batch_is_valid && non_ed_sigs.iter().all(|b| b.is_valid())
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
    #[test]
    fn validatable_ed_sig() {
        use super::ValidatableSignature;
        use super::ed25519::{PublicKey, Signature, ValidatableEd25519Signature};
        use hex_literal::hex;
        let pk = PublicKey::from_bytes(&hex!(
            "fc51cd8e6218a1a38da47ed00230f058
             0816ed13ba3303ac5deb911548908025"
        ))
        .unwrap();
        let sig: Signature = hex!(
            "6291d657deec24024827e69c3abe01a3
             0ce548a284743a445e3680d7db5ac3ac
             18ff9b538d16f290ae67f760984dc659
             4a7c15e9716ed28dc027beceea1ec40a"
        )
        .into();

        let valid = ValidatableEd25519Signature::new(pk, sig, &hex!("af82"));
        let invalid = ValidatableEd25519Signature::new(pk, sig, &hex!("af83"));

        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }
}
