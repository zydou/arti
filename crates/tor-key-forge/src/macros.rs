//! Macros that can be used to improve your life with regards to crypto.

use derive_deftly::define_derive_deftly;

// NOTE: We will require a define_rsa_keypair for the future so the relay legacy RSA keys can be
// declared.

/// Create an ed25519 keypair wrapper given a visibility and a struct name.
///
/// # Syntax:
/// ```rust,ignore
/// define_ed25519_keypair(<visibility> <prefix>)
/// ```
///
/// This macro creates a struct tuple named `<prefix>Keypair` which contains the lower-level
/// cryptographic keypair for an ed25519 keypair. It derives the deftly Ed25519Keypair template
/// which in turn creates `<prefix>PublicKey` along a series of useful methods.
///
/// The keypair is NOT clonable by design in order to avoid duplicating secret key material.
///
/// # Example:
///
/// ```rust
/// use tor_key_forge::define_ed25519_keypair;
///
/// define_ed25519_keypair!(NonPublicSigning);
/// define_ed25519_keypair!(pub PublicSigning);
/// define_ed25519_keypair!(pub(crate) CratePublicSigning);
/// ```
///
/// The above results in `NonPublicSigningKeypair` and `NonPublicSigningPublicKey` struct being
/// created and usable with a series of useful methods. Same for the other defines.
///
/// You can then use these objects like so:
///
/// ```rust
/// use rand::Rng;
/// use tor_key_forge::Keygen;
/// use tor_key_forge::define_ed25519_keypair;
/// use tor_llcrypto::pk::ValidatableSignature;
/// use tor_llcrypto::pk::ed25519::Signer;
///
/// define_ed25519_keypair!(
///     /// Our signing key.
///     MySigning
/// );
///
/// let mut rng = rand::thread_rng();
/// let signing_kp = MySigningKeypair::generate(&mut rng).expect("Invalid keygen");
/// let signing_pubkey = signing_kp.public();
/// // Lets sign this wonderful message.
/// let message = "Workers want rights, not your opinion".as_bytes();
/// let sig = signing_kp.sign(&message);
///
/// // You can then verify either directly with the keypair or the public key.
/// assert!(signing_kp.verify(sig, &message));
/// assert!(signing_pubkey.verify(sig, &message));
/// ```
#[macro_export]
macro_rules! define_ed25519_keypair {
    ($(#[ $docs_and_attrs:meta ])*
     $vis:vis $base_name:ident) => {
        $crate::macro_deps::paste! {
            #[derive($crate::derive_deftly::Deftly)]
            #[derive_deftly($crate::macro_deps::Ed25519Keypair)]
            #[deftly(kp(pubkey = $base_name "PublicKey"))]
            #[non_exhaustive]
            $(#[ $docs_and_attrs ])*
            $vis struct [<$base_name "Keypair">]($crate::macro_deps::ed25519::Keypair);
        }
    };
}

define_derive_deftly! {
    /// Implement set of helper functions around a type wrapping an ed25519::Keypair.
    export Ed25519Keypair for struct:

    // Enforce that the object has a single field. We want to avoid the implementer to start
    // storing metadata or other things in this object that is meant specifically to be
    // a semantic wrapper around an Ed25519 keypair.
    ${if not(approx_equal(${for fields { 1 }}, 1)) { ${error "Single field only"}}}

    ${define KP_NAME $( $fname )}
    ${define PK_NAME ${tmeta(kp(pubkey)) as ident}}

    /// Public key component of this keypair. Useful if we move the public key around,
    /// it then keeps it semantic with the name and less prone to errors.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[derive($crate::macro_deps::derive_more::From, $crate::macro_deps::derive_more::Into)]
    #[non_exhaustive]
    $tvis struct $PK_NAME ($tvis $crate::macro_deps::ed25519::PublicKey);

    impl $PK_NAME {
        /// Verify the signature of a given message.
        #[allow(unused)]
        $tvis fn verify(&self, sig: $crate::macro_deps::ed25519::Signature, text: &[u8]) -> bool {
            use $crate::macro_deps::ValidatableSignature;
            $crate::macro_deps::ed25519::ValidatableEd25519Signature::new(self.0, sig, text).is_valid()
        }
    }

    impl $crate::macro_deps::ed25519::Ed25519PublicKey for $PK_NAME {
        fn public_key(&self) -> &$crate::macro_deps::ed25519::PublicKey {
            &self.0
        }
    }

    // We don't expect all implementations to use all code.
    #[allow(unused)]
    impl $ttype {
        /// Build the raw inner public key into the wrapper public key object.
        $tvis fn public(&self) -> $PK_NAME {
            $PK_NAME((&self.$KP_NAME).into())
        }
        /// Verify the signature of a given message.
        $tvis fn verify(&self, sig: $crate::macro_deps::ed25519::Signature, text: &[u8]) -> bool {
            use $crate::macro_deps::ValidatableSignature;
            $crate::macro_deps::ed25519::ValidatableEd25519Signature::new(
                self.0.verifying_key(), sig, text
            ).is_valid()
        }
        /// Return a Ed25519Identity built from this keypair.
        $tvis fn to_ed25519_id(&self) -> $crate::macro_deps::ed25519::Ed25519Identity {
            $crate::macro_deps::ed25519::Ed25519Identity::from(&self.public().0)
        }
    }

    impl From<$crate::macro_deps::ed25519::Keypair> for $ttype {
        fn from(kp: $crate::macro_deps::ed25519::Keypair) -> Self {
            Self(kp)
        }
    }
    impl $crate::macro_deps::ed25519::Ed25519PublicKey for $ttype {
        fn public_key(&self) -> &$crate::macro_deps::ed25519::PublicKey {
            self.0.as_ref()
        }
    }

    impl $crate::macro_deps::ed25519::Signer<$crate::macro_deps::ed25519::Signature> for $ttype {
        fn try_sign(
            &self,
            msg: &[u8])
        -> Result<$crate::macro_deps::ed25519::Signature, $crate::macro_deps::signature::Error> {
            self.0.try_sign(msg)
        }
    }

    /// Implementing EncodableItem, ToEncodableKey and Keygen allows this wrapper key to be stored
    /// in a keystore.

    impl $crate::EncodableItem for $ttype {
        fn item_type() -> $crate::KeystoreItemType {
            $crate::KeyType::Ed25519Keypair.into()
        }
        fn as_ssh_key_data(&self) -> $crate::Result<$crate::SshKeyData> {
            self.$KP_NAME.as_ssh_key_data()
        }
    }

    impl $crate::ToEncodableKey for $ttype {
        type Key = $crate::macro_deps::ed25519::Keypair;
        type KeyPair = $ttype;

        fn to_encodable_key(self) -> Self::Key {
            self.$KP_NAME
        }
        fn from_encodable_key(key: Self::Key) -> Self {
            Self(key)
        }
    }

    impl $crate::Keygen for $ttype {
        fn generate(mut rng: &mut dyn $crate::KeygenRng) -> $crate::Result<Self>
        where
            Self: Sized
        {
            Ok(Self { $KP_NAME: $crate::macro_deps::ed25519::Keypair::generate(&mut rng) })
        }
    }
}

/// Create a curve25519 keypair wrapper given a visibility and a struct name.
///
/// # Syntax:
/// ```rust,ignore
/// define_curve25519_keypair(<visibility> <prefix>)
/// ```
///
/// This macro creates a struct tuple named `<prefix>Keypair` which contains the lower-level
/// cryptographic keypair for a curve25519 keypair. It derives the deftly Curve25519Keypair template
/// which in turn creates `<prefix>PublicKey` along a series of useful methods.
///
/// The keypair is NOT clonable by design in order to avoid duplicating secret key material.
///
/// # Example:
///
/// ```rust
/// use tor_key_forge::define_curve25519_keypair;
///
/// define_curve25519_keypair!(NonPublicEnc);
/// define_curve25519_keypair!(pub PublicEnc);
/// define_curve25519_keypair!(pub(crate) CratePublicEnc);
/// ```
///
/// The above results in `NonPublicEncKeypair` and `NonPublicEncPublicKey` struct being created and
/// usable with a series of useful methods.
///
/// You can then use these objects like so:
///
/// ```rust
/// use rand::Rng;
/// use tor_key_forge::define_curve25519_keypair;
/// use tor_key_forge::Keygen;
///
/// define_curve25519_keypair!(
///     // This is Alice's keypair.
///     AliceEnc
/// );
/// define_curve25519_keypair!(BobEnc);
///
/// let mut rng = rand::thread_rng();
/// let alice_kp = AliceEncKeypair::generate(&mut rng).expect("Failed alice keygen");
/// let bob_kp = BobEncKeypair::generate(&mut rng).expect("Failed bob keygen");
///
/// // Using the public key wrapper
/// let alice_shared_secret = alice_kp.diffie_hellman(bob_kp.public());
/// // Using the direct curve25519::PublicKey.
/// let bob_shared_secret = bob_kp.diffie_hellman(&alice_kp.public().0);
///
/// assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
/// ```
#[macro_export]
macro_rules! define_curve25519_keypair {
    ($(#[ $docs_and_attrs:meta ])*
    $vis:vis $base_name:ident) => {
        $crate::macro_deps::paste! {
            #[derive($crate::derive_deftly::Deftly)]
            #[derive_deftly($crate::macro_deps::Curve25519Keypair)]
            #[deftly(kp(pubkey = $base_name "PublicKey"))]
            #[non_exhaustive]
            $(#[ $docs_and_attrs ])*
            $vis struct [<$base_name "Keypair">]($crate::macro_deps::curve25519::StaticKeypair);
        }
    };
}

define_derive_deftly! {
    /// Implement set of helper functions around a type wrapping an ed25519::Keypair.
    export Curve25519Keypair for struct:

    // Enforce that the object has a single field. We want to avoid the implementer to start
    // storing metadata or other things in this object that is meant specifically to be
    // a semantic wrapper around an Curve25519 keypair.
    ${if not(approx_equal(${for fields { 1 }}, 1)) { ${error "Single field only"}}}

    ${define KP_NAME $( $fname )}
    ${define PK_NAME ${tmeta(kp(pubkey)) as ident}}

    /// Public key component of this keypair. Useful if we move the public key around,
    /// it then keeps it semantic with the name and less prone to errors.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[derive($crate::macro_deps::derive_more::From, $crate::macro_deps::derive_more::Into)]
    #[non_exhaustive]
    $tvis struct $PK_NAME ($crate::macro_deps::curve25519::PublicKey);

    impl std::borrow::Borrow<$crate::macro_deps::curve25519::PublicKey> for $PK_NAME {
        #[inline]
        fn borrow(&self) -> &$crate::macro_deps::curve25519::PublicKey {
            &self.0
        }
    }

    impl $ttype {
        /// Build the raw inner public key into the wrapper public key object.
        $tvis fn public(&self) -> $PK_NAME {
            $PK_NAME(self.$KP_NAME.public.clone())
        }

        /// Wrapper around the diffie_hellman() function of the underlying type. This is pretty fun
        /// because it accepts both the PK_NAME wrapper or the raw inner curve25519::PublicKey.
        $tvis fn diffie_hellman<T>(&self, pk: T) -> $crate::macro_deps::curve25519::SharedSecret
        where
            T: std::borrow::Borrow<$crate::macro_deps::curve25519::PublicKey>
        {
            self.$KP_NAME.secret.diffie_hellman(pk.borrow())
        }
    }

    impl From<$crate::macro_deps::curve25519::StaticKeypair> for $ttype {
        fn from(kp: $crate::macro_deps::curve25519::StaticKeypair) -> Self {
            Self(kp)
        }
    }

    /// Implementing EncodableItem, ToEncodableKey and Keygen allows this wrapper key to be stored
    /// in a keystore.

    impl $crate::EncodableItem for $ttype {
        fn item_type() -> $crate::KeystoreItemType {
            $crate::KeyType::X25519StaticKeypair.into()
        }
        fn as_ssh_key_data(&self) -> $crate::Result<$crate::SshKeyData> {
            self.$KP_NAME.as_ssh_key_data()
        }
    }

    impl $crate::ToEncodableKey for $ttype {
        type Key = $crate::macro_deps::curve25519::StaticKeypair;
        type KeyPair = $ttype;

        fn to_encodable_key(self) -> Self::Key {
            self.$KP_NAME
        }
        fn from_encodable_key(key: Self::Key) -> Self {
            Self(key)
        }
    }

    impl $crate::Keygen for $ttype {
        fn generate(mut rng: &mut dyn $crate::KeygenRng) -> $crate::Result<Self>
        where
            Self: Sized
        {
            let secret = $crate::macro_deps::curve25519::StaticSecret::random_from_rng(rng);
            let public: $crate::macro_deps::curve25519::PublicKey = (&secret).into();
            let kp = $crate::macro_deps::curve25519::StaticKeypair {
                secret: secret.into(),
                public: public.into(),
            };
            Ok(kp.into())
        }
    }
}

// Re-export dependencies as `tor_key_forge::macro_deps` that we use to make this macro work.
#[doc(hidden)]
pub mod deps {
    pub use derive_deftly_template_Curve25519Keypair;
    pub use derive_deftly_template_Ed25519Keypair;
    pub use derive_more;
    pub use paste::paste;
    pub use signature;
    pub use tor_llcrypto::pk::{curve25519, ed25519, ValidatableSignature};
}

#[cfg(test)]
mod test {
    use crate::Keygen;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_llcrypto::pk::ed25519::Signer;

    #[test]
    fn deftly_ed25519_keypair() {
        define_ed25519_keypair!(SomeEd25519);

        let mut rng = testing_rng();
        let kp = SomeEd25519Keypair::generate(&mut rng).expect("Failed to gen key");

        // Make sure the generated public key from our wrapper is the same as the
        // underlying keypair.
        let pubkey = kp.public();
        assert_eq!(pubkey.0, kp.0.verifying_key());

        // Message to sign and verify.
        let msg: [u8; 4] = [2, 3, 4, 5];
        let msg_bad: [u8; 4] = [2, 3, 4, 6];

        let sig = kp.sign(msg.as_slice());
        assert!(kp.verify(sig, msg.as_slice()));
        // Lets make sure we don't validate another message.
        assert!(!kp.verify(sig, msg_bad.as_slice()));
    }
}
