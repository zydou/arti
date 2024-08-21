//! Macros that can be used to improve your life with regards to crypto.

use derive_deftly::define_derive_deftly;

/// Create an ed25519 keypair wrapper given a visibility and a struct name.
///
/// # Syntax:
/// ```rust
/// define_ed25519_keypair( visibility, prefix )
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
/// use tor_keys::{define_ed25519_keypair, derive_deftly_template_Ed25519Keypair, Keygen};
/// use tor_llcrypto::pk::ValidatableSignature;
///
/// define_ed25519_keypair!(NonPublicSigning);
/// define_ed25519_keypair!(pub PublicSigning);
/// define_ed25519_keypair!(pub(crate) CratePublicSigning);
/// ```
///
/// The above results in `MySigningKeypair` and `MySigningPublicKey` struct being created and usable
/// with a series of useful methods.
///
/// You can then use these objects like so:
///
/// ```rust
/// use rand::Rng;
/// use tor_keys::{define_ed25519_keypair, derive_deftly_template_Ed25519Keypair, Keygen};
/// use tor_llcrypto::pk::ValidatableSignature;
///
/// define_ed25519_keypair!(MySigning);
///
/// let mut rng = rand::thread_rng();
/// let signing_kp = MySigningKeypair::generate(rng);
/// let signing_pubkey = signing_kp.public();
/// // Lets sign this wonderful message.
/// let message = "Bonjour".as_bytes();
/// let sig = signing_kp.sign(&message);
///
/// // You can then verify either directly with the keypair or the public key.
/// assert!(signing_kp.verify(sig, &message))
/// assert!(signing_pubkey.verify(sig, &message))
/// ```
#[macro_export]
macro_rules! define_ed25519_keypair {
    ($vis:vis $base_name:ident) => {
        paste::paste! {
            #[derive(Deftly)]
            #[derive_deftly(Ed25519Keypair)]
            #[deftly(kp(pubkey = $base_name "PublicKey"))]
            $vis struct [<$base_name "Keypair">](ed25519::Keypair);
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
    #[derive(Clone, Debug, derive_more::From, derive_more::Into, PartialEq, Eq)]
    $tvis struct $PK_NAME (ed25519::PublicKey);

    impl $PK_NAME {
        /// Verify the signature of a given message.
        #[allow(unused)]
        $tvis fn verify(&self, sig: ed25519::Signature, text: &[u8]) -> bool {
            ed25519::ValidatableEd25519Signature::new(self.0, sig, text).is_valid()
        }
    }

    impl $ttype {
        /// Build the raw inner public key into the wrapper public key object.
        $tvis fn public(&self) -> $PK_NAME {
            $PK_NAME((&self.$KP_NAME).into())
        }
        /// Generate the new keypair given a secure random number generator.
        $tvis fn generate<R>(rng: &mut R) -> Self
        where
            R: rand::Rng + rand::CryptoRng,
        {
            Self { $KP_NAME: ed25519::Keypair::generate(rng) }
        }
        /// Sign a given message.
        $tvis fn sign(&self, msg: &[u8]) -> ed25519::Signature {
            ed25519::ExpandedKeypair::from(&self.$KP_NAME).sign(msg)
        }
        /// Verify the signature of a given message.
        $tvis fn verify(&self, sig: ed25519::Signature, text: &[u8]) -> bool {
            ed25519::ValidatableEd25519Signature::new(self.public().0, sig, text).is_valid()
        }
    }

    impl From<ed25519::Keypair> for $ttype {
        fn from(kp: ed25519::Keypair) -> Self {
            Self(kp)
        }
    }

    // NOTE: Ultimately, this could also implement the tor-keymgr traits so we
    // could get all this for free with this macro. It would mean that automagically,
    // this keypair could be used with the keystore. Only the KeySpecifier would remain
    // for this type to be created which conviniently enough as a deftly macro already.
    //
    // We would need this whole macro into a new crate though specifically for
    // key declaration.
    //
    // Something like:
    //
    //  impl EncodableKey for $ttype {
    //      fn key_type() -> KeyType {
    //          $KP_TYPE.into()
    //      }
    //      fn as_ssh_key_data(&self) -> Result<SshKeyData> {
    //          self.$KP_NAME.as_ssh_key_data()
    //      }
    //  }
    //
    //  impl ToEncodableKey for $ttype {
    //      type Key = $KP_TYPE;
    //      fn to_encodable_key(self) -> Self::Key {
    //          self.$KP_NAME
    //      }
    //      fn from_encodable_key(key: Self::Key) -> Self {
    //          Self::new(key)
    //      }
    //  }
    //
    //  impl Keygen for $ttype {
    //      fn generate(rng: &mut dyn KeygenRng) -> Result<Self>
    //      where
    //          Self: Sized
    //      {
    //          Ok(Self::generate(rng))
    //      }
    //  }
}

#[cfg(test)]
mod test {
    use derive_deftly::Deftly;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_llcrypto::pk::{ed25519, ValidatableSignature};

    #[test]
    fn deftly_ed25519_keypair() {
        define_ed25519_keypair!(SomeEd25519);

        let mut rng = testing_rng();
        let kp = SomeEd25519Keypair::generate(&mut rng);

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
