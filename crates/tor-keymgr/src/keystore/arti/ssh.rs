//! Traits for converting keys to and from OpenSSH format.
//
// TODO #902: OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

use tor_error::internal;
use tor_key_forge::{ErasedKey, KeyType, SshKeyAlgorithm, SshKeyData};

use crate::Result;
use crate::keystore::arti::err::ArtiNativeKeystoreError;

use std::path::PathBuf;
use zeroize::Zeroizing;

/// An unparsed OpenSSH key.
///
/// Note: This is a wrapper around the contents of a file we think is an OpenSSH key. The inner
/// value is unchecked/unvalidated, and might not actually be a valid OpenSSH key.
///
/// The inner value is zeroed on drop.
pub(super) struct UnparsedOpenSshKey {
    /// The contents of an OpenSSH key file.
    inner: Zeroizing<String>,
    /// The path of the file (for error reporting).
    path: PathBuf,
}

/// Parse an OpenSSH key, returning its corresponding [`SshKeyData`].
macro_rules! parse_openssh {
    (PRIVATE $key:expr, $key_type:expr) => {{
        SshKeyData::try_from_keypair_data(parse_openssh!(
            $key,
            $key_type,
            ssh_key::private::PrivateKey::from_openssh
        ).key_data().clone())?
    }};

    (PUBLIC $key:expr, $key_type:expr) => {{
        SshKeyData::try_from_key_data(parse_openssh!(
            $key,
            $key_type,
            ssh_key::public::PublicKey::from_openssh
        ).key_data().clone())?
    }};

    ($key:expr, $key_type:expr, $parse_fn:path) => {{
        let key = $parse_fn(&*$key.inner).map_err(|e| {
            ArtiNativeKeystoreError::SshKeyParse {
                // TODO: rust thinks this clone is necessary because key.path is also used below (but
                // if we get to this point, we're going to return an error and never reach the other
                // error handling branches where we use key.path).
                path: $key.path.clone(),
                key_type: $key_type.clone().clone(),
                err: e.into(),
            }
        })?;

        let wanted_key_algo = ssh_algorithm($key_type)?;

        if SshKeyAlgorithm::from(key.algorithm()) != wanted_key_algo {
            return Err(ArtiNativeKeystoreError::UnexpectedSshKeyType {
                path: $key.path,
                wanted_key_algo,
                found_key_algo: key.algorithm().into(),
            }.into());
        }

        key
    }};
}

/// Get the algorithm of this key type.
fn ssh_algorithm(key_type: &KeyType) -> Result<SshKeyAlgorithm> {
    match key_type {
        KeyType::Ed25519Keypair | KeyType::Ed25519PublicKey => Ok(SshKeyAlgorithm::Ed25519),
        KeyType::X25519StaticKeypair | KeyType::X25519PublicKey => Ok(SshKeyAlgorithm::X25519),
        KeyType::Ed25519ExpandedKeypair => Ok(SshKeyAlgorithm::Ed25519Expanded),
        KeyType::RsaKeypair | KeyType::RsaPublicKey => Ok(SshKeyAlgorithm::Rsa),
        &_ => {
            Err(ArtiNativeKeystoreError::Bug(internal!("Unknown SSH key type {key_type:?}")).into())
        }
    }
}

impl UnparsedOpenSshKey {
    /// Create a new [`UnparsedOpenSshKey`].
    ///
    /// The contents of `inner` are erased on drop.
    pub(crate) fn new(inner: String, path: PathBuf) -> Self {
        Self {
            inner: Zeroizing::new(inner),
            path,
        }
    }

    /// Parse an OpenSSH key, convert the key material into a known key type, and return the
    /// type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    pub(crate) fn parse_ssh_format_erased(self, key_type: &KeyType) -> Result<ErasedKey> {
        match key_type {
            KeyType::Ed25519Keypair
            | KeyType::X25519StaticKeypair
            | KeyType::Ed25519ExpandedKeypair
            | KeyType::RsaKeypair => Ok(parse_openssh!(PRIVATE self, key_type).into_erased()?),
            KeyType::Ed25519PublicKey | KeyType::X25519PublicKey | KeyType::RsaPublicKey => {
                Ok(parse_openssh!(PUBLIC self, key_type).into_erased()?)
            }
            &_ => Err(ArtiNativeKeystoreError::Bug(internal!("Unknown SSH key type")).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::test_utils::ssh_keys::*;
    use crate::test_utils::sshkeygen_ed25519_strings;

    use tor_key_forge::{EncodableItem, KeystoreItem};
    use tor_llcrypto::pk::{curve25519, ed25519};

    use super::*;

    /// Comments used for the various keys. Should be kept in sync with the comments
    /// used in `maint/keygen-openssh-test/generate`, the fallback comment used in
    /// `maint/keygen-openssh-test/src/main.rs: make_openssh_key! {}`, and the
    /// comment used in `crate::test_utils::sshkeygen_ed25519_strings()`.
    const ED25519_OPENSSH_COMMENT: &str = "armadillo@example.com";
    const ED25519_EXPANDED_OPENSSH_COMMENT: &str = "armadillo@example.com";
    const X25519_OPENSSH_COMMENT: &str = "test-key";
    const ED25519_SSHKEYGEN_COMMENT: &str = "";

    /// Convenience trait for getting the underlying bytes for key types.
    trait ToBytes {
        type Bytes;
        fn to_bytes(&self) -> Self::Bytes;
    }

    impl ToBytes for ed25519::Keypair {
        type Bytes = [u8; 32];
        fn to_bytes(&self) -> Self::Bytes {
            self.to_bytes()
        }
    }

    impl ToBytes for ed25519::PublicKey {
        type Bytes = [u8; 32];
        fn to_bytes(&self) -> Self::Bytes {
            self.to_bytes()
        }
    }

    impl ToBytes for ed25519::ExpandedKeypair {
        type Bytes = [u8; 64];
        fn to_bytes(&self) -> Self::Bytes {
            self.to_secret_key_bytes()
        }
    }

    impl ToBytes for curve25519::StaticKeypair {
        type Bytes = [u8; 32];
        fn to_bytes(&self) -> Self::Bytes {
            self.secret.to_bytes()
        }
    }

    impl ToBytes for curve25519::PublicKey {
        type Bytes = [u8; 32];
        fn to_bytes(&self) -> Self::Bytes {
            self.to_bytes()
        }
    }

    /// In-memory mangling. Pass private or public ED25519 key.
    fn mangle_ed25519(key: &mut String) {
        if key.len() > 150 {
            // private
            key.replace_range(107..178, "hello");
        } else {
            // public
            key.insert_str(12, "garbage");
        }
    }

    /// This macro checks if the passed encoded key can be successfully parsed or not. For the
    /// encoded<1> keys that are successfully parsed and decoded<2>, the decoded<2> keys are
    /// re-encoded<3>, and these re-encoded<3> keys are re-decoded<4>. Then, it asserts that:
    ///
    /// * Encoded<1> and re-encoded<3> keys are the same.
    /// * Decoded<2> and re-decoded<4> keys are the same.
    macro_rules! test_parse_ssh_format_erased {
        ($key_ty:tt, $key:expr, err = $expect_err:expr) => {{
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new($key.into(), PathBuf::from("/dummy/path"));
            let err = key
                .parse_ssh_format_erased(&key_type)
                .map(|_| "<type erased key>")
                .unwrap_err();

            assert_eq!(err.to_string(), $expect_err);
        }};

        ($key_ty:tt, $enc1:expr, $expected_ty:path, $comment:expr) => {{
            let enc1 = $enc1.trim();
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new(enc1.into(), PathBuf::from("/test/path"));
            let erased_key = key.parse_ssh_format_erased(&key_type).unwrap();

            let Ok(dec1) = erased_key.downcast::<$expected_ty>() else {
                panic!("failed to downcast");
            };

            let keystore_item = EncodableItem::as_keystore_item(&*dec1).unwrap();
            let enc2 = match keystore_item {
                KeystoreItem::Key(key) => key.to_openssh_string($comment).unwrap(),
                _ => panic!("unexpected keystore item type {keystore_item:?}"),
            };
            let enc2 = enc2.trim();

            // TODO: From
            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2873#note_3178959:
            // > the problem is that the two keys have different checkint values. When a PrivateKey is
            // > parsed, its checkint is saved, and used when reencoding the key, so technically the
            // > checkints should be the same. However, arti only actually stores the underlying
            // > KeypairData and not the actual PrivateKey, so in SshKeyData::to_openssh_string, we
            // > create a brand new PrivateKey from that KeypairData, which winds up with a None
            // > checkint. When that PrivateKey then gets serialized, the checkint is taken from
            // > KeypairData::checkint, which isn't the same as the checkint ssh-keygen put in the
            // > original key. It's a weird implementation detail, but technically not a bug.
            match key_type {
                KeyType::Ed25519Keypair |
                KeyType::X25519StaticKeypair |
                KeyType::Ed25519ExpandedKeypair => (),
                _ => assert_eq!(enc1, enc2),
            }

            let key = UnparsedOpenSshKey::new(enc2.into(), PathBuf::from("/test/path"));
            let erased_key = key.parse_ssh_format_erased(&key_type).unwrap();
            let Ok(dec2) = erased_key.downcast::<$expected_ty>() else {
                panic!("failed to downcast");
            };

            assert_eq!(dec1.to_bytes(), dec2.to_bytes());
        }};
    }

    #[test]
    fn wrong_key_type() {
        let key_type = KeyType::Ed25519Keypair;
        let key = UnparsedOpenSshKey::new(DSA_OPENSSH.into(), PathBuf::from("/test/path"));
        let err = key
            .parse_ssh_format_erased(&key_type)
            .map(|_| "<type erased key>")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "Unexpected OpenSSH key type: wanted {}, found {}",
                SshKeyAlgorithm::Ed25519,
                SshKeyAlgorithm::Dsa
            )
        );

        test_parse_ssh_format_erased!(
            Ed25519Keypair,
            DSA_OPENSSH,
            err = format!(
                "Unexpected OpenSSH key type: wanted {}, found {}",
                SshKeyAlgorithm::Ed25519,
                SshKeyAlgorithm::Dsa
            )
        );
    }

    #[test]
    fn invalid_ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519Keypair,
            ED25519_OPENSSH_BAD,
            err = "Failed to parse OpenSSH with type Ed25519Keypair"
        );

        test_parse_ssh_format_erased!(
            Ed25519Keypair,
            ED25519_OPENSSH_BAD_PUB,
            err = "Failed to parse OpenSSH with type Ed25519Keypair"
        );

        test_parse_ssh_format_erased!(
            Ed25519PublicKey,
            ED25519_OPENSSH_BAD_PUB,
            err = "Failed to parse OpenSSH with type Ed25519PublicKey"
        );

        if let Ok((mut bad, mut bad_pub)) = sshkeygen_ed25519_strings() {
            mangle_ed25519(&mut bad);
            mangle_ed25519(&mut bad_pub);

            test_parse_ssh_format_erased!(
                Ed25519Keypair,
                &bad,
                err = "Failed to parse OpenSSH with type Ed25519Keypair"
            );

            test_parse_ssh_format_erased!(
                Ed25519Keypair,
                &bad_pub,
                err = "Failed to parse OpenSSH with type Ed25519Keypair"
            );

            test_parse_ssh_format_erased!(
                Ed25519PublicKey,
                &bad_pub,
                err = "Failed to parse OpenSSH with type Ed25519PublicKey"
            );
        }
    }

    #[test]
    fn ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519Keypair,
            ED25519_OPENSSH,
            ed25519::Keypair,
            ED25519_OPENSSH_COMMENT
        );
        test_parse_ssh_format_erased!(
            Ed25519PublicKey,
            ED25519_OPENSSH_PUB,
            ed25519::PublicKey,
            ED25519_OPENSSH_COMMENT
        );

        if let Ok((enc1, enc1_pub)) = sshkeygen_ed25519_strings() {
            test_parse_ssh_format_erased!(
                Ed25519Keypair,
                enc1,
                ed25519::Keypair,
                ED25519_SSHKEYGEN_COMMENT
            );
            test_parse_ssh_format_erased!(
                Ed25519PublicKey,
                enc1_pub,
                ed25519::PublicKey,
                ED25519_SSHKEYGEN_COMMENT
            );
        }
    }

    #[test]
    fn invalid_expanded_ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519ExpandedKeypair,
            ED25519_EXPANDED_OPENSSH_BAD,
            err = "Failed to parse OpenSSH with type Ed25519ExpandedKeypair"
        );
    }

    #[test]
    fn expanded_ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519ExpandedKeypair,
            ED25519_EXPANDED_OPENSSH,
            ed25519::ExpandedKeypair,
            ED25519_EXPANDED_OPENSSH_COMMENT
        );

        test_parse_ssh_format_erased!(
            Ed25519PublicKey,
            ED25519_EXPANDED_OPENSSH_PUB, // using ed25519-expanded for public keys doesn't make sense
            err = "Failed to parse OpenSSH with type Ed25519PublicKey"
        );
    }

    #[test]
    fn x25519_key() {
        test_parse_ssh_format_erased!(
            X25519StaticKeypair,
            X25519_OPENSSH,
            curve25519::StaticKeypair,
            X25519_OPENSSH_COMMENT
        );

        test_parse_ssh_format_erased!(
            X25519PublicKey,
            X25519_OPENSSH_PUB,
            curve25519::PublicKey,
            X25519_OPENSSH_COMMENT
        );
    }

    #[test]
    fn invalid_x25519_key() {
        test_parse_ssh_format_erased!(
            X25519StaticKeypair,
            X25519_OPENSSH_UNKNOWN_ALGORITHM,
            err = "Unexpected OpenSSH key type: wanted X25519, found pangolin@torproject.org"
        );

        test_parse_ssh_format_erased!(
            X25519PublicKey,
            X25519_OPENSSH_UNKNOWN_ALGORITHM, // Note: this is a private key
            err = "Failed to parse OpenSSH with type X25519PublicKey"
        );

        test_parse_ssh_format_erased!(
            X25519PublicKey,
            X25519_OPENSSH_UNKNOWN_ALGORITHM_PUB,
            err = "Unexpected OpenSSH key type: wanted X25519, found armadillo@torproject.org"
        );
    }
}
