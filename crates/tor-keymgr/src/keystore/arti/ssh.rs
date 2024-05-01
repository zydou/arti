//! Traits for converting keys to and from OpenSSH format.
//
// TODO #902: OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

use crate::keystore::arti::err::ArtiNativeKeystoreError;
use crate::ssh::SshKeyAlgorithm;
use crate::{ErasedKey, KeyType, Result, SshKeyData};

use zeroize::Zeroizing;

use std::path::PathBuf;

use crate::UnknownKeyTypeError;

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
        KeyType::Unknown { arti_extension } => Err(ArtiNativeKeystoreError::UnknownKeyType(
            UnknownKeyTypeError {
                arti_extension: arti_extension.clone(),
            },
        )
        .into()),
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
            | KeyType::Ed25519ExpandedKeypair => {
                parse_openssh!(PRIVATE self, key_type).into_erased()
            }
            KeyType::Ed25519PublicKey | KeyType::X25519PublicKey => {
                parse_openssh!(PUBLIC self, key_type).into_erased()
            }
            KeyType::Unknown { arti_extension } => Err(ArtiNativeKeystoreError::UnknownKeyType(
                UnknownKeyTypeError {
                    arti_extension: arti_extension.clone(),
                },
            )
            .into()),
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::test_utils::ssh_keys::*;

    use tor_llcrypto::pk::{curve25519, ed25519};

    use super::*;

    macro_rules! test_parse_ssh_format_erased {
        ($key_ty:tt, $key:expr, $expected_ty:path) => {{
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new($key.into(), PathBuf::from("/test/path"));
            let erased_key = key.parse_ssh_format_erased(&key_type).unwrap();

            assert!(erased_key.downcast::<$expected_ty>().is_ok());
        }};

        ($key_ty:tt, $key:expr, err = $expect_err:expr) => {{
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new($key.into(), PathBuf::from("/dummy/path"));
            let err = key
                .parse_ssh_format_erased(&key_type)
                .map(|_| "<type erased key>")
                .unwrap_err();

            assert_eq!(err.to_string(), $expect_err);
        }};
    }

    #[test]
    fn wrong_key_type() {
        let key_type = KeyType::Ed25519Keypair;
        let key = UnparsedOpenSshKey::new(OPENSSH_DSA.into(), PathBuf::from("/test/path"));
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
            OPENSSH_DSA,
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
            OPENSSH_ED25519_BAD,
            err = "Failed to parse OpenSSH with type Ed25519Keypair"
        );

        test_parse_ssh_format_erased!(
            Ed25519Keypair,
            OPENSSH_ED25519_PUB_BAD,
            err = "Failed to parse OpenSSH with type Ed25519Keypair"
        );

        test_parse_ssh_format_erased!(
            Ed25519PublicKey,
            OPENSSH_ED25519_PUB_BAD,
            err = "Failed to parse OpenSSH with type Ed25519PublicKey"
        );
    }

    #[test]
    fn ed25519_key() {
        test_parse_ssh_format_erased!(Ed25519Keypair, OPENSSH_ED25519, ed25519::Keypair);
        test_parse_ssh_format_erased!(Ed25519PublicKey, OPENSSH_ED25519_PUB, ed25519::PublicKey);
    }

    #[test]
    fn invalid_expanded_ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519ExpandedKeypair,
            OPENSSH_EXP_ED25519_BAD,
            err = "Failed to parse OpenSSH with type Ed25519ExpandedKeypair"
        );
    }

    #[test]
    fn expanded_ed25519_key() {
        test_parse_ssh_format_erased!(
            Ed25519ExpandedKeypair,
            OPENSSH_EXP_ED25519,
            ed25519::ExpandedKeypair
        );

        test_parse_ssh_format_erased!(
            Ed25519PublicKey,
            OPENSSH_EXP_ED25519_PUB, // using ed25519-expanded for public keys doesn't make sense
            err = "Failed to parse OpenSSH with type Ed25519PublicKey"
        );
    }

    #[test]
    fn x25519_key() {
        test_parse_ssh_format_erased!(
            X25519StaticKeypair,
            OPENSSH_X25519,
            curve25519::StaticKeypair
        );

        test_parse_ssh_format_erased!(X25519PublicKey, OPENSSH_X25519_PUB, curve25519::PublicKey);
    }

    #[test]
    fn invalid_x25519_key() {
        test_parse_ssh_format_erased!(
            X25519StaticKeypair,
            OPENSSH_X25519_UNKNOWN_ALGORITHM,
            err = "Unexpected OpenSSH key type: wanted X25519, found pangolin@torproject.org"
        );

        test_parse_ssh_format_erased!(
            X25519PublicKey,
            OPENSSH_X25519_UNKNOWN_ALGORITHM, // Note: this is a private key
            err = "Failed to parse OpenSSH with type X25519PublicKey"
        );

        test_parse_ssh_format_erased!(
            X25519PublicKey,
            OPENSSH_X25519_PUB_UNKNOWN_ALGORITHM,
            err = "Unexpected OpenSSH key type: wanted X25519, found armadillo@torproject.org"
        );
    }
}
