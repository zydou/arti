//! Traits for converting keys to and from OpenSSH format.
//
// TODO #902: OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::Algorithm;

use crate::keystore::arti::err::ArtiNativeKeystoreError;
use crate::{ErasedKey, KeyType, Result};

use tor_llcrypto::pk::{curve25519, ed25519};
use zeroize::Zeroizing;

use std::path::PathBuf;

use super::UnknownKeyTypeError;

/// The algorithm string for x25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const X25519_ALGORITHM_NAME: &str = "x25519@spec.torproject.org";

/// The algorithm string for expanded ed25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const ED25519_EXPANDED_ALGORITHM_NAME: &str = "ed25519-expanded@spec.torproject.org";

/// An unparsed OpenSSH key.
///
/// Note: This is a wrapper around the contents of a file we think is an OpenSSH key. The inner
/// value is unchecked/unvalidated, and might not actually be a valid OpenSSH key.
///
/// The inner value is zeroed on drop.
pub(crate) struct UnparsedOpenSshKey {
    /// The contents of an OpenSSH key file.
    inner: Zeroizing<String>,
    /// The path of the file (for error reporting).
    path: PathBuf,
}

/// Parse an OpenSSH key, returning its underlying [`KeyData`], if it's a public key, or
/// [`KeypairData`], if it's a private one.
macro_rules! parse_openssh {
    (PRIVATE $key:expr, $key_type:expr) => {{
        parse_openssh!(
            $key,
            $key_type,
            ssh_key::private::PrivateKey::from_openssh,
            convert_ed25519_kp,
            convert_expanded_ed25519_kp,
            convert_x25519_kp,
            KeypairData
        )
    }};

    (PUBLIC $key:expr, $key_type:expr) => {{
        parse_openssh!(
            $key,
            $key_type,
            ssh_key::public::PublicKey::from_openssh,
            convert_ed25519_pk,
            convert_expanded_ed25519_pk,
            convert_x25519_pk,
            KeyData
        )
    }};

    ($key:expr, $key_type:expr, $parse_fn:path, $ed25519_fn:path, $expanded_ed25519_fn:path, $x25519_fn:path, $key_data_ty:tt) => {{
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

        let wanted_key_algo = $key_type.ssh_algorithm()?;

        if SshKeyAlgorithm::from(key.algorithm()) != wanted_key_algo {
            return Err(ArtiNativeKeystoreError::UnexpectedSshKeyType {
                path: $key.path,
                wanted_key_algo,
                found_key_algo: key.algorithm().into(),
            }.into());
        }

        // Build the expected key type (i.e. convert ssh_key key types to the key types
        // we're using internally).
        match key.key_data() {
            $key_data_ty::Ed25519(key) => Ok($ed25519_fn(key).map(Box::new)?),
            $key_data_ty::Other(other) => {
                match SshKeyAlgorithm::from(key.algorithm()) {
                    SshKeyAlgorithm::X25519 => Ok($x25519_fn(other).map(Box::new)?),
                    SshKeyAlgorithm::Ed25519Expanded => Ok($expanded_ed25519_fn(other).map(Box::new)?),
                    _ => {
                        Err(ArtiNativeKeystoreError::UnexpectedSshKeyType {
                            path: $key.path,
                            wanted_key_algo,
                            found_key_algo: key.algorithm().into(),
                        }.into())
                    }
                }
            }
            _ => Err(ArtiNativeKeystoreError::UnexpectedSshKeyType {
                path: $key.path,
                wanted_key_algo,
                found_key_algo: key.algorithm().into(),
            }.into())
        }
    }};
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
}

/// SSH key algorithms.
//
// Note: this contains all the types supported by ssh_key, plus variants representing
// x25519 and expanded ed25519 keys.
#[derive(Clone, Debug, PartialEq, derive_more::Display)]
pub(crate) enum SshKeyAlgorithm {
    /// Digital Signature Algorithm
    Dsa,
    /// Elliptic Curve Digital Signature Algorithm
    Ecdsa,
    /// Ed25519
    Ed25519,
    /// Expanded Ed25519
    Ed25519Expanded,
    /// X25519
    X25519,
    /// RSA
    Rsa,
    /// FIDO/U2F key with ECDSA/NIST-P256 + SHA-256
    SkEcdsaSha2NistP256,
    /// FIDO/U2F key with Ed25519
    SkEd25519,
    /// An unrecognized [`ssh_key::Algorithm`].
    Unknown(ssh_key::Algorithm),
}

impl From<Algorithm> for SshKeyAlgorithm {
    fn from(algo: Algorithm) -> SshKeyAlgorithm {
        match &algo {
            Algorithm::Dsa => SshKeyAlgorithm::Dsa,
            Algorithm::Ecdsa { .. } => SshKeyAlgorithm::Ecdsa,
            Algorithm::Ed25519 => SshKeyAlgorithm::Ed25519,
            Algorithm::Rsa { .. } => SshKeyAlgorithm::Rsa,
            Algorithm::SkEcdsaSha2NistP256 => SshKeyAlgorithm::SkEcdsaSha2NistP256,
            Algorithm::SkEd25519 => SshKeyAlgorithm::SkEd25519,
            Algorithm::Other(name) => match name.as_str() {
                X25519_ALGORITHM_NAME => SshKeyAlgorithm::X25519,
                ED25519_EXPANDED_ALGORITHM_NAME => SshKeyAlgorithm::Ed25519Expanded,
                _ => SshKeyAlgorithm::Unknown(algo),
            },
            // Note: ssh_key::Algorithm is non_exhaustive, so we need this catch-all variant
            _ => SshKeyAlgorithm::Unknown(algo),
        }
    }
}

/// Try to convert an [`Ed25519Keypair`](ssh_key::private::Ed25519Keypair) to an [`ed25519::Keypair`].
// TODO remove this allow?
// clippy wants this whole function to be infallible because
// nowadays ed25519::Keypair can be made infallibly from bytes,
// but is that really right?
#[allow(clippy::unnecessary_fallible_conversions)]
fn convert_ed25519_kp(key: &ssh_key::private::Ed25519Keypair) -> Result<ed25519::Keypair> {
    Ok(ed25519::Keypair::try_from(&key.private.to_bytes())
        .map_err(|_| ArtiNativeKeystoreError::InvalidSshKeyData("bad ed25519 keypair".into()))?)
}

/// Try to convert an [`OpaqueKeypair`](ssh_key::private::OpaqueKeypair) to a [`curve25519::StaticKeypair`].
fn convert_x25519_kp(key: &ssh_key::private::OpaqueKeypair) -> Result<curve25519::StaticKeypair> {
    let public: [u8; 32] = key.public.as_ref().try_into().map_err(|_| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad x25519 public key length".into())
    })?;

    let secret: [u8; 32] = key.private.as_ref().try_into().map_err(|_| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad x25519 secret key length".into())
    })?;

    Ok(curve25519::StaticKeypair {
        public: public.into(),
        secret: secret.into(),
    })
}

/// Try to convert an [`OpaqueKeypair`](ssh_key::private::OpaqueKeypair) to an [`ed25519::ExpandedKeypair`].
fn convert_expanded_ed25519_kp(
    key: &ssh_key::private::OpaqueKeypair,
) -> Result<ed25519::ExpandedKeypair> {
    let public = ed25519::PublicKey::try_from(key.public.as_ref()).map_err(|_| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad expanded ed25519 public key ".into())
    })?;

    let keypair = ed25519::ExpandedKeypair::from_secret_key_bytes(
        key.private.as_ref().try_into().map_err(|_| {
            ArtiNativeKeystoreError::InvalidSshKeyData(
                "bad length on expanded ed25519 secret key ".into(),
            )
        })?,
    )
    .ok_or_else(|| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad expanded ed25519 secret key ".into())
    })?;

    if &public != keypair.public() {
        return Err(ArtiNativeKeystoreError::InvalidSshKeyData(
            "mismatched ed25519 keypair".into(),
        )
        .into());
    }

    Ok(keypair)
}

/// Try to convert an [`Ed25519PublicKey`](ssh_key::public::Ed25519PublicKey) to an [`ed25519::PublicKey`].
fn convert_ed25519_pk(key: &ssh_key::public::Ed25519PublicKey) -> Result<ed25519::PublicKey> {
    Ok(ed25519::PublicKey::from_bytes(key.as_ref()).map_err(|_| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad ed25519 public key ".into())
    })?)
}

/// Try to convert an [`OpaquePublicKey`](ssh_key::public::OpaquePublicKey) to an [`ed25519::PublicKey`].
///
/// This function always returns an error because the custom `ed25519-expanded@spec.torproject.org`
/// SSH algorithm should not be used for ed25519 public keys (only for expanded ed25519 key
/// _pairs_). This function is needed for the [`parse_openssh!`] macro.
fn convert_expanded_ed25519_pk(
    _key: &ssh_key::public::OpaquePublicKey,
) -> Result<ed25519::PublicKey> {
    Err(ArtiNativeKeystoreError::InvalidSshKeyData(
        "invalid ed25519 public key (ed25519 public keys should be stored as ssh-ed25519)".into(),
    )
    .into())
}

/// Try to convert an [`OpaquePublicKey`](ssh_key::public::OpaquePublicKey) to a [`curve25519::PublicKey`].
fn convert_x25519_pk(key: &ssh_key::public::OpaquePublicKey) -> Result<curve25519::PublicKey> {
    let public: [u8; 32] = key.as_ref().try_into().map_err(|_| {
        ArtiNativeKeystoreError::InvalidSshKeyData("bad x25519 public key length".into())
    })?;

    Ok(curve25519::PublicKey::from(public))
}

impl KeyType {
    /// Get the algorithm of this key type.
    pub(crate) fn ssh_algorithm(&self) -> Result<SshKeyAlgorithm> {
        match self {
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

    /// Parse an OpenSSH key, convert the key material into a known key type, and return the
    /// type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    pub(crate) fn parse_ssh_format_erased(&self, key: UnparsedOpenSshKey) -> Result<ErasedKey> {
        // TODO: perhaps this needs to be a method on EncodableKey instead?

        match &self {
            KeyType::Ed25519Keypair
            | KeyType::X25519StaticKeypair
            | KeyType::Ed25519ExpandedKeypair => {
                parse_openssh!(PRIVATE key, self)
            }
            KeyType::Ed25519PublicKey | KeyType::X25519PublicKey => {
                parse_openssh!(PUBLIC key, self)
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

    use super::*;

    macro_rules! test_parse_ssh_format_erased {
        ($key_ty:tt, $key:expr, $expected_ty:path) => {{
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new($key.into(), PathBuf::from("/test/path"));
            let erased_key = key_type.parse_ssh_format_erased(key).unwrap();

            assert!(erased_key.downcast::<$expected_ty>().is_ok());
        }};

        ($key_ty:tt, $key:expr, err = $expect_err:expr) => {{
            let key_type = KeyType::$key_ty;
            let key = UnparsedOpenSshKey::new($key.into(), PathBuf::from("/dummy/path"));
            let err = key_type
                .parse_ssh_format_erased(key)
                .map(|_| "<type erased key>")
                .unwrap_err();

            assert_eq!(err.to_string(), $expect_err);
        }};
    }

    #[test]
    fn wrong_key_type() {
        let key_type = KeyType::Ed25519Keypair;
        let key = UnparsedOpenSshKey::new(OPENSSH_DSA.into(), PathBuf::from("/test/path"));
        let err = key_type
            .parse_ssh_format_erased(key)
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
