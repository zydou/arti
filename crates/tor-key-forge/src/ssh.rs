//! Shared OpenSSH helpers.

use ssh_key::{
    private::KeypairData, public::KeyData, Algorithm, LineEnding, PrivateKey, PublicKey,
};
use tor_error::{internal, into_internal};
use tor_llcrypto::pk::{curve25519, ed25519};

use crate::{ErasedKey, Error, KeyType, Result};

/// The algorithm string for x25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const X25519_ALGORITHM_NAME: &str = "x25519@spec.torproject.org";

/// The algorithm string for expanded ed25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const ED25519_EXPANDED_ALGORITHM_NAME: &str = "ed25519-expanded@spec.torproject.org";

/// SSH key algorithms.
//
// Note: this contains all the types supported by ssh_key, plus variants representing
// x25519 and expanded ed25519 keys.
#[derive(Clone, Debug, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub enum SshKeyAlgorithm {
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

/// Convert ssh_key KeyData or KeypairData to one of our key types.
macro_rules! ssh_to_internal_erased {
    (PRIVATE $key:expr, $algo:expr) => {{
        ssh_to_internal_erased!(
            $key,
            $algo,
            convert_ed25519_kp,
            convert_expanded_ed25519_kp,
            convert_x25519_kp,
            KeypairData
        )
    }};

    (PUBLIC $key:expr, $algo:expr) => {{
        ssh_to_internal_erased!(
            $key,
            $algo,
            convert_ed25519_pk,
            convert_expanded_ed25519_pk,
            convert_x25519_pk,
            KeyData
        )
    }};

    ($key:expr, $algo:expr, $ed25519_fn:path, $expanded_ed25519_fn:path, $x25519_fn:path, $key_data_ty:tt) => {{
        let key = $key;
        let algo = SshKeyAlgorithm::from($algo);

        // Build the expected key type (i.e. convert ssh_key key types to the key types
        // we're using internally).
        match key {
            $key_data_ty::Ed25519(key) => Ok($ed25519_fn(&key).map(Box::new)?),
            $key_data_ty::Other(other) => match algo {
                SshKeyAlgorithm::X25519 => Ok($x25519_fn(&other).map(Box::new)?),
                SshKeyAlgorithm::Ed25519Expanded => Ok($expanded_ed25519_fn(&other).map(Box::new)?),
                _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
            },
            _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
        }
    }};
}

/// Try to convert an [`Ed25519Keypair`](ssh_key::private::Ed25519Keypair) to an [`ed25519::Keypair`].
// TODO remove this allow?
// clippy wants this whole function to be infallible because
// nowadays ed25519::Keypair can be made infallibly from bytes,
// but is that really right?
#[allow(clippy::unnecessary_fallible_conversions)]
fn convert_ed25519_kp(key: &ssh_key::private::Ed25519Keypair) -> Result<ed25519::Keypair> {
    Ok(ed25519::Keypair::try_from(&key.private.to_bytes())
        .map_err(|_| internal!("bad ed25519 keypair"))?)
}

/// Try to convert an [`OpaqueKeypair`](ssh_key::private::OpaqueKeypair) to a [`curve25519::StaticKeypair`].
fn convert_x25519_kp(key: &ssh_key::private::OpaqueKeypair) -> Result<curve25519::StaticKeypair> {
    let public: [u8; 32] = key
        .public
        .as_ref()
        .try_into()
        .map_err(|_| internal!("bad x25519 public key length"))?;

    let secret: [u8; 32] = key
        .private
        .as_ref()
        .try_into()
        .map_err(|_| internal!("bad x25519 secret key length"))?;

    Ok(curve25519::StaticKeypair {
        public: public.into(),
        secret: secret.into(),
    })
}

/// Try to convert an [`OpaqueKeypair`](ssh_key::private::OpaqueKeypair) to an [`ed25519::ExpandedKeypair`].
fn convert_expanded_ed25519_kp(
    key: &ssh_key::private::OpaqueKeypair,
) -> Result<ed25519::ExpandedKeypair> {
    let public = ed25519::PublicKey::try_from(key.public.as_ref())
        .map_err(|_| internal!("bad expanded ed25519 public key "))?;

    let keypair = ed25519::ExpandedKeypair::from_secret_key_bytes(
        key.private
            .as_ref()
            .try_into()
            .map_err(|_| internal!("bad length on expanded ed25519 secret key ",))?,
    )
    .ok_or_else(|| internal!("bad expanded ed25519 secret key "))?;

    if &public != keypair.public() {
        return Err(internal!("mismatched ed25519 keypair",).into());
    }

    Ok(keypair)
}

/// Try to convert an [`Ed25519PublicKey`](ssh_key::public::Ed25519PublicKey) to an [`ed25519::PublicKey`].
fn convert_ed25519_pk(key: &ssh_key::public::Ed25519PublicKey) -> Result<ed25519::PublicKey> {
    Ok(ed25519::PublicKey::from_bytes(key.as_ref())
        .map_err(|_| internal!("bad ed25519 public key "))?)
}

/// Try to convert an [`OpaquePublicKey`](ssh_key::public::OpaquePublicKey) to an [`ed25519::PublicKey`].
///
/// This function always returns an error because the custom `ed25519-expanded@spec.torproject.org`
/// SSH algorithm should not be used for ed25519 public keys (only for expanded ed25519 key
/// _pairs_). This function is needed for the [`ssh_to_internal_erased!`] macro.
fn convert_expanded_ed25519_pk(
    _key: &ssh_key::public::OpaquePublicKey,
) -> Result<ed25519::PublicKey> {
    Err(internal!(
        "invalid ed25519 public key (ed25519 public keys should be stored as ssh-ed25519)",
    )
    .into())
}

/// Try to convert an [`OpaquePublicKey`](ssh_key::public::OpaquePublicKey) to a [`curve25519::PublicKey`].
fn convert_x25519_pk(key: &ssh_key::public::OpaquePublicKey) -> Result<curve25519::PublicKey> {
    let public: [u8; 32] = key
        .as_ref()
        .try_into()
        .map_err(|_| internal!("bad x25519 public key length"))?;

    Ok(curve25519::PublicKey::from(public))
}

/// A public key or a keypair.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SshKeyData(SshKeyDataInner);

/// The inner representation of a public key or a keypair.
#[derive(Clone, Debug)]
#[non_exhaustive]
enum SshKeyDataInner {
    /// The [`KeyData`] of a public key.
    Public(KeyData),
    /// The [`KeypairData`] of a private key.
    Private(KeypairData),
}

impl SshKeyData {
    /// Try to convert a [`KeyData`] to [`SshKeyData`].
    ///
    /// Returns an error if this type of [`KeyData`] is not supported.
    pub fn try_from_key_data(key: KeyData) -> Result<Self> {
        let algo = SshKeyAlgorithm::from(key.algorithm());
        let () = match key {
            KeyData::Ed25519(_) => Ok(()),
            KeyData::Other(_) => match algo {
                SshKeyAlgorithm::X25519 => Ok(()),
                _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
            },
            _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
        }?;

        Ok(Self(SshKeyDataInner::Public(key)))
    }

    /// Try to convert a [`KeypairData`] to [`SshKeyData`].
    ///
    /// Returns an error if this type of [`KeypairData`] is not supported.
    pub fn try_from_keypair_data(key: KeypairData) -> Result<Self> {
        let algo = SshKeyAlgorithm::from(
            key.algorithm()
                .map_err(into_internal!("encrypted keys are not yet supported"))?,
        );
        let () = match key {
            KeypairData::Ed25519(_) => Ok(()),
            KeypairData::Other(_) => match algo {
                SshKeyAlgorithm::X25519 => Ok(()),
                SshKeyAlgorithm::Ed25519Expanded => Ok(()),
                _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
            },
            _ => Err(Error::UnsupportedKeyAlgorithm(algo)),
        }?;

        Ok(Self(SshKeyDataInner::Private(key)))
    }

    /// Encode this key as an OpenSSH-formatted key using the specified `comment`
    pub fn to_openssh_string(&self, comment: &str) -> Result<String> {
        let openssh_key = match &self.0 {
            SshKeyDataInner::Public(key_data) => {
                let openssh_key = PublicKey::new(key_data.clone(), comment);

                openssh_key
                    .to_openssh()
                    .map_err(|_| tor_error::internal!("failed to encode SSH key"))?
            }
            SshKeyDataInner::Private(keypair) => {
                let openssh_key = PrivateKey::new(keypair.clone(), comment)
                    .map_err(|_| tor_error::internal!("failed to create SSH private key"))?;

                openssh_key
                    .to_openssh(LineEnding::LF)
                    .map_err(|_| tor_error::internal!("failed to encode SSH key"))?
                    .to_string()
            }
        };

        Ok(openssh_key)
    }

    /// Convert the key material into a known key type,
    /// and return the type-erased value.
    ///
    /// The caller is expected to downcast the value returned to the correct concrete type.
    pub fn into_erased(self) -> Result<ErasedKey> {
        match self.0 {
            SshKeyDataInner::Private(key) => {
                let algorithm = key
                    .algorithm()
                    .map_err(into_internal!("unsupported key type"))?;
                ssh_to_internal_erased!(PRIVATE key, algorithm)
            }
            SshKeyDataInner::Public(key) => {
                let algorithm = key.algorithm();
                ssh_to_internal_erased!(PUBLIC key, algorithm)
            }
        }
    }

    /// Return the [`KeyType`] of this OpenSSH key.
    ///
    /// Returns an error if the underlying key material is [`KeypairData::Encrypted`],
    /// or if its algorithm is unsupported.
    pub fn key_type(&self) -> Result<KeyType> {
        match &self.0 {
            SshKeyDataInner::Public(k) => KeyType::try_from_key_data(k),
            SshKeyDataInner::Private(k) => KeyType::try_from_keypair_data(k),
        }
    }
}
