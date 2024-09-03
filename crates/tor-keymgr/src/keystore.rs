//! The [`Keystore`] trait and its implementations.

pub(crate) mod arti;
pub(crate) mod ephemeral;

use rand::{CryptoRng, RngCore};
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData, OpaqueKeypair};
use ssh_key::public::{Ed25519PublicKey, KeyData, OpaquePublicKey};
use ssh_key::{Algorithm, AlgorithmName, LineEnding, PrivateKey, PublicKey};
use tor_error::{internal, into_internal};
use tor_hscrypto::pk::{
    HsBlindIdKey, HsBlindIdKeypair, HsClientDescEncKeypair, HsDescSigningKeypair, HsIdKey,
    HsIdKeypair, HsIntroPtSessionIdKeypair, HsSvcNtorKeypair,
};
use tor_llcrypto::pk::{curve25519, ed25519};

use crate::key_type::KeyType;
use crate::ssh::{SshKeyAlgorithm, ED25519_EXPANDED_ALGORITHM_NAME, X25519_ALGORITHM_NAME};
use crate::{Error, KeyPath, KeySpecifier, KeystoreId, Result};

use downcast_rs::{impl_downcast, Downcast};

/// A type-erased key returned by a [`Keystore`].
pub type ErasedKey = Box<dyn EncodableKey>;

/// A random number generator for generating [`EncodableKey`]s.
pub trait KeygenRng: RngCore + CryptoRng {}

impl<T> KeygenRng for T where T: RngCore + CryptoRng {}

/// A generic key store.
pub trait Keystore: Send + Sync + 'static {
    /// An identifier for this key store instance.
    ///
    /// This identifier is used by some [`KeyMgr`](crate::KeyMgr) APIs to identify a specific key
    /// store.
    fn id(&self) -> &KeystoreId;

    /// Check if the key identified by `key_spec` exists in this key store.
    fn contains(&self, key_spec: &dyn KeySpecifier, key_type: &KeyType) -> Result<bool>;

    /// Retrieve the key identified by `key_spec`.
    ///
    /// Returns `Ok(Some(key))` if the key was successfully retrieved. Returns `Ok(None)` if the
    /// key does not exist in this key store.
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: &KeyType) -> Result<Option<ErasedKey>>;

    /// Write `key` to the key store.
    //
    // Note: the key_type argument here might seem redundant: `key` implements `EncodableKey`,
    // which has a `key_type` function. However:
    //   * `key_type` is an associated function on `EncodableKey`, not a method, which means we
    //   can't call it on `key: &dyn EncodableKey` (you can't call an associated function of trait
    //   object). The caller of `Keystore::insert` (i.e. `KeyMgr`) OTOH _can_ call `K::key_type()`
    //   on the `EncodableKey` because the concrete type `K` that implements `EncodableKey` is
    //   known.
    //  * one could argue I should make `key_type` a `&self` method rather than an associated function,
    //   which would fix this problem (and enable us to remove the additional `key_type` param).
    //   However, that would break `KeyMgr::remove`, which calls
    //   `store.remove(key_spec, K::Key::key_type())`, where `K` is a type parameter specified by
    //   the caller (in `KeyMgr::remove` we don't have a `value: K`, so we can't call `key_type` if
    //   `key_type` is a `&self` method)...
    //
    // TODO: Maybe we can refactor this API and remove the "redundant" param somehow.
    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
    ) -> Result<()>;

    /// Remove the specified key.
    ///
    /// A return value of `Ok(None)` indicates the key doesn't exist in this key store, whereas
    /// `Ok(Some(())` means the key was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: &KeyType) -> Result<Option<()>>;

    /// List all the keys in this keystore.
    fn list(&self) -> Result<Vec<(KeyPath, KeyType)>>;
}

/// A trait for generating fresh keys.
pub trait Keygen {
    /// Generate a new key of this type.
    fn generate(rng: &mut dyn KeygenRng) -> Result<Self>
    where
        Self: Sized;
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

/// Try to convert an [`Ed25519Keypair`] to an [`ed25519::Keypair`].
// TODO remove this allow?
// clippy wants this whole function to be infallible because
// nowadays ed25519::Keypair can be made infallibly from bytes,
// but is that really right?
#[allow(clippy::unnecessary_fallible_conversions)]
fn convert_ed25519_kp(key: &ssh_key::private::Ed25519Keypair) -> Result<ed25519::Keypair> {
    Ok(ed25519::Keypair::try_from(&key.private.to_bytes())
        .map_err(|_| internal!("bad ed25519 keypair"))?)
}

/// Try to convert an [`OpaqueKeypair`] to a [`curve25519::StaticKeypair`].
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

/// Try to convert an [`OpaqueKeypair`] to an [`ed25519::ExpandedKeypair`].
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

/// Try to convert an [`Ed25519PublicKey`] to an [`ed25519::PublicKey`].
fn convert_ed25519_pk(key: &ssh_key::public::Ed25519PublicKey) -> Result<ed25519::PublicKey> {
    Ok(ed25519::PublicKey::from_bytes(key.as_ref())
        .map_err(|_| internal!("bad ed25519 public key "))?)
}

/// Try to convert an [`OpaquePublicKey`] to an [`ed25519::PublicKey`].
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

/// Try to convert an [`OpaquePublicKey`] to a [`curve25519::PublicKey`].
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
    pub(crate) fn try_from_key_data(key: KeyData) -> Result<Self> {
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
    pub(crate) fn try_from_keypair_data(key: KeypairData) -> Result<Self> {
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
    pub(crate) fn to_openssh_string(&self, comment: &str) -> Result<String> {
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

/// Seal preventing external types from implementing `EncodableKey`.
mod sealed {
    /// Sealed
    pub trait Sealed {}
}

// TODO: refactor the keymgr tests to not require a custom EncodableKey impl.
#[cfg(test)]
pub(crate) use sealed::Sealed;

#[cfg(not(test))]
use sealed::Sealed;

/// A key that can be serialized to, and deserialized from, a format used by a
/// [`Keystore`].
//
// Sealed, because the supported key types form a closed set.
// When adding a new `EncodableKey` impl, you must also update
// [`SshKeyData::into_erased`](crate::SshKeyData::into_erased) to
// return the corresponding concrete type implementing `EncodableKey`
// (as a `dyn EncodableKey`).
pub trait EncodableKey: Downcast + Sealed {
    /// The type of the key.
    fn key_type() -> KeyType
    where
        Self: Sized;

    /// Return the [`SshKeyData`] of this key.
    fn as_ssh_key_data(&self) -> Result<SshKeyData>;
}

impl_downcast!(EncodableKey);

impl Keygen for curve25519::StaticKeypair {
    fn generate(rng: &mut dyn KeygenRng) -> Result<Self>
    where
        Self: Sized,
    {
        let secret = curve25519::StaticSecret::random_from_rng(rng);
        let public = curve25519::PublicKey::from(&secret);

        Ok(curve25519::StaticKeypair { secret, public })
    }
}

impl Sealed for curve25519::StaticKeypair {}

impl EncodableKey for curve25519::StaticKeypair {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::X25519StaticKeypair
    }

    fn as_ssh_key_data(&self) -> Result<SshKeyData> {
        let algorithm_name = AlgorithmName::new(X25519_ALGORITHM_NAME)
            .map_err(|_| internal!("invalid algorithm name"))?;

        let ssh_public = OpaquePublicKey::new(
            self.public.to_bytes().to_vec(),
            Algorithm::Other(algorithm_name),
        );
        let keypair = OpaqueKeypair::new(self.secret.to_bytes().to_vec(), ssh_public);

        SshKeyData::try_from_keypair_data(ssh_key::private::KeypairData::Other(keypair))
    }
}

impl Sealed for curve25519::PublicKey {}

impl EncodableKey for curve25519::PublicKey {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::X25519PublicKey
    }

    fn as_ssh_key_data(&self) -> Result<SshKeyData> {
        let algorithm_name = AlgorithmName::new(X25519_ALGORITHM_NAME)
            .map_err(|_| internal!("invalid algorithm name"))?;

        let ssh_public =
            OpaquePublicKey::new(self.to_bytes().to_vec(), Algorithm::Other(algorithm_name));

        SshKeyData::try_from_key_data(KeyData::Other(ssh_public))
    }
}

impl Keygen for ed25519::Keypair {
    fn generate(mut rng: &mut dyn KeygenRng) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(ed25519::Keypair::generate(&mut rng))
    }
}

impl Sealed for ed25519::Keypair {}

impl EncodableKey for ed25519::Keypair {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::Ed25519Keypair
    }

    fn as_ssh_key_data(&self) -> Result<SshKeyData> {
        let keypair = Ed25519Keypair {
            public: Ed25519PublicKey(self.verifying_key().to_bytes()),
            private: Ed25519PrivateKey::from_bytes(self.as_bytes()),
        };

        SshKeyData::try_from_keypair_data(KeypairData::Ed25519(keypair))
    }
}

impl Sealed for ed25519::PublicKey {}

impl EncodableKey for ed25519::PublicKey {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::Ed25519PublicKey
    }

    fn as_ssh_key_data(&self) -> Result<SshKeyData> {
        let key_data = Ed25519PublicKey(self.to_bytes());

        SshKeyData::try_from_key_data(ssh_key::public::KeyData::Ed25519(key_data))
    }
}

impl Keygen for ed25519::ExpandedKeypair {
    fn generate(rng: &mut dyn KeygenRng) -> Result<Self>
    where
        Self: Sized,
    {
        let keypair = <ed25519::Keypair as Keygen>::generate(rng)?;

        Ok((&keypair).into())
    }
}

impl Sealed for ed25519::ExpandedKeypair {}

impl EncodableKey for ed25519::ExpandedKeypair {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::Ed25519ExpandedKeypair
    }

    fn as_ssh_key_data(&self) -> Result<SshKeyData> {
        let algorithm_name = AlgorithmName::new(ED25519_EXPANDED_ALGORITHM_NAME)
            .map_err(|_| internal!("invalid algorithm name"))?;

        let ssh_public = OpaquePublicKey::new(
            self.public().to_bytes().to_vec(),
            Algorithm::Other(algorithm_name),
        );

        let keypair = OpaqueKeypair::new(self.to_secret_key_bytes().to_vec(), ssh_public);

        SshKeyData::try_from_keypair_data(ssh_key::private::KeypairData::Other(keypair))
    }
}

/// A key that can be converted to an [`EncodableKey`].
//
// NOTE: Conceptually, the `ToEncodableKey` and `EncodableKey` traits serve the same purpose (they
// provide information about how to encode/decode a key).
//
// The reason we have two traits instead of just one is because `EncodableKey` cannot have an
// associated type: if it did, we'd need to either give `Keystore::insert` a generic parameter
// (which would make `Keystore` object-unsafe), or specify a concrete type for the associated type
// of the `EncodableKey` (which would defeat the whole purpose of the trait, i.e. to enable users
// to store their own "encodable key" types).
//
// `ToEncodableKey` is used in the `KeyMgr` impl, where the associated type isn't an issue because
// the `KeyMgr` implementation is generic over `K: ToEncodableKey`. The `Keystore`s themselves only
// receive `&dyn EncodableKey`s.
pub trait ToEncodableKey {
    /// The key type this can be converted to/from.
    type Key: EncodableKey + 'static;

    /// Convert this key to a type that implements [`EncodableKey`].
    fn to_encodable_key(self) -> Self::Key;

    /// Convert an [`EncodableKey`] to another key type.
    fn from_encodable_key(key: Self::Key) -> Self;
}

impl ToEncodableKey for HsClientDescEncKeypair {
    type Key = curve25519::StaticKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsClientDescEncKeypair::new(key.public.into(), key.secret.into())
    }
}

impl ToEncodableKey for HsBlindIdKeypair {
    type Key = ed25519::ExpandedKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsBlindIdKeypair::from(key)
    }
}

impl ToEncodableKey for HsBlindIdKey {
    type Key = ed25519::PublicKey;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsBlindIdKey::from(key)
    }
}

impl ToEncodableKey for HsIdKeypair {
    type Key = ed25519::ExpandedKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsIdKeypair::from(key)
    }
}

impl ToEncodableKey for HsIdKey {
    type Key = ed25519::PublicKey;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsIdKey::from(key)
    }
}

impl ToEncodableKey for HsDescSigningKeypair {
    type Key = ed25519::Keypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsDescSigningKeypair::from(key)
    }
}

impl ToEncodableKey for HsIntroPtSessionIdKeypair {
    type Key = ed25519::Keypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        key.into()
    }
}

impl ToEncodableKey for HsSvcNtorKeypair {
    type Key = curve25519::StaticKeypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        key.into()
    }
}
