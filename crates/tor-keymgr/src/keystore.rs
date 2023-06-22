//! The [`KeyStore`] trait and its implementations.

pub(crate) mod arti;

use tor_hscrypto::pk::{HsClientDescEncSecretKey, HsClientIntroAuthKeypair};
use tor_llcrypto::pk::{curve25519, ed25519};

use crate::key_type::KeyType;
use crate::{KeySpecifier, Result};

use std::any::Any;

/// A type-erased key returned by a [`KeyStore`].
pub type ErasedKey = Box<dyn Any>;

/// A generic key store.
//
// TODO HSS: eventually this will be able to store items that aren't keys (such as certificates and
// perhaps other types of sensitive data). We should consider renaming this (and other Key* types)
// to something more generic (such as `SecretStore` or `Vault`).
pub trait KeyStore: Send + Sync + 'static {
    /// Retrieve the key identified by `key_spec`.
    ///
    /// Returns `Ok(Some(key))` if the key was successfully retrieved. Returns `Ok(None)` if the
    /// key does not exist in this key store.
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<ErasedKey>>;

    /// Write `key` to the key store.
    //
    // TODO hs: the key_type argument here might seem redundant: `key` implements `EncodableKey`,
    // which has a `key_type` function. However:
    //   * `key_type` is an associated function on `EncodableKey`, not a method, which means we
    //   can't call it on `key: &dyn EncodableKey` (you can't call an associated function of trait
    //   object). The caller of `KeyStore::insert` (i.e. `KeyMgr`) OTOH _can_ call `K::key_type()`
    //   on the `EncodableKey` because the concrete type `K` that implements `EncodableKey` is
    //   known.
    //  * one argue I should make `key_type` a `&self` method rather than an associated function,
    //   which would fix this problem (and enable us to remove the additional `key_type` param).
    //   However, that would break `KeyMgr::remove`, which calls
    //   `store.remove(key_spec, K::Key::key_type())`, where `K` is a type parameter specified by
    //   the caller (in `KeyMgr::remove` we don't have a `value: K`, so we can't call `key_type` if
    //   `key_type` is a `&self` method)...
    //
    // Maybe we can refactor this API and remove the "redundant" param somehow.
    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
    ) -> Result<()>;

    /// Remove the specified key.
    ///
    /// A return vaue of `Ok(None)` indicates the key doesn't exist in this key store, whereas
    /// `Ok(Some(())` means the key was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<()>>;

    /// Check whether the key bundle associated with the specified identity is in the store.
    fn has_key_bundle(&self, key_spec: &dyn KeySpecifier) -> Result<bool>;
}

/// A key that can be serialized to, and deserialized from, a format used by a
/// [`KeyStore`](crate::KeyStore).
pub trait EncodableKey {
    /// The type of the key.
    fn key_type() -> KeyType
    where
        Self: Sized;
}

impl EncodableKey for curve25519::StaticSecret {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::X25519StaticSecret
    }
}

impl EncodableKey for ed25519::Keypair {
    fn key_type() -> KeyType
    where
        Self: Sized,
    {
        KeyType::Ed25519Keypair
    }
}

/// A key that can be converted to an [`EncodableKey`].
//
// TODO hs: try to fold this trait into `EncodableKey`.
pub trait ToEncodableKey {
    /// The key type this can be converted to/from.
    type Key: EncodableKey + 'static;

    /// Convert this key to a type that implements [`EncodableKey`].
    fn to_encodable_key(self) -> Self::Key;

    /// Convert an [`EncodableKey`] to another key type.
    fn from_encodable_key(key: Self::Key) -> Self;
}

impl ToEncodableKey for HsClientDescEncSecretKey {
    type Key = curve25519::StaticSecret;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsClientDescEncSecretKey::from(key)
    }
}

impl ToEncodableKey for HsClientIntroAuthKeypair {
    type Key = ed25519::Keypair;

    fn to_encodable_key(self) -> Self::Key {
        self.into()
    }

    fn from_encodable_key(key: Self::Key) -> Self {
        HsClientIntroAuthKeypair::from(key)
    }
}
