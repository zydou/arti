//! The [`Keystore`] trait and its implementations.

pub(crate) mod arti;
#[cfg(feature = "ctor-keystore")]
pub(crate) mod ctor;
pub(crate) mod fs_utils;

#[cfg(feature = "ephemeral-keystore")]
pub(crate) mod ephemeral;

use tor_key_forge::{EncodableItem, ErasedKey, KeyType};

use crate::{KeyPath, KeySpecifier, KeystoreId, Result};

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
    // Note: the key_type argument here might seem redundant: `key` implements `EncodableItem`,
    // which has a `key_type` function. However:
    //   * `key_type` is an associated function on `EncodableItem`, not a method, which means we
    //   can't call it on `key: &dyn EncodableItem` (you can't call an associated function of trait
    //   object). The caller of `Keystore::insert` (i.e. `KeyMgr`) OTOH _can_ call `K::key_type()`
    //   on the `EncodableItem` because the concrete type `K` that implements `EncodableItem` is
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
        key: &dyn EncodableItem,
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
