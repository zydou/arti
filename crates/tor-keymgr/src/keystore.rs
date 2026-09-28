//! The [`Keystore`] trait and its implementations.

pub(crate) mod arti;
pub(crate) mod ctor;
pub(crate) mod fs_utils;

#[cfg(feature = "ephemeral-keystore")]
pub(crate) mod ephemeral;

use tor_key_forge::{EncodableItem, ErasedKey, KeystoreItemType};

use crate::raw::RawEntryId;
use crate::{KeySpecifier, KeystoreEntry, KeystoreId, Result, UnrecognizedEntryError};

/// A type alias returned by `Keystore::list`.
pub type KeystoreEntryResult<T> = std::result::Result<T, UnrecognizedEntryError>;

/// A generic key store.
pub trait Keystore: Send + Sync + 'static {
    /// An identifier for this key store instance.
    ///
    /// This identifier is used by some [`KeyMgr`](crate::KeyMgr) APIs to identify a specific key
    /// store.
    fn id(&self) -> &KeystoreId;

    /// Check if the key identified by `key_spec` exists in this key store.
    fn contains(&self, key_spec: &dyn KeySpecifier, item_type: &KeystoreItemType) -> Result<bool>;

    /// Retrieve the key identified by `key_spec`.
    ///
    /// Returns `Ok(Some(key))` if the key was successfully retrieved. Returns `Ok(None)` if the
    /// key does not exist in this key store.
    fn get(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<Option<ErasedKey>>;

    /// Convert the specified string to a [`RawEntryId`] that
    /// represents the raw unique identifier of an entry in this keystore.
    ///
    /// The specified `raw_id` is allowed to represent an unrecognized
    /// or nonexistent entry.
    ///
    /// Implementations that do not have `RawEntryId`s
    /// that are deserializable from string will return an error.
    //
    // TODO: currently, the only such implementation is the EphemeralKeystore.
    // If we ever decide to remove EphemeralKeystore
    // (see https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2580),
    // we should consider rethinking this API too.
    //
    // For example, we might want to remove this function altogether,
    // and let the user create the RawEntryId instead.
    //
    ///
    /// Returns a `RawEntryId` that is specific to this [`Keystore`] implementation.
    ///
    /// Returns an error if `raw_id` cannot be converted to
    /// the correct variant for this keystore implementation
    /// (e.g.: `RawEntryId::Path(PathBuf) for [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)).
    ///
    /// Important: a `RawEntryId` should only be used to access
    /// the entries of the keystore it originates from
    /// (if used with a *different* keystore, the behavior is unspecified:
    /// the operation may fail, it may succeed, or it may lead to the
    /// wrong entry being accessed).
    #[cfg(feature = "onion-service-cli-extra")]
    fn raw_entry_id(&self, raw_id: &str) -> Result<RawEntryId>;

    /// Write `key` to the key store.
    fn insert(&self, key: &dyn EncodableItem, key_spec: &dyn KeySpecifier) -> Result<()>;

    /// Remove the specified key.
    ///
    /// A return value of `Ok(None)` indicates the key doesn't exist in this key store, whereas
    /// `Ok(Some(())` means the key was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    fn remove(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<Option<()>>;

    /// Remove a keystore entry given its [`RawEntryId`].
    ///
    /// Unlike [`remove`](Keystore::remove), this method can also remove
    /// entries that are unrecognized
    /// (i.e. those that do not have a corresponding [`KeySpecifier`] and [`KeystoreItemType`]).
    ///
    /// Returns an error if the entry couldn't be removed, or if the entry doesn't exist.
    #[cfg(feature = "onion-service-cli-extra")]
    fn remove_unchecked(&self, entry_id: &RawEntryId) -> Result<()>;

    /// List all the entries in this keystore.
    ///
    /// Returns a list of results, where `Ok` signifies a recognized entry,
    /// and `Err(KeystoreListError)` an unrecognized one.
    /// An entry is said to be recognized if it has a valid [`KeyPath`](crate).
    fn list(&self) -> Result<Vec<KeystoreEntryResult<KeystoreEntry>>>;
}
