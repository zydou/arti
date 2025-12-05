//! The [`Keystore`] trait and its implementations.

pub(crate) mod arti;
#[cfg(feature = "ctor-keystore")]
pub(crate) mod ctor;
pub(crate) mod fs_utils;

#[cfg(feature = "ephemeral-keystore")]
pub(crate) mod ephemeral;

use tor_key_forge::{EncodableItem, ErasedKey, KeystoreItemType};

use crate::raw::RawEntryId;
use crate::{KeySpecifier, KeystoreEntry, KeystoreId, Result, UnrecognizedEntryError};

/// A type alias returned by `Keystore::list`.
pub type KeystoreEntryResult<T> = std::result::Result<T, UnrecognizedEntryError>;

// NOTE: Some methods require a `KeystoreEntryResult<KeystoreEntry>` as an
// argument (e.g.: `KeyMgr::raw_keystore_entry`). For this reason  implementing
// `From<UnrecognizedEntryError> for <KeystoreEntryResult<KeystoreEntry>>` makes
// `UnrecognizedEntryError` more ergonomic.
impl<'a> From<UnrecognizedEntryError> for KeystoreEntryResult<KeystoreEntry<'a>> {
    fn from(val: UnrecognizedEntryError) -> Self {
        Err(val)
    }
}

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

    /// Remove the specified keystore entry.
    ///
    /// This method accepts both recognized and unrecognized entries, identified
    /// by a [`RawEntryId`] instance.
    ///
    /// If the entry wasn't successfully removed, or if the entry doesn't
    /// exists, `Err` is returned.
    #[cfg(feature = "onion-service-cli-extra")]
    fn remove_unchecked(&self, entry_id: &RawEntryId) -> Result<()>;

    /// List all the entries in this keystore.
    ///
    /// Returns a list of results, where `Ok` signifies a recognized entry,
    /// and `Err(KeystoreListError)` an unrecognized one.
    /// An entry is said to be recognized if it has a valid [`KeyPath`](crate).
    fn list(&self) -> Result<Vec<KeystoreEntryResult<KeystoreEntry>>>;
}
