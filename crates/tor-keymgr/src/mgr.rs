//! Code for managing multiple [`Keystore`]s.
//!
//! The [`KeyMgr`] reads from (and writes to) a number of key stores. The key stores all implement
//! [`Keystore`].

use crate::{
    EncodableKey, KeySpecifier, Keystore, KeystoreError, KeystoreSelector, Result, ToEncodableKey,
};

use std::iter;
use tor_error::{internal, HasKind};

/// A boxed [`Keystore`].
type BoxedKeystore = Box<dyn Keystore>;

/// An error returned by [`KeyMgr`](crate::KeyMgr)'.
#[derive(thiserror::Error, Debug, Clone)]
enum KeyMgrError {
    /// The requested key store was not found.
    #[error("Could not find keystore with id {0}")]
    KeystoreNotFound(&'static str),

    /// The specified [`KeystoreSelector`](crate::KeystoreSelector) cannot be used for the
    /// requested operation.
    #[error("Action {op} cannot be performed with selector {selector:?}")]
    UnsupportedKeystoreSelector {
        /// The operation we were trying to perform
        op: &'static str,
        /// The [`KeystoreSelector`](crate::KeystoreSelector)
        selector: crate::KeystoreSelector,
    },
}

impl HasKind for KeyMgrError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::KeystoreMisuse
    }
}

impl KeystoreError for KeyMgrError {}

/// A key manager with several [`Keystore`]s.
///
/// Note: [`KeyMgr`] is a low-level utility and does not implement caching (the key stores are
/// accessed for every read/write).
//
// TODO HSS: derive builder for KeyMgr.
pub struct KeyMgr {
    /// The default key store.
    default_store: BoxedKeystore,
    /// The secondary key stores.
    key_stores: Vec<BoxedKeystore>,
}

impl KeyMgr {
    /// Create a new [`KeyMgr`] with a default [`Keystore`] and zero or more secondary [`Keystore`]s.
    pub fn new(default_store: impl Keystore, key_stores: Vec<BoxedKeystore>) -> Self {
        Self {
            default_store: Box::new(default_store),
            key_stores,
        }
    }

    /// Read a key from one of the key stores, and try to deserialize it as `K::Key`.
    ///
    /// The key returned is retrieved from the first key store that contains an entry for the given
    /// specifier.
    ///
    /// Returns Ok(None) if none of the key stores have the requested key.
    pub fn get<K: ToEncodableKey>(&self, key_spec: &dyn KeySpecifier) -> Result<Option<K>> {
        self.get_from_store(key_spec, self.all_stores())
    }

    /// Insert `key` into the [`Keystore`] specified by `selector`.
    ///
    /// This function can only be used with [`KeystoreSelector::Default`] and
    /// [`KeystoreSelector::Id`]. It returns an error if the specified `selector`
    /// is not supported.
    ///
    /// If the key already exists, it is overwritten.
    ///
    // TODO HSS: would it be useful for this API to return a Result<Option<K>> here (i.e. the old key)?
    pub fn insert<K: ToEncodableKey>(
        &self,
        key: K,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<()> {
        let key = key.to_encodable_key();

        match selector {
            KeystoreSelector::Id(keystore_id) => {
                let Some(keystore) = self.find_keystore(keystore_id) else {
                    return Err(KeyMgrError::KeystoreNotFound(keystore_id).boxed());
                };
                keystore.insert(&key, key_spec, K::Key::key_type())
            }
            KeystoreSelector::Default => {
                self.default_store
                    .insert(&key, key_spec, K::Key::key_type())
            }
            KeystoreSelector::All => Err(KeyMgrError::UnsupportedKeystoreSelector {
                op: "insert",
                selector,
            }
            .boxed()),
        }
    }

    /// Remove the specified key.
    ///
    /// If the key exists in multiple key stores, this will only remove it from the first one.
    ///
    /// A return vaue of `Ok(None)` indicates the key doesn't exist in any of the key stores,
    /// whereas `Ok(Some(())` means the key was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    pub fn remove<K: ToEncodableKey>(&self, key_spec: &dyn KeySpecifier) -> Result<Option<()>> {
        for store in &self.key_stores {
            match store.remove(key_spec, K::Key::key_type()) {
                Ok(None) => {
                    // This key store doesn't have the key we're trying to remove, so we search the
                    // next key store...
                    continue;
                }
                res => return res,
            }
        }

        Ok(None)
    }

    /// Attempt to retrieve a key from one of the specified `stores`.
    ///
    /// See [`KeyMgr::get`] for more details.
    fn get_from_store<'a, K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        stores: impl Iterator<Item = &'a BoxedKeystore>,
    ) -> Result<Option<K>> {
        for store in stores {
            let key = match store.get(key_spec, K::Key::key_type()) {
                Ok(None) => {
                    // The key doesn't exist in this store, so we check the next one...
                    continue;
                }
                Ok(Some(k)) => k,
                Err(e) => {
                    // TODO HSS: we immediately return if one of the keystores is inaccessible.
                    // Perhaps we should ignore any errors and simply poll the next store in the
                    // list?
                    return Err(e);
                }
            };

            // Found it! Now try to downcast it to the right type (this should _not_ fail)...
            let key: K::Key = key
                .downcast::<K::Key>()
                .map(|k| *k)
                .map_err(|_| internal!("failed to downcast key to requested type"))?;

            return Ok(Some(K::from_encodable_key(key)));
        }

        Ok(None)
    }

    /// Return an iterator over all configured stores.
    fn all_stores(&self) -> impl Iterator<Item = &BoxedKeystore> {
        iter::once(&self.default_store).chain(self.key_stores.iter())
    }

    /// Return the [`Keystore`] with the specified `id`.
    fn find_keystore(&self, id: &'static str) -> Option<&BoxedKeystore> {
        self.all_stores().find(|keystore| keystore.id() == id)
    }
}
