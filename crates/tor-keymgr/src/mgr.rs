//! Code for managing multiple [`KeyStore`]s.
//!
//! The [`KeyMgr`] reads from (and writes to) a number of key stores. The key stores all implement
//! [`KeyStore`].

use crate::{EncodableKey, KeySpecifier, KeyStore, Result, ToEncodableKey};

use tor_error::internal;

/// A key manager with several [`KeyStore`]s.
///
/// Note: [`KeyMgr`] is a low-level utility and does not implement caching (the key stores are
/// accessed for every read/write).
pub struct KeyMgr {
    /// The underlying persistent stores.
    key_stores: Vec<Box<dyn KeyStore>>,
}

impl KeyMgr {
    /// Create a new [`KeyMgr`].
    pub fn new(key_stores: Vec<Box<dyn KeyStore>>) -> Self {
        Self { key_stores }
    }

    /// Read a key from one of the key stores, and try to deserialize it as `K::Key`.
    ///
    /// The key returned is retrieved from the first key store that contains an entry for the given
    /// specifier.
    ///
    /// Returns Ok(None) if none of the key stores have the requested key.
    pub fn get<K: ToEncodableKey>(&self, key_spec: &dyn KeySpecifier) -> Result<Option<K>> {
        // Check if the requested key identity exists in any of the key stores:
        for store in &self.key_stores {
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

    /// Insert the specified key intro the appropriate key store.
    ///
    /// If the key bundle of this `key` exists in one of the key stores, the key is inserted
    /// there. Otherwise, the key is inserted into the first key store.
    ///
    /// If the key already exists, it is overwritten.
    ///
    // TODO HSS: would it be useful for this API to return a Result<Option<K>> here (i.e. the old key)?
    // TODO HSS (#903): define what "key bundle" means
    pub fn insert<K: ToEncodableKey>(&self, key: K, key_spec: &dyn KeySpecifier) -> Result<()> {
        // TODO HSS: maybe we should designate an explicit 'primary' store instead of implicitly
        // preferring the first one.
        let primary_store = match self.key_stores.first() {
            Some(store) => store,
            None => return Err(internal!("no key stores configured").into()),
        };
        let key = key.to_encodable_key();

        let store = self
            .key_stores
            .iter()
            .find_map(|s| match s.has_key_bundle(key_spec) {
                Ok(true) => Some(Ok(s)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .transpose()?
            // None of the stores has the key bundle of key_spec, so we insert the key into the first
            // store.
            .unwrap_or(primary_store);

        store.insert(&key, key_spec, K::Key::key_type())
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
}
