//! Code for managing multiple [`Keystore`]s.
//!
//! The [`KeyMgr`] reads from (and writes to) a number of key stores. The key stores all implement
//! [`Keystore`].
//!
//! ## Concurrent key store access
//!
//! The key stores will allow concurrent modification by different processes. In
//! order to implement this safely without locking, the key store operations (get,
//! insert, remove) will need to be atomic.
//!
//! **Note**: [`KeyMgr::generate`] should **not** be used concurrently with any other `KeyMgr`
//! operation that mutates the state of key stores, because its outcome depends on whether the
//! selected key store [`contains`][Keystore::contains] the specified key (and thus suffers from a
//! a TOCTOU race).

use crate::{
    EncodableKey, KeySpecifier, KeygenRng, Keystore, KeystoreId, KeystoreSelector, Result,
    ToEncodableKey,
};

use std::iter;
use tor_error::{bad_api_usage, internal};

/// A boxed [`Keystore`].
type BoxedKeystore = Box<dyn Keystore>;

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

    /// Generate a new key of type `K`, and insert it into the key store specified by `selector`.
    ///
    /// If the key already exists in the specified key store, the `overwrite` flag is used to
    /// decide whether to overwrite it with a newly generated key.
    ///
    /// Returns `Ok(Some(())` if a new key was created, and `Ok(None)` otherwise.
    ///
    /// **IMPORTANT**: using this function concurrently with any other `KeyMgr` operation that
    /// mutates the key store state is **not** recommended, as it can yield surprising results! The
    /// outcome of [`KeyMgr::generate`] depends on whether the selected key store
    /// [`contains`][Keystore::contains] the specified key, and thus suffers from a a TOCTOU race.
    //
    // TODO HSS: can we make this less racy without a lock? Perhaps we should say we'll always
    // overwrite any existing keys.
    pub fn generate<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
        rng: &mut dyn KeygenRng,
        overwrite: bool,
    ) -> Result<Option<()>> {
        let store = self.select_keystore(&selector)?;
        let key_type = K::Key::key_type();

        if overwrite || !store.contains(key_spec, key_type)? {
            let key = K::Key::generate(rng)?;
            store.insert(&key, key_spec, key_type).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Insert `key` into the [`Keystore`] specified by `selector`.
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
        let store = self.select_keystore(&selector)?;

        store.insert(&key, key_spec, K::Key::key_type())
    }

    /// Remove the key identified by `key_spec` from the [`Keystore`] specified by `selector`.
    ///
    /// Returns `Ok(None)` if the key does not exist in the requested keystore.
    /// Returns `Ok(Some(())` if the key was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    pub fn remove<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<Option<()>> {
        let store = self.select_keystore(&selector)?;

        store.remove(key_spec, K::Key::key_type())
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

    /// Return the [`Keystore`] matching the specified `selector`.
    fn select_keystore(&self, selector: &KeystoreSelector) -> Result<&BoxedKeystore> {
        match selector {
            KeystoreSelector::Id(keystore_id) => self.find_keystore(keystore_id),
            KeystoreSelector::Default => Ok(&self.default_store),
        }
    }

    /// Return the [`Keystore`] with the specified `id`.
    fn find_keystore(&self, id: &KeystoreId) -> Result<&BoxedKeystore> {
        self.all_stores()
            .find(|keystore| keystore.id() == id)
            .ok_or_else(|| bad_api_usage!("could not find keystore with ID {id}").into())
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{ArtiPath, ErasedKey, KeyType};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::RwLock;
    use tor_basic_utils::test_rng::testing_rng;

    /// The type of "key" stored in the test key stores.
    type TestKey = String;

    impl EncodableKey for TestKey {
        fn key_type() -> KeyType
        where
            Self: Sized,
        {
            // Dummy value
            KeyType::Ed25519Keypair
        }

        fn generate(_rng: &mut dyn KeygenRng) -> Result<Self>
        where
            Self: Sized,
        {
            Ok("generated_test_key".into())
        }

        fn as_ssh_keypair_data(&self) -> Result<ssh_key::private::KeypairData> {
            // (Ab)use the encrypted variant for testing purposes
            Ok(ssh_key::private::KeypairData::Encrypted(
                self.as_bytes().to_vec(),
            ))
        }
    }

    impl ToEncodableKey for TestKey {
        type Key = TestKey;

        fn to_encodable_key(self) -> Self::Key {
            self
        }

        fn from_encodable_key(key: Self::Key) -> Self {
            key
        }
    }

    macro_rules! impl_keystore {
        ($name:tt, $id:expr) => {
            struct $name {
                inner: RwLock<HashMap<(ArtiPath, KeyType), TestKey>>,
                id: KeystoreId,
            }

            impl Default for $name {
                fn default() -> Self {
                    Self {
                        inner: Default::default(),
                        id: KeystoreId::from_str($id).unwrap(),
                    }
                }
            }

            #[allow(dead_code)] // this is only dead code for Keystore1
            impl $name {
                fn new_boxed() -> BoxedKeystore {
                    Box::<Self>::default()
                }
            }

            impl Keystore for $name {
                fn contains(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<bool> {
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .contains_key(&(key_spec.arti_path()?, key_type)))
                }

                fn id(&self) -> &KeystoreId {
                    &self.id
                }

                fn get(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: KeyType,
                ) -> Result<Option<ErasedKey>> {
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .get(&(key_spec.arti_path()?, key_type))
                        .map(|k| Box::new(k.clone()) as Box<dyn EncodableKey>))
                }

                fn insert(
                    &self,
                    key: &dyn EncodableKey,
                    key_spec: &dyn KeySpecifier,
                    key_type: KeyType,
                ) -> Result<()> {
                    let key = key.as_ssh_keypair_data()?;
                    let key_bytes = key.encrypted().unwrap().to_vec();

                    let value = String::from_utf8(key_bytes).unwrap();

                    self.inner.write().unwrap().insert(
                        (key_spec.arti_path()?, key_type),
                        format!("{}_{value}", self.id()),
                    );

                    Ok(())
                }

                fn remove(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: KeyType,
                ) -> Result<Option<()>> {
                    Ok(self
                        .inner
                        .write()
                        .unwrap()
                        .remove(&(key_spec.arti_path()?, key_type))
                        .map(|_| ()))
                }
            }
        };
    }

    macro_rules! impl_specifier {
        ($name:tt, $id:expr) => {
            struct $name;

            impl KeySpecifier for $name {
                fn arti_path(&self) -> Result<ArtiPath> {
                    ArtiPath::new($id.into())
                }

                fn ctor_path(&self) -> Option<crate::CTorPath> {
                    None
                }
            }
        };
    }

    impl_keystore!(Keystore1, "keystore1");
    impl_keystore!(Keystore2, "keystore2");
    impl_keystore!(Keystore3, "keystore3");

    impl_specifier!(TestKeySpecifier1, "spec1");
    impl_specifier!(TestKeySpecifier2, "spec2");
    impl_specifier!(TestKeySpecifier3, "spec3");

    #[test]
    fn insert_and_get() {
        let mgr = KeyMgr::new(
            Keystore1::default(),
            vec![Keystore2::new_boxed(), Keystore3::new_boxed()],
        );

        // Insert a key into Keystore2
        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore2_coot".to_string())
        );

        // Insert a different key using the _same_ key specifier.
        mgr.insert(
            "gull".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
        )
        .unwrap();
        // Check that the original value was overwritten:
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore2_gull".to_string())
        );

        // Insert a key into the default keystore
        mgr.insert(
            "moorhen".to_string(),
            &TestKeySpecifier2,
            KeystoreSelector::Default,
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier2).unwrap(),
            Some("keystore1_moorhen".to_string())
        );

        // The key doesn't exist in any of the stores yet.
        assert!(mgr.get::<TestKey>(&TestKeySpecifier3).unwrap().is_none());

        // Insert the same key into all 3 key stores, in reverse order of keystore priority
        // (otherwise KeyMgr::get will return the key from the default store for each iteration and
        // we won't be able to see the key was actually inserted in each store).
        for store in ["keystore3", "keystore2", "keystore1"] {
            mgr.insert(
                "cormorant".to_string(),
                &TestKeySpecifier3,
                KeystoreSelector::Id(&KeystoreId::from_str(store).unwrap()),
            )
            .unwrap();

            // Ensure the key now exists in `store`.
            assert_eq!(
                mgr.get::<TestKey>(&TestKeySpecifier3).unwrap(),
                Some(format!("{store}_cormorant"))
            );
        }

        // The key exists in all key stores, but if no keystore_id is specified, we return the
        // value from the first key store it is found in (in this case, Keystore1)
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier3).unwrap(),
            Some("keystore1_cormorant".to_string())
        );
    }

    #[test]
    fn remove() {
        let mgr = KeyMgr::new(
            Keystore1::default(),
            vec![Keystore2::new_boxed(), Keystore3::new_boxed()],
        );

        assert!(!mgr.key_stores[0]
            .contains(&TestKeySpecifier1, TestKey::key_type())
            .unwrap());

        // Insert a key into Keystore2
        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore2_coot".to_string())
        );

        // Try to remove the key from a non-existent key store
        assert!(mgr
            .remove::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("not_an_id_we_know_of").unwrap())
            )
            .is_err());
        // The key still exists in Keystore2
        assert!(mgr.key_stores[0]
            .contains(&TestKeySpecifier1, TestKey::key_type())
            .unwrap());

        // Try to remove the key from the default key store
        assert_eq!(
            mgr.remove::<TestKey>(&TestKeySpecifier1, KeystoreSelector::Default)
                .unwrap(),
            None
        );

        // The key still exists in Keystore2
        assert!(mgr.key_stores[0]
            .contains(&TestKeySpecifier1, TestKey::key_type())
            .unwrap());

        // Removing from Keystore2 should succeed.
        assert_eq!(
            mgr.remove::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap())
            )
            .unwrap(),
            Some(())
        );

        // The key doesn't exist in Keystore2 anymore
        assert!(!mgr.key_stores[0]
            .contains(&TestKeySpecifier1, TestKey::key_type())
            .unwrap());
    }

    #[test]
    fn keygen() {
        let mgr = KeyMgr::new(Keystore1::default(), vec![]);

        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Default,
        )
        .unwrap();

        // Try to generate a new key (overwrite = false)
        mgr.generate::<TestKey>(
            &TestKeySpecifier1,
            KeystoreSelector::Default,
            &mut testing_rng(),
            false,
        )
        .unwrap();

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore1_coot".to_string())
        );

        // Try to generate a new key (overwrite = true)
        mgr.generate::<TestKey>(
            &TestKeySpecifier1,
            KeystoreSelector::Default,
            &mut testing_rng(),
            true,
        )
        .unwrap();

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore1_generated_test_key".to_string())
        );
    }
}
