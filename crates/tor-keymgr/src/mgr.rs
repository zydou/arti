//! Code for managing multiple [`Keystore`](crate::Keystore)s.
//!
//! See the [`KeyMgr`] docs for more details.

use crate::{
    BoxedKeystore, EncodableKey, KeyPath, KeyPathError, KeyPathInfo, KeyPathInfoExtractor,
    KeyPathPattern, KeySpecifier, KeyType, Keygen, KeygenRng, KeystoreId, KeystoreSelector, Result,
    ToEncodableKey,
};

use itertools::Itertools;
use std::iter;
use std::result::Result as StdResult;
use tor_error::{bad_api_usage, internal};

// TODO: unify get()/get_with_type() and remove()/remove_with_type()

/// A key manager that acts as a frontend to a default [`Keystore`](crate::Keystore) and
/// any number of secondary [`Keystore`](crate::Keystore)s.
///
/// Note: [`KeyMgr`] is a low-level utility and does not implement caching (the key stores are
/// accessed for every read/write).
///
/// The `KeyMgr` accessors - [`get()`](KeyMgr::get), [`get_with_type()`](KeyMgr::get_with_type) -
/// search the configured key stores in order: first the default key store,
/// and then the secondary stores, in order.
///
///
/// ## Concurrent key store access
///
/// The key stores will allow concurrent modification by different processes. In
/// order to implement this safely without locking, the key store operations (get,
/// insert, remove) will need to be atomic.
///
/// **Note**: [`KeyMgr::generate`] and [`KeyMgr::get_or_generate`] should **not** be used
/// concurrently with any other `KeyMgr` operation that mutates the same key
/// (i.e. a key with the same `ArtiPath`), because
/// their outcome depends on whether the selected key store
/// [`contains`][crate::Keystore::contains]
/// the specified key (and thus suffers from a a TOCTOU race).
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned", build_fn(private, name = "build_unvalidated"))]
pub struct KeyMgr {
    /// The default key store.
    default_store: BoxedKeystore,
    /// The secondary key stores.
    #[builder(default, setter(custom))]
    secondary_stores: Vec<BoxedKeystore>,
    /// The key info extractors.
    ///
    /// These are initialized internally by [`KeyMgrBuilder::build`], using the values collected
    /// using `inventory`.
    #[builder(default, setter(skip))]
    key_info_extractors: Vec<&'static dyn KeyPathInfoExtractor>,
}

impl KeyMgrBuilder {
    /// Construct a [`KeyMgr`] from this builder.
    pub fn build(self) -> StdResult<KeyMgr, KeyMgrBuilderError> {
        let mut keymgr = self.build_unvalidated()?;

        keymgr.key_info_extractors = inventory::iter::<&'static dyn KeyPathInfoExtractor>
            .into_iter()
            .copied()
            .collect();

        Ok(keymgr)
    }
}

// TODO: auto-generate using define_list_builder_accessors/define_list_builder_helper
// when that becomes possible.
//
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1760#note_2969841
impl KeyMgrBuilder {
    /// Access the being-built list of secondary stores (resolving default)
    ///
    /// If the field has not yet been set or accessed, the default list will be
    /// constructed and a mutable reference to the now-defaulted list of builders
    /// will be returned.
    pub fn secondary_stores(&mut self) -> &mut Vec<BoxedKeystore> {
        self.secondary_stores.get_or_insert(Default::default())
    }

    /// Set the whole list (overriding the default)
    pub fn set_secondary_stores(mut self, list: Vec<BoxedKeystore>) -> Self {
        self.secondary_stores = Some(list);
        self
    }

    /// Inspect the being-built list (with default unresolved)
    ///
    /// If the list has not yet been set, or accessed, `&None` is returned.
    pub fn opt_secondary_stores(&self) -> &Option<Vec<BoxedKeystore>> {
        &self.secondary_stores
    }

    /// Mutably access the being-built list (with default unresolved)
    ///
    /// If the list has not yet been set, or accessed, `&mut None` is returned.
    pub fn opt_secondary_stores_mut(&mut self) -> &mut Option<Vec<BoxedKeystore>> {
        &mut self.secondary_stores
    }
}

inventory::collect!(&'static dyn crate::KeyPathInfoExtractor);

impl KeyMgr {
    /// Read a key from one of the key stores, and try to deserialize it as `K::Key`.
    ///
    /// The key returned is retrieved from the first key store that contains an entry for the given
    /// specifier.
    ///
    /// Returns `Ok(None)` if none of the key stores have the requested key.
    pub fn get<K: ToEncodableKey>(&self, key_spec: &dyn KeySpecifier) -> Result<Option<K>> {
        self.get_from_store(key_spec, &K::Key::key_type(), self.all_stores())
    }

    /// Read a key from one of the key stores, and try to deserialize it as `K::Key`.
    ///
    /// The key returned is retrieved from the first key store that contains an entry for the given
    /// specifier.
    ///
    /// Returns `Ok(None)` if none of the key stores have the requested key.
    ///
    /// Returns an error if the specified `key_type` does not match `K::Key::key_type()`.
    pub fn get_with_type<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
    ) -> Result<Option<K>> {
        self.get_from_store(key_spec, key_type, self.all_stores())
    }

    /// Read the key identified by `key_spec`.
    ///
    /// The key returned is retrieved from the first key store that contains an entry for the given
    /// specifier.
    ///
    /// If the requested key does not exist in any of the key stores, this generates a new key of
    /// type `K` from the key created using using `K::Key`'s [`Keygen`] implementation, and inserts
    /// it into the specified keystore, returning the newly inserted value.
    ///
    /// This is a convenience wrapper around [`get()`](KeyMgr::get) and
    /// [`generate()`](KeyMgr::generate).
    pub fn get_or_generate<K>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
        rng: &mut dyn KeygenRng,
    ) -> Result<K>
    where
        K: ToEncodableKey,
        K::Key: Keygen,
    {
        match self.get(key_spec)? {
            Some(k) => Ok(k),
            None => self.generate(key_spec, selector, rng, false),
        }
    }

    /// Generate a new key of type `K`, and insert it into the key store specified by `selector`.
    ///
    /// If the key already exists in the specified key store, the `overwrite` flag is used to
    /// decide whether to overwrite it with a newly generated key.
    ///
    /// On success, this function returns the newly generated key.
    ///
    /// Returns [`Error::KeyAlreadyExists`](crate::Error::KeyAlreadyExists)
    /// if the key already exists in the specified key store and `overwrite` is `false`.
    ///
    /// **IMPORTANT**: using this function concurrently with any other `KeyMgr` operation that
    /// mutates the key store state is **not** recommended, as it can yield surprising results! The
    /// outcome of [`KeyMgr::generate`] depends on whether the selected key store
    /// [`contains`][crate::Keystore::contains] the specified key, and thus suffers from a a TOCTOU race.
    //
    // TODO (#1119): can we make this less racy without a lock? Perhaps we should say we'll always
    // overwrite any existing keys.
    //
    // TODO: consider replacing the overwrite boolean with a GenerateOptions type
    // (sort of like std::fs::OpenOptions)
    pub fn generate<K>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
        rng: &mut dyn KeygenRng,
        overwrite: bool,
    ) -> Result<K>
    where
        K: ToEncodableKey,
        K::Key: Keygen,
    {
        let store = self.select_keystore(&selector)?;
        let key_type = K::Key::key_type();

        if overwrite || !store.contains(key_spec, &key_type)? {
            let key = K::Key::generate(rng)?;
            store.insert(&key, key_spec, &key_type)?;

            Ok(K::from_encodable_key(key))
        } else {
            Err(crate::Error::KeyAlreadyExists)
        }
    }

    /// Insert `key` into the [`Keystore`](crate::Keystore) specified by `selector`.
    ///
    /// If the key already exists, it is overwritten.
    ///
    /// Returns an error if the selected keystore is not the default keystore or one of the
    /// configured secondary stores.
    ///
    // TODO (#1115): would it be useful for this API to return a Result<Option<K>> here (i.e. the old key)?
    pub fn insert<K: ToEncodableKey>(
        &self,
        key: K,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<()> {
        let key = key.to_encodable_key();
        let store = self.select_keystore(&selector)?;

        store.insert(&key, key_spec, &K::Key::key_type())
    }

    /// Remove the key identified by `key_spec` from the [`Keystore`](crate::Keystore)
    /// specified by `selector`.
    ///
    /// Returns an error if the selected keystore is not the default keystore or one of the
    /// configured secondary stores.
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

        store.remove(key_spec, &K::Key::key_type())
    }

    /// Remove the key identified by `key_spec` and `key_type` from the
    /// [`Keystore`](crate::Keystore) specified by `selector`.
    ///
    /// Like [`KeyMgr::remove`], except this function takes an explicit
    /// [`&KeyType`](crate::KeyType) argument instead
    /// of obtaining it from the specified type's [`ToEncodableKey`] implementation.
    pub fn remove_with_type(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
        selector: KeystoreSelector,
    ) -> Result<Option<()>> {
        let store = self.select_keystore(&selector)?;

        store.remove(key_spec, key_type)
    }

    /// Return the keys matching the specified [`KeyPathPattern`].
    ///
    /// NOTE: This searches for matching keys in _all_ keystores.
    pub fn list_matching(&self, pat: &KeyPathPattern) -> Result<Vec<(KeyPath, KeyType)>> {
        self.all_stores()
            .map(|store| -> Result<Vec<_>> {
                Ok(store
                    .list()?
                    .into_iter()
                    .filter(|(key_path, _): &(KeyPath, KeyType)| key_path.matches(pat).is_some())
                    .collect::<Vec<_>>())
            })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
    }

    /// Describe the specified key.
    ///
    /// Returns [`KeyPathError::Unrecognized`] if none of the registered
    /// [`KeyPathInfoExtractor`]s is able to parse the specified [`KeyPath`].
    ///
    /// This function uses the [`KeyPathInfoExtractor`]s registered using
    /// [`register_key_info_extractor`](crate::register_key_info_extractor),
    /// or by [`DefaultKeySpecifier`](crate::derive_adhoc_template_KeySpecifier).
    pub fn describe(&self, path: &KeyPath) -> StdResult<KeyPathInfo, KeyPathError> {
        for info_extractor in &self.key_info_extractors {
            if let Ok(info) = info_extractor.describe(path) {
                return Ok(info);
            }
        }

        Err(KeyPathError::Unrecognized(path.clone()))
    }

    /// Attempt to retrieve a key from one of the specified `stores`.
    ///
    /// See [`KeyMgr::get`] for more details.
    fn get_from_store<'a, K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
        stores: impl Iterator<Item = &'a BoxedKeystore>,
    ) -> Result<Option<K>> {
        let static_key_type = K::Key::key_type();
        if key_type != &static_key_type {
            return Err(internal!(
                "key type {:?} does not match the key type {:?} of requested key K::Key",
                key_type,
                static_key_type
            )
            .into());
        }

        for store in stores {
            let key = match store.get(key_spec, &K::Key::key_type()) {
                Ok(None) => {
                    // The key doesn't exist in this store, so we check the next one...
                    continue;
                }
                Ok(Some(k)) => k,
                Err(e) => {
                    // TODO (#1115): we immediately return if one of the keystores is inaccessible.
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
        iter::once(&self.default_store).chain(self.secondary_stores.iter())
    }

    /// Return the [`Keystore`](crate::Keystore) matching the specified `selector`.
    ///
    /// Returns an error if the selected keystore is not the default keystore or one of the
    /// configured secondary stores.
    fn select_keystore(&self, selector: &KeystoreSelector) -> Result<&BoxedKeystore> {
        match selector {
            KeystoreSelector::Id(keystore_id) => self.find_keystore(keystore_id),
            KeystoreSelector::Default => Ok(&self.default_store),
        }
    }

    /// Return the [`Keystore`](crate::Keystore) with the specified `id`.
    ///
    /// Returns an error if the specified ID is not the ID of the default keystore or
    /// the ID of one of the configured secondary stores.
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
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{ArtiPath, ArtiPathUnavailableError, ErasedKey, KeyPath, KeyType, SshKeyData};
    use std::collections::HashMap;
    use std::result::Result as StdResult;
    use std::str::FromStr;
    use std::sync::RwLock;
    use tor_basic_utils::test_rng::testing_rng;

    /// The type of "key" stored in the test key stores.
    type TestKey = String;

    /// The corresponding fake public key type.
    type TestPublicKey = String;

    impl Keygen for TestKey {
        fn generate(_rng: &mut dyn KeygenRng) -> Result<Self>
        where
            Self: Sized,
        {
            Ok("generated_test_key".into())
        }
    }

    impl EncodableKey for TestKey {
        fn key_type() -> KeyType
        where
            Self: Sized,
        {
            // Dummy value
            KeyType::Ed25519Keypair
        }

        fn as_ssh_key_data(&self) -> Result<SshKeyData> {
            // (Ab)use the encrypted variant for testing purposes
            Ok(SshKeyData::Private(
                ssh_key::private::KeypairData::Encrypted(self.as_bytes().to_vec()),
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

            impl crate::Keystore for $name {
                fn contains(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: &KeyType,
                ) -> Result<bool> {
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .contains_key(&(key_spec.arti_path().unwrap(), key_type.clone())))
                }

                fn id(&self) -> &KeystoreId {
                    &self.id
                }

                fn get(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: &KeyType,
                ) -> Result<Option<ErasedKey>> {
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .get(&(key_spec.arti_path().unwrap(), key_type.clone()))
                        .map(|k| Box::new(k.clone()) as Box<dyn EncodableKey>))
                }

                fn insert(
                    &self,
                    key: &dyn EncodableKey,
                    key_spec: &dyn KeySpecifier,
                    key_type: &KeyType,
                ) -> Result<()> {
                    let key = key.as_ssh_key_data()?;
                    let key_bytes = key.into_private().unwrap().encrypted().unwrap().to_vec();

                    let value = String::from_utf8(key_bytes).unwrap();

                    self.inner.write().unwrap().insert(
                        (key_spec.arti_path().unwrap(), key_type.clone()),
                        format!("{}_{value}", self.id()),
                    );

                    Ok(())
                }

                fn remove(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: &KeyType,
                ) -> Result<Option<()>> {
                    Ok(self
                        .inner
                        .write()
                        .unwrap()
                        .remove(&(key_spec.arti_path().unwrap(), key_type.clone()))
                        .map(|_| ()))
                }

                fn list(&self) -> Result<Vec<(KeyPath, KeyType)>> {
                    // These tests don't use this function
                    unimplemented!()
                }
            }
        };
    }

    macro_rules! impl_specifier {
        ($name:tt, $id:expr) => {
            struct $name;

            impl KeySpecifier for $name {
                fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError> {
                    Ok(ArtiPath::new($id.into()).map_err(|e| tor_error::internal!("{e}"))?)
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

    impl_specifier!(TestPublicKeySpecifier1, "pub-spec1");

    #[test]
    fn insert_and_get() {
        let mut builder = KeyMgrBuilder::default().default_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

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
        let mut builder = KeyMgrBuilder::default().default_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        assert!(!mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
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
        assert!(mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
            .unwrap());

        // Try to remove the key from the default key store
        assert_eq!(
            mgr.remove::<TestKey>(&TestKeySpecifier1, KeystoreSelector::Default)
                .unwrap(),
            None
        );

        // The key still exists in Keystore2
        assert!(mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
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
        assert!(!mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
            .unwrap());
    }

    #[test]
    fn keygen() {
        let mgr = KeyMgrBuilder::default()
            .default_store(Box::<Keystore1>::default())
            .build()
            .unwrap();

        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Default,
        )
        .unwrap();

        // There is no corresponding public key entry.
        assert_eq!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1).unwrap(),
            None
        );

        // Try to generate a new key (overwrite = false)
        let err = mgr
            .generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Default,
                &mut testing_rng(),
                false,
            )
            .unwrap_err();

        assert!(matches!(err, crate::Error::KeyAlreadyExists));

        // The previous entry was not overwritten because overwrite = false
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore1_coot".to_string())
        );

        // We don't store public keys in the keystore
        assert_eq!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1).unwrap(),
            None,
        );

        // Try to generate a new key (overwrite = true)
        let key = mgr
            .generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Default,
                &mut testing_rng(),
                true,
            )
            .unwrap();

        assert_eq!(key, "generated_test_key".to_string());

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1).unwrap(),
            Some("keystore1_generated_test_key".to_string())
        );

        // We don't store public keys in the keystore
        assert_eq!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1).unwrap(),
            None,
        );
    }

    #[test]
    fn get_or_generate() {
        let mut builder = KeyMgrBuilder::default().default_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        let keystore2 = KeystoreId::from_str("keystore2").unwrap();
        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&keystore2),
        )
        .unwrap();

        // The key already exists in keystore 2 so it won't be auto-generated.
        assert_eq!(
            mgr.get_or_generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Default,
                &mut testing_rng()
            )
            .unwrap(),
            "keystore2_coot".to_string()
        );

        // This key doesn't exist in any of the keystores, so it will be auto-generated and
        // inserted into keystore 3.
        let keystore3 = KeystoreId::from_str("keystore3").unwrap();
        assert_eq!(
            mgr.get_or_generate::<TestKey>(
                &TestKeySpecifier2,
                KeystoreSelector::Id(&keystore3),
                &mut testing_rng()
            )
            .unwrap(),
            "generated_test_key".to_string()
        );

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier2).unwrap(),
            Some("keystore3_generated_test_key".to_string())
        );
    }
}
