//! Code for managing multiple [`Keystore`](crate::Keystore)s.
//!
//! See the [`KeyMgr`] docs for more details.

use crate::{
    BoxedKeystore, KeyPath, KeyPathError, KeyPathInfo, KeyPathInfoExtractor, KeyPathPattern,
    KeySpecifier, KeystoreId, KeystoreSelector, Result,
};

use itertools::Itertools;
use std::iter;
use std::result::Result as StdResult;
use tor_error::{bad_api_usage, internal};
use tor_key_forge::{EncodableKey, KeyType, Keygen, KeygenRng, ToEncodableKey};

/// A key manager that acts as a frontend to a primary [`Keystore`](crate::Keystore) and
/// any number of secondary [`Keystore`](crate::Keystore)s.
///
/// Note: [`KeyMgr`] is a low-level utility and does not implement caching (the key stores are
/// accessed for every read/write).
///
/// The `KeyMgr` accessors - currently just [`get()`](KeyMgr::get) -
/// search the configured key stores in order: first the primary key store,
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
/// the specified key (and thus suffers from a TOCTOU race).
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned", build_fn(private, name = "build_unvalidated"))]
pub struct KeyMgr {
    /// The primary key store.
    primary_store: BoxedKeystore,
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

/// A keystore entry descriptor.
///
/// This identifies a key entry from a specific keystore.
/// The key entry can be retrieved, using [`KeyMgr::get_entry`],
/// or removed, using [`KeyMgr::remove_entry`].
///
/// Returned from [`KeyMgr::list_matching`].
#[derive(Clone, Debug, PartialEq, amplify::Getters)]
pub struct KeystoreEntry<'a> {
    /// The [`KeyPath`] of the key.
    key_path: KeyPath,
    /// The [`KeyType`] of the key.
    key_type: KeyType,
    /// The [`KeystoreId`] that of the keystore where the key was found.
    #[getter(as_copy)]
    keystore_id: &'a KeystoreId,
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
        let result = self.get_from_store(key_spec, &K::Key::key_type(), self.all_stores())?;
        if result.is_none() {
            // If the key_spec is the specifier for the public part of a keypair,
            // try getting the pair and extracting the public portion from it.
            if let Some(key_pair_spec) = key_spec.keypair_specifier() {
                return Ok(self.get::<K::KeyPair>(&*key_pair_spec)?.map(|k| k.into()));
            }
        }
        Ok(result)
    }

    /// Retrieve the specified keystore entry, and try to deserialize it as `K::Key`.
    ///
    /// The key returned is retrieved from the key store specified in the [`KeystoreEntry`].
    ///
    /// Returns `Ok(None)` if the key store does not contain the requested entry.
    ///
    /// Returns an error if the specified `key_type` does not match `K::Key::key_type()`.
    pub fn get_entry<K: ToEncodableKey>(&self, entry: &KeystoreEntry) -> Result<Option<K>> {
        let selector = entry.keystore_id().into();
        let store = self.select_keystore(&selector)?;
        self.get_from_store(entry.key_path(), entry.key_type(), [store].into_iter())
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
    /// [`contains`][crate::Keystore::contains] the specified key, and thus suffers from a TOCTOU race.
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
    /// If the key already exists in the specified key store, the `overwrite` flag is used to
    /// decide whether to overwrite it with the provided key.
    ///
    /// If this key is not already in the keystore, `None` is returned.
    ///
    /// If this key already exists in the keystore, its value is updated
    /// and the old value is returned.
    ///
    /// Returns an error if the selected keystore is not the primary keystore or one of the
    /// configured secondary stores.
    pub fn insert<K: ToEncodableKey>(
        &self,
        key: K,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
        overwrite: bool,
    ) -> Result<Option<K>> {
        let key = key.to_encodable_key();
        let store = self.select_keystore(&selector)?;
        let key_type = K::Key::key_type();
        let old_key: Option<K> = self.get_from_store(key_spec, &key_type, [store].into_iter())?;

        if old_key.is_some() && !overwrite {
            Err(crate::Error::KeyAlreadyExists)
        } else {
            let () = store.insert(&key, key_spec, &key_type)?;
            Ok(old_key)
        }
    }

    /// Remove the key identified by `key_spec` from the [`Keystore`](crate::Keystore)
    /// specified by `selector`.
    ///
    /// Returns an error if the selected keystore is not the primary keystore or one of the
    /// configured secondary stores.
    ///
    /// Returns the value of the removed key,
    /// or `Ok(None)` if the key does not exist in the requested keystore.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    pub fn remove<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<Option<K>> {
        let store = self.select_keystore(&selector)?;
        let key_type = K::Key::key_type();
        let old_key: Option<K> = self.get_from_store(key_spec, &key_type, [store].into_iter())?;

        store.remove(key_spec, &key_type)?;

        Ok(old_key)
    }

    /// Remove the specified keystore entry.
    ///
    /// Like [`KeyMgr::remove`], except this function does not return the value of the removed key.
    ///
    /// A return value of `Ok(None)` indicates the key was not found in the specified key store,
    /// whereas `Ok(Some(())` means the key was successfully removed.
    //
    // TODO: We should be consistent and return the removed key.
    //
    // This probably will involve changing the return type of Keystore::remove
    // to Result<Option<ErasedKey>>.
    pub fn remove_entry(&self, entry: &KeystoreEntry) -> Result<Option<()>> {
        let selector = entry.keystore_id().into();
        let store = self.select_keystore(&selector)?;

        store.remove(entry.key_path(), entry.key_type())
    }

    /// Return the keystore entry descriptors of the keys matching the specified [`KeyPathPattern`].
    ///
    /// NOTE: This searches for matching keys in _all_ keystores.
    pub fn list_matching(&self, pat: &KeyPathPattern) -> Result<Vec<KeystoreEntry>> {
        self.all_stores()
            .map(|store| -> Result<Vec<_>> {
                Ok(store
                    .list()?
                    .into_iter()
                    .filter(|(key_path, _): &(KeyPath, KeyType)| key_path.matches(pat).is_some())
                    .map(|(path, key_type)| KeystoreEntry {
                        key_path: path.clone(),
                        key_type,
                        keystore_id: store.id(),
                    })
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
    /// or by [`DefaultKeySpecifier`](crate::derive_deftly_template_KeySpecifier).
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
                    // Note: we immediately return if one of the keystores is inaccessible.
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
        iter::once(&self.primary_store).chain(self.secondary_stores.iter())
    }

    /// Return the [`Keystore`](crate::Keystore) matching the specified `selector`.
    ///
    /// Returns an error if the selected keystore is not the primary keystore or one of the
    /// configured secondary stores.
    fn select_keystore(&self, selector: &KeystoreSelector) -> Result<&BoxedKeystore> {
        match selector {
            KeystoreSelector::Id(keystore_id) => self.find_keystore(keystore_id),
            KeystoreSelector::Primary => Ok(&self.primary_store),
        }
    }

    /// Return the [`Keystore`](crate::Keystore) with the specified `id`.
    ///
    /// Returns an error if the specified ID is not the ID of the primary keystore or
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
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{ArtiPath, ArtiPathUnavailableError, KeyPath};
    use std::collections::HashMap;
    use std::result::Result as StdResult;
    use std::str::FromStr;
    use std::sync::RwLock;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_key_forge::{EncodableKey, ErasedKey, SshKeyData};
    use tor_llcrypto::pk::ed25519;

    /// The type of "key" stored in the test key stores.
    #[derive(Clone, Debug)]
    struct TestKey {
        /// The underlying key.
        key: SshKeyData,
        /// Some metadata about the key
        meta: String,
    }

    /// The corresponding fake public key type.
    #[derive(Clone, Debug)]
    struct TestPublicKey {
        /// The underlying key.
        key: SshKeyData,
    }

    impl From<TestKey> for TestPublicKey {
        fn from(tk: TestKey) -> TestPublicKey {
            TestPublicKey { key: tk.key }
        }
    }

    impl TestKey {
        /// Create a new test key with the specified metadata.
        fn new(meta: &str) -> Self {
            let mut rng = testing_rng();
            TestKey {
                key: ed25519::Keypair::generate(&mut rng)
                    .as_ssh_key_data()
                    .unwrap(),
                meta: meta.into(),
            }
        }
    }

    impl Keygen for TestKey {
        fn generate(mut rng: &mut dyn KeygenRng) -> tor_key_forge::Result<Self>
        where
            Self: Sized,
        {
            Ok(TestKey {
                key: ed25519::Keypair::generate(&mut rng).as_ssh_key_data()?,
                meta: "generated_test_key".into(),
            })
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

        fn as_ssh_key_data(&self) -> tor_key_forge::Result<SshKeyData> {
            Ok(self.key.clone())
        }
    }

    impl ToEncodableKey for TestKey {
        type Key = Self;
        type KeyPair = Self;

        fn to_encodable_key(self) -> Self::Key {
            self
        }

        fn from_encodable_key(key: Self::Key) -> Self {
            key
        }
    }

    impl EncodableKey for TestPublicKey {
        fn key_type() -> KeyType
        where
            Self: Sized,
        {
            KeyType::Ed25519PublicKey
        }

        fn as_ssh_key_data(&self) -> tor_key_forge::Result<SshKeyData> {
            Ok(self.key.clone())
        }
    }

    impl ToEncodableKey for TestPublicKey {
        type Key = Self;
        type KeyPair = TestKey;

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
                    let key = key.downcast_ref::<TestKey>().unwrap();
                    let value = &key.meta;
                    let key = TestKey {
                        key: key.as_ssh_key_data()?,
                        meta: format!("{}_{value}", self.id()),
                    };

                    self.inner
                        .write()
                        .unwrap()
                        .insert((key_spec.arti_path().unwrap(), key_type.clone()), key);

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
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .iter()
                        .map(|((arti_path, key_type), _)| {
                            (KeyPath::Arti(arti_path.clone()), key_type.clone())
                        })
                        .collect())
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

                fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
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
    impl_specifier!(TestKeySpecifier4, "spec4");

    impl_specifier!(TestPublicKeySpecifier1, "pub-spec1");

    /// Create a test `KeystoreEntry`.
    fn entry_descriptor(specifier: impl KeySpecifier, keystore_id: &KeystoreId) -> KeystoreEntry {
        KeystoreEntry {
            key_path: specifier.arti_path().unwrap().into(),
            key_type: TestKey::key_type(),
            keystore_id,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        // Insert a key into Keystore2
        let old_key = mgr
            .insert(
                TestKey::new("coot"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                true,
            )
            .unwrap();

        assert!(old_key.is_none());
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore2_coot".to_string()),
        );

        // Insert a different key using the _same_ key specifier.
        let old_key = mgr
            .insert(
                TestKey::new("gull"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                true,
            )
            .unwrap()
            .unwrap()
            .meta;
        assert_eq!(old_key, "keystore2_coot");
        // Check that the original value was overwritten:
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore2_gull".to_string()),
        );

        // Insert a different key using the _same_ key specifier (overwrite = false)
        let err = mgr
            .insert(
                TestKey::new("gull"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                false,
            )
            .unwrap_err();
        assert!(matches!(err, crate::Error::KeyAlreadyExists));

        // Insert a new key into Keystore2 (overwrite = false)
        let old_key = mgr
            .insert(
                TestKey::new("penguin"),
                &TestKeySpecifier2,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                false,
            )
            .unwrap();
        assert!(old_key.is_none());

        // Insert a key into the primary keystore
        let old_key = mgr
            .insert(
                TestKey::new("moorhen"),
                &TestKeySpecifier3,
                KeystoreSelector::Primary,
                true,
            )
            .unwrap();
        assert!(old_key.is_none());
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier3)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore1_moorhen".to_string())
        );

        // The key doesn't exist in any of the stores yet.
        assert!(mgr.get::<TestKey>(&TestKeySpecifier4).unwrap().is_none());

        // Insert the same key into all 3 key stores, in reverse order of keystore priority
        // (otherwise KeyMgr::get will return the key from the primary store for each iteration and
        // we won't be able to see the key was actually inserted in each store).
        for store in ["keystore3", "keystore2", "keystore1"] {
            let old_key = mgr
                .insert(
                    TestKey::new("cormorant"),
                    &TestKeySpecifier4,
                    KeystoreSelector::Id(&KeystoreId::from_str(store).unwrap()),
                    true,
                )
                .unwrap();
            assert!(old_key.is_none());

            // Ensure the key now exists in `store`.
            assert_eq!(
                mgr.get::<TestKey>(&TestKeySpecifier4)
                    .unwrap()
                    .map(|k| k.meta),
                Some(format!("{store}_cormorant"))
            );
        }

        // The key exists in all key stores, but if no keystore_id is specified, we return the
        // value from the first key store it is found in (in this case, Keystore1)
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier4)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore1_cormorant".to_string())
        );
    }

    #[test]
    fn remove() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        assert!(!mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
            .unwrap());

        // Insert a key into Keystore2
        mgr.insert(
            TestKey::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
            true,
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1)
                .unwrap()
                .map(|k| k.meta),
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

        // Try to remove the key from the primary key store
        assert!(mgr
            .remove::<TestKey>(&TestKeySpecifier1, KeystoreSelector::Primary)
            .unwrap()
            .is_none(),);

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
            .unwrap()
            .map(|k| k.meta),
            Some("keystore2_coot".to_string())
        );

        // The key doesn't exist in Keystore2 anymore
        assert!(!mgr.secondary_stores[0]
            .contains(&TestKeySpecifier1, &TestKey::key_type())
            .unwrap());
    }

    #[test]
    fn keygen() {
        let mgr = KeyMgrBuilder::default()
            .primary_store(Box::<Keystore1>::default())
            .build()
            .unwrap();

        mgr.insert(
            TestKey::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Primary,
            true,
        )
        .unwrap();

        // There is no corresponding public key entry.
        assert!(mgr
            .get::<TestPublicKey>(&TestPublicKeySpecifier1)
            .unwrap()
            .is_none(),);

        // Try to generate a new key (overwrite = false)
        let err = mgr
            .generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Primary,
                &mut testing_rng(),
                false,
            )
            .unwrap_err();

        assert!(matches!(err, crate::Error::KeyAlreadyExists));

        // The previous entry was not overwritten because overwrite = false
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore1_coot".to_string())
        );

        // We don't store public keys in the keystore
        assert!(mgr
            .get::<TestPublicKey>(&TestPublicKeySpecifier1)
            .unwrap()
            .is_none(),);

        // Try to generate a new key (overwrite = true)
        let key = mgr
            .generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Primary,
                &mut testing_rng(),
                true,
            )
            .unwrap();

        assert_eq!(key.meta, "generated_test_key".to_string());

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore1_generated_test_key".to_string())
        );

        // We don't store public keys in the keystore
        assert!(mgr
            .get::<TestPublicKey>(&TestPublicKeySpecifier1)
            .unwrap()
            .is_none(),);
    }

    #[test]
    fn get_or_generate() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        let keystore2 = KeystoreId::from_str("keystore2").unwrap();
        let entry_desc1 = entry_descriptor(TestKeySpecifier1, &keystore2);
        assert!(mgr.get_entry::<TestKey>(&entry_desc1).unwrap().is_none());

        mgr.insert(
            TestKey::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&keystore2),
            true,
        )
        .unwrap();

        // The key already exists in keystore 2 so it won't be auto-generated.
        assert_eq!(
            mgr.get_or_generate::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Primary,
                &mut testing_rng()
            )
            .unwrap()
            .meta,
            "keystore2_coot".to_string(),
        );

        assert_eq!(
            mgr.get_entry::<TestKey>(&entry_desc1)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore2_coot".to_string())
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
            .unwrap()
            .meta,
            "generated_test_key".to_string(),
        );

        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier2)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore3_generated_test_key".to_string())
        );

        let entry_desc2 = entry_descriptor(TestKeySpecifier2, &keystore3);
        assert_eq!(
            mgr.get_entry::<TestKey>(&entry_desc2)
                .unwrap()
                .map(|k| k.meta),
            Some("keystore3_generated_test_key".to_string()),
        );

        let arti_pat = KeyPathPattern::Arti("*".to_string());
        let matching = mgr.list_matching(&arti_pat).unwrap();

        assert_eq!(matching.len(), 2);
        assert!(matching.contains(&entry_desc1));
        assert!(matching.contains(&entry_desc2));

        assert_eq!(mgr.remove_entry(&entry_desc2).unwrap(), Some(()));
        assert!(mgr.get_entry::<TestKey>(&entry_desc2).unwrap().is_none());
        assert!(mgr.remove_entry(&entry_desc2).unwrap().is_none());
    }
}
