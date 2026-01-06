//! Code for managing multiple [`Keystore`](crate::Keystore)s.
//!
//! See the [`KeyMgr`] docs for more details.

use crate::raw::{RawEntryId, RawKeystoreEntry};
use crate::{
    ArtiPath, BoxedKeystore, KeyCertificateSpecifier, KeyPath, KeyPathInfo, KeyPathInfoExtractor,
    KeyPathPattern, KeySpecifier, KeystoreCorruptionError, KeystoreEntryResult, KeystoreId,
    KeystoreSelector, Result,
};

use itertools::Itertools;
use std::iter;
use std::result::Result as StdResult;
use tor_error::{bad_api_usage, internal, into_bad_api_usage};
use tor_key_forge::{
    ItemType, Keygen, KeygenRng, KeystoreItemType, ToEncodableCert, ToEncodableKey,
};

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
    /// The [`KeystoreItemType`] of the key.
    key_type: KeystoreItemType,
    /// The [`KeystoreId`] of the keystore where the key was found.
    #[getter(as_copy)]
    keystore_id: &'a KeystoreId,
    /// The [`RawEntryId`] of the key, an identifier used in
    /// `arti raw` operations.
    #[getter(skip)]
    raw_id: RawEntryId,
}

impl<'a> KeystoreEntry<'a> {
    /// Create a new `KeystoreEntry`
    pub(crate) fn new(
        key_path: KeyPath,
        key_type: KeystoreItemType,
        keystore_id: &'a KeystoreId,
        raw_id: RawEntryId,
    ) -> Self {
        Self {
            key_path,
            key_type,
            keystore_id,
            raw_id,
        }
    }

    /// Return an instance of [`RawKeystoreEntry`]
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn raw_entry(&self) -> RawKeystoreEntry {
        RawKeystoreEntry::new(self.raw_id.clone(), self.keystore_id.clone())
    }
}

// NOTE: Some methods require a `KeystoreEntryResult<KeystoreEntry>` as an
// argument (e.g.: `KeyMgr::raw_keystore_entry`). For this reason  implementing
// `From<KeystoreEntry<'a>> for KeystoreEntryResult<KeystoreEntry<'a>>` makes
// `KeystoreEntry` more ergonomic.
impl<'a> From<KeystoreEntry<'a>> for KeystoreEntryResult<KeystoreEntry<'a>> {
    fn from(val: KeystoreEntry<'a>) -> Self {
        Ok(val)
    }
}

impl KeyMgrBuilder {
    /// Construct a [`KeyMgr`] from this builder.
    pub fn build(self) -> StdResult<KeyMgr, KeyMgrBuilderError> {
        use itertools::Itertools as _;

        let mut keymgr = self.build_unvalidated()?;

        if !keymgr.all_stores().map(|s| s.id()).all_unique() {
            return Err(KeyMgrBuilderError::ValidationError(
                "the keystore IDs are not pairwise unique".into(),
            ));
        }

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
        let result = self.get_from_store(key_spec, &K::Key::item_type(), self.all_stores())?;
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
    /// Returns an error if the specified `key_type` does not match `K::Key::item_type()`.
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

    /// Read a key from one of the key stores specified, and try to deserialize it as `K::Key`.
    ///
    /// Returns `Ok(None)` if none of the key stores have the requested key.
    ///
    /// Returns an error if the specified keystore does not exist.
    // TODO: The function takes `&KeystoreId`, but it would be better to accept a
    // `KeystoreSelector`.
    // This way, the caller can pass `KeystoreSelector::Primary` directly without
    // needing to know the specific `KeystoreId` of the primary keystore.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn get_from<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        keystore_id: &KeystoreId,
    ) -> Result<Option<K>> {
        let store = std::iter::once(self.find_keystore(keystore_id)?);
        self.get_from_store(key_spec, &K::Key::item_type(), store)
    }

    /// Validates the integrity of a [`KeystoreEntry`].
    ///
    /// This retrieves the key corresponding to the provided [`KeystoreEntry`],
    /// and checks if its contents are valid (i.e. that the key can be parsed).
    /// The [`KeyPath`] of the entry is further validated using [`describe`](KeyMgr::describe).
    ///
    /// Returns `Ok(())` if the specified keystore entry is valid, and `Err` otherwise.
    ///
    /// NOTE: If the specified entry does not exist, this will only validate its [`KeyPath`].
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn validate_entry_integrity(&self, entry: &KeystoreEntry) -> Result<()> {
        let selector = entry.keystore_id().into();
        let store = self.select_keystore(&selector)?;
        // Ignore the parsed key, only checking if it parses correctly
        let _ = store.get(entry.key_path(), entry.key_type())?;

        let path = entry.key_path();
        // Ignore the result, just checking if the path is recognized
        let _ = self
            .describe(path)
            .ok_or_else(|| KeystoreCorruptionError::Unrecognized(path.clone()))?;

        Ok(())
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

        if overwrite || !store.contains(key_spec, &K::Key::item_type())? {
            let key = K::Key::generate(rng)?;
            store.insert(&key, key_spec)?;

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
        let key_type = K::Key::item_type();
        let old_key: Option<K> = self.get_from_store(key_spec, &key_type, [store].into_iter())?;

        if old_key.is_some() && !overwrite {
            Err(crate::Error::KeyAlreadyExists)
        } else {
            let () = store.insert(&key, key_spec)?;
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
        let key_type = K::Key::item_type();
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

    /// Remove the specified keystore entry.
    ///
    /// Similar to [`KeyMgr::remove_entry`], except this method accepts both recognized and
    /// unrecognized entries, identified by a raw id (in the form of a `&str`) and a
    /// [`KeystoreId`].
    ///
    /// Returns an error if the entry could not be removed, or if the entry doesn't exist.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn remove_unchecked(&self, raw_id: &str, keystore_id: &KeystoreId) -> Result<()> {
        let selector = KeystoreSelector::from(keystore_id);
        let store = self.select_keystore(&selector)?;
        let raw_id = store.raw_entry_id(raw_id)?;
        let store = self.select_keystore(&selector)?;
        store.remove_unchecked(&raw_id)
    }

    /// Return the keystore entry descriptors of the keys matching the specified [`KeyPathPattern`].
    ///
    /// NOTE: This searches for matching keys in _all_ keystores.
    ///
    /// NOTE: This function only returns the *recognized* entries that match the provided pattern.
    /// The unrecognized entries (i.e. those that do not have a valid [`KeyPath`]) will be filtered out,
    /// even if they match the specified pattern.
    pub fn list_matching(&self, pat: &KeyPathPattern) -> Result<Vec<KeystoreEntry>> {
        self.all_stores()
            .map(|store| -> Result<Vec<_>> {
                Ok(store
                    .list()?
                    .into_iter()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.key_path().matches(pat))
                    .collect::<Vec<_>>())
            })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
    }

    /// List keys and certificates of the specified keystore.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn list_by_id(&self, id: &KeystoreId) -> Result<Vec<KeystoreEntryResult<KeystoreEntry>>> {
        self.find_keystore(id)?.list()
    }

    /// List keys and certificates of all the keystores.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn list(&self) -> Result<Vec<KeystoreEntryResult<KeystoreEntry>>> {
        self.all_stores()
            .map(|store| -> Result<Vec<_>> { store.list() })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
    }

    /// List all the configured keystore.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn list_keystores(&self) -> Vec<KeystoreId> {
        self.all_stores()
            .map(|store| store.id().to_owned())
            .collect()
    }

    /// Describe the specified key.
    ///
    /// Returns `None` if none of the registered
    /// [`KeyPathInfoExtractor`]s is able to parse the specified [`KeyPath`].
    ///
    /// This function uses the [`KeyPathInfoExtractor`]s registered using
    /// [`register_key_info_extractor`](crate::register_key_info_extractor),
    /// or by [`DefaultKeySpecifier`](crate::derive_deftly_template_KeySpecifier).
    pub fn describe(&self, path: &KeyPath) -> Option<KeyPathInfo> {
        for info_extractor in &self.key_info_extractors {
            if let Ok(info) = info_extractor.describe(path) {
                return Some(info);
            }
        }

        None
    }

    /// Attempt to retrieve a key from one of the specified `stores`.
    ///
    /// Returns the `<K as ToEncodableKey>::Key` representation of the key.
    ///
    /// See [`KeyMgr::get`] for more details.
    fn get_from_store_raw<'a, K: ItemType>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeystoreItemType,
        stores: impl Iterator<Item = &'a BoxedKeystore>,
    ) -> Result<Option<K>> {
        let static_key_type = K::item_type();
        if key_type != &static_key_type {
            return Err(internal!(
                "key type {:?} does not match the key type {:?} of requested key K::Key",
                key_type,
                static_key_type
            )
            .into());
        }

        for store in stores {
            let key = match store.get(key_spec, &K::item_type()) {
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
            let key: K = key
                .downcast::<K>()
                .map(|k| *k)
                .map_err(|_| internal!("failed to downcast key to requested type"))?;

            return Ok(Some(key));
        }

        Ok(None)
    }

    /// Attempt to retrieve a key from one of the specified `stores`.
    ///
    /// See [`KeyMgr::get`] for more details.
    fn get_from_store<'a, K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeystoreItemType,
        stores: impl Iterator<Item = &'a BoxedKeystore>,
    ) -> Result<Option<K>> {
        let Some(key) = self.get_from_store_raw::<K::Key>(key_spec, key_type, stores)? else {
            return Ok(None);
        };

        Ok(Some(K::from_encodable_key(key)))
    }

    /// Read the specified key and certificate from one of the key stores,
    /// deserializing the subject key as `K::Key`, the cert as `C::Cert`,
    /// and the signing key as `C::SigningKey`.
    ///
    /// Returns `Ok(None)` if none of the key stores have the requested key.
    ///
    // Note: the behavior of this function is a bit inconsistent with
    // get_or_generate_key_and_cert: here, if the cert is absent but
    // its subject key is not, we return Ok(None).
    // In get_or_generate_key_and_cert, OTOH< we return an error in that case
    // (because we can't possibly generate the missing subject key
    // without overwriting the cert of the missing key).
    ///
    /// This function validates the certificate using [`ToEncodableCert::validate`],
    /// returning an error if it is invalid or missing.
    #[cfg(feature = "experimental-api")]
    pub fn get_key_and_cert<K, C>(
        &self,
        spec: &dyn KeyCertificateSpecifier,
    ) -> Result<Option<(K, C)>>
    where
        K: ToEncodableKey,
        C: ToEncodableCert<K>,
    {
        let subject_key_spec = spec.subject_key_specifier();
        // Get the subject key...
        let Some(key) =
            self.get_from_store::<K>(subject_key_spec, &K::Key::item_type(), self.all_stores())?
        else {
            return Ok(None);
        };

        let subject_key_arti_path = subject_key_spec
            .arti_path()
            .map_err(|_| bad_api_usage!("subject key does not have an ArtiPath?!"))?;
        let cert_spec =
            ArtiPath::from_path_and_denotators(subject_key_arti_path, &spec.cert_denotators())
                .map_err(into_bad_api_usage!("invalid certificate specifier"))?;

        let Some(cert) = self.get_from_store_raw::<C::ParsedCert>(
            &cert_spec,
            &<C::ParsedCert as ItemType>::item_type(),
            self.all_stores(),
        )?
        else {
            return Err(KeystoreCorruptionError::MissingCertificate.into());
        };

        // Finally, get the signing key and validate the cert
        let signed_with = self.get_cert_signing_key::<K, C>(spec)?;
        let cert = C::validate(cert, &key, &signed_with)?;

        Ok(Some((key, cert)))
    }

    /// Like [`KeyMgr::get_key_and_cert`], except this function also generates the subject key
    /// and its corresponding certificate if they don't already exist.
    ///
    /// If the key certificate is missing, it will be generated
    /// from the subject key and signing key using the provided `make_certificate` callback.
    ///
    /// Generates the missing key and/or certificate as follows:
    ///
    /// ```text
    /// | Subject Key exists | Signing Key exists | Cert exists | Action                                 |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | Y                  | Y           | Validate cert, return key and cert     |
    /// |                    |                    |             | if valid, error otherwise              |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | N                  | Y                  | N           | Generate subject key and               |
    /// |                    |                    |             | a new cert signed with signing key     |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | Y                  | N           | Generate cert signed with signing key  |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | N                  | N           | Error - cannot validate cert           |
    /// |                    |                    |             | if signing key is not available        |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y/N                | N                  | N           | Error - cannot generate cert           |
    /// |                    |                    |             | if signing key is not available        |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | N                  | Y/N                | Y           | Error - subject key was removed?       |
    /// |                    |                    |             | (we found the cert,                    |
    /// |                    |                    |             | but the subject key is missing)        |
    /// ```
    ///
    //
    // Note; the table above isn't a markdown table because CommonMark-flavor markdown
    // doesn't support multiline text in tables. Even if we trim down the text,
    // the resulting markdown table would be pretty unreadable in raw form
    // (it would have several excessively long lines, over 120 chars in len).
    #[cfg(feature = "experimental-api")]
    pub fn get_or_generate_key_and_cert<K, C>(
        &self,
        spec: &dyn KeyCertificateSpecifier,
        make_certificate: impl FnOnce(&K, &<C as ToEncodableCert<K>>::SigningKey) -> C,
        selector: KeystoreSelector,
        rng: &mut dyn KeygenRng,
    ) -> Result<(K, C)>
    where
        K: ToEncodableKey,
        K::Key: Keygen,
        C: ToEncodableCert<K>,
    {
        let subject_key_spec = spec.subject_key_specifier();
        let subject_key_arti_path = subject_key_spec
            .arti_path()
            .map_err(|_| bad_api_usage!("subject key does not have an ArtiPath?!"))?;

        let cert_specifier =
            ArtiPath::from_path_and_denotators(subject_key_arti_path, &spec.cert_denotators())
                .map_err(into_bad_api_usage!("invalid certificate specifier"))?;

        let maybe_cert = self.get_from_store_raw::<C::ParsedCert>(
            &cert_specifier,
            &C::ParsedCert::item_type(),
            self.all_stores(),
        )?;

        let maybe_subject_key = self.get::<K>(subject_key_spec)?;

        match (&maybe_cert, &maybe_subject_key) {
            (Some(_), None) => {
                return Err(KeystoreCorruptionError::MissingSubjectKey.into());
            }
            _ => {
                // generate key and/or cert
            }
        }
        let subject_key = match maybe_subject_key {
            Some(key) => key,
            _ => self.generate(subject_key_spec, selector, rng, false)?,
        };

        let signed_with = self.get_cert_signing_key::<K, C>(spec)?;
        let cert = match maybe_cert {
            Some(cert) => C::validate(cert, &subject_key, &signed_with)?,
            None => {
                let cert = make_certificate(&subject_key, &signed_with);

                let () = self.insert_cert(cert.clone(), &cert_specifier, selector)?;

                cert
            }
        };

        Ok((subject_key, cert))
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
            .ok_or_else(|| crate::Error::KeystoreNotFound(id.clone()))
    }

    /// Get the signing key of the certificate described by `spec`.
    ///
    /// Returns a [`KeystoreCorruptionError::MissingSigningKey`] error
    /// if the signing key doesn't exist in any of the keystores.
    #[cfg(feature = "experimental-api")]
    fn get_cert_signing_key<K, C>(
        &self,
        spec: &dyn KeyCertificateSpecifier,
    ) -> Result<C::SigningKey>
    where
        K: ToEncodableKey,
        C: ToEncodableCert<K>,
    {
        let Some(signing_key_spec) = spec.signing_key_specifier() else {
            return Err(bad_api_usage!(
                "signing key specifier is None, but external signing key was not provided?"
            )
            .into());
        };

        let Some(signing_key) = self.get_from_store::<C::SigningKey>(
            signing_key_spec,
            &<C::SigningKey as ToEncodableKey>::Key::item_type(),
            self.all_stores(),
        )?
        else {
            return Err(KeystoreCorruptionError::MissingSigningKey.into());
        };

        Ok(signing_key)
    }

    /// Insert `cert` into the [`Keystore`](crate::Keystore) specified by `selector`.
    ///
    /// If the key already exists in the specified key store, it will be overwritten.
    ///
    // NOTE: if we ever make this public we should rethink/improve its API.
    // TODO: maybe fold this into insert() somehow?
    fn insert_cert<K, C>(
        &self,
        cert: C,
        cert_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<()>
    where
        K: ToEncodableKey,
        K::Key: Keygen,
        C: ToEncodableCert<K>,
    {
        let cert = cert.to_encodable_cert();
        let store = self.select_keystore(&selector)?;

        let () = store.insert(&cert, cert_spec)?;
        Ok(())
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::keystore::arti::err::{ArtiNativeKeystoreError, MalformedPathError};
    use crate::raw::{RawEntryId, RawKeystoreEntry};
    use crate::{
        ArtiPath, ArtiPathUnavailableError, Error, KeyPath, KeystoreEntryResult, KeystoreError,
        UnrecognizedEntryError,
    };
    use std::path::PathBuf;
    use std::result::Result as StdResult;
    use std::str::FromStr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, SystemTime};
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cert::CertifiedKey;
    use tor_cert::Ed25519Cert;
    use tor_error::{ErrorKind, HasKind};
    use tor_key_forge::{
        CertData, EncodableItem, ErasedKey, InvalidCertError, KeyType, KeystoreItem,
    };
    use tor_llcrypto::pk::ed25519::{self, Ed25519PublicKey as _};
    use tor_llcrypto::rng::FakeEntropicRng;

    /// Metadata structure for tracking key operations in tests.
    #[derive(Clone, Debug, PartialEq)]
    struct KeyMetadata {
        /// The identifier for the item (e.g., "coot", "moorhen").
        item_id: String,
        /// The keystore from which the item was retrieved.
        ///
        /// Set by `Keystore::get`.
        retrieved_from: Option<KeystoreId>,
        /// Whether the item was generated via `Keygen::generate`.
        is_generated: bool,
    }

    /// Metadata structure for tracking certificate operations in tests.
    #[derive(Clone, Debug, PartialEq)]
    struct CertMetadata {
        /// The identifier for the subject key (e.g., "coot").
        subject_key_id: String,
        /// The identifier for the signing key (e.g., "moorhen").
        signing_key_id: String,
        /// The keystore from which the certificate was retrieved.
        ///
        /// Set by `Keystore::get`.
        retrieved_from: Option<KeystoreId>,
        /// Whether the certificate was freshly generated (i.e. returned from the "or generate"
        /// branch of `get_or_generate()`) or retrieved from a keystore.
        is_generated: bool,
    }

    /// Metadata structure for tracking item operations in tests.
    #[derive(Clone, Debug, PartialEq, derive_more::From)]
    enum ItemMetadata {
        /// Metadata about a key.
        Key(KeyMetadata),
        /// Metadata about a certificate.
        Cert(CertMetadata),
    }

    impl ItemMetadata {
        /// Get the item ID.
        ///
        /// For keys, this returns the key's ID.
        /// For certificates, this returns a formatted string identifying the subject key.
        fn item_id(&self) -> &str {
            match self {
                ItemMetadata::Key(k) => &k.item_id,
                ItemMetadata::Cert(c) => &c.subject_key_id,
            }
        }

        /// Get retrieved_from.
        fn retrieved_from(&self) -> Option<&KeystoreId> {
            match self {
                ItemMetadata::Key(k) => k.retrieved_from.as_ref(),
                ItemMetadata::Cert(c) => c.retrieved_from.as_ref(),
            }
        }

        /// Get is_generated.
        fn is_generated(&self) -> bool {
            match self {
                ItemMetadata::Key(k) => k.is_generated,
                ItemMetadata::Cert(c) => c.is_generated,
            }
        }

        /// Set the retrieved_from field to the specified keystore ID.
        fn set_retrieved_from(&mut self, id: KeystoreId) {
            match self {
                ItemMetadata::Key(meta) => meta.retrieved_from = Some(id),
                ItemMetadata::Cert(meta) => meta.retrieved_from = Some(id),
            }
        }

        /// Returns a reference to key metadata if this is a Key variant.
        fn as_key(&self) -> Option<&KeyMetadata> {
            match self {
                ItemMetadata::Key(meta) => Some(meta),
                _ => None,
            }
        }

        /// Returns a reference to certificate metadata if this is a Cert variant.
        fn as_cert(&self) -> Option<&CertMetadata> {
            match self {
                ItemMetadata::Cert(meta) => Some(meta),
                _ => None,
            }
        }
    }

    /// The type of "key" stored in the test key stores.
    #[derive(Clone, Debug)]
    struct TestItem {
        /// The underlying key.
        item: KeystoreItem,
        /// Metadata about the key.
        meta: ItemMetadata,
    }

    /// A "certificate" used for testing purposes.
    #[derive(Clone, Debug)]
    struct AlwaysValidCert(TestItem);

    /// The corresponding fake public key type.
    #[derive(Clone, Debug)]
    struct TestPublicKey {
        /// The underlying key.
        key: KeystoreItem,
    }

    impl From<TestItem> for TestPublicKey {
        fn from(tk: TestItem) -> TestPublicKey {
            TestPublicKey { key: tk.item }
        }
    }

    impl TestItem {
        /// Create a new test key with the specified metadata.
        fn new(item_id: &str) -> Self {
            let mut rng = testing_rng();
            TestItem {
                item: ed25519::Keypair::generate(&mut rng)
                    .as_keystore_item()
                    .unwrap(),
                meta: ItemMetadata::Key(KeyMetadata {
                    item_id: item_id.to_string(),
                    retrieved_from: None,
                    is_generated: false,
                }),
            }
        }
    }

    impl Keygen for TestItem {
        fn generate(mut rng: &mut dyn KeygenRng) -> tor_key_forge::Result<Self>
        where
            Self: Sized,
        {
            Ok(TestItem {
                item: ed25519::Keypair::generate(&mut rng).as_keystore_item()?,
                meta: ItemMetadata::Key(KeyMetadata {
                    item_id: "generated_test_key".to_string(),
                    retrieved_from: None,
                    is_generated: true,
                }),
            })
        }
    }

    impl ItemType for TestItem {
        fn item_type() -> KeystoreItemType
        where
            Self: Sized,
        {
            // Dummy value
            KeyType::Ed25519Keypair.into()
        }
    }

    impl EncodableItem for TestItem {
        fn as_keystore_item(&self) -> tor_key_forge::Result<KeystoreItem> {
            Ok(self.item.clone())
        }
    }

    impl ToEncodableKey for TestItem {
        type Key = Self;
        type KeyPair = Self;

        fn to_encodable_key(self) -> Self::Key {
            self
        }

        fn from_encodable_key(key: Self::Key) -> Self {
            key
        }
    }

    impl ItemType for TestPublicKey {
        fn item_type() -> KeystoreItemType
        where
            Self: Sized,
        {
            KeyType::Ed25519PublicKey.into()
        }
    }

    impl EncodableItem for TestPublicKey {
        fn as_keystore_item(&self) -> tor_key_forge::Result<KeystoreItem> {
            Ok(self.key.clone())
        }
    }

    impl ToEncodableKey for TestPublicKey {
        type Key = Self;
        type KeyPair = TestItem;

        fn to_encodable_key(self) -> Self::Key {
            self
        }

        fn from_encodable_key(key: Self::Key) -> Self {
            key
        }
    }

    impl ToEncodableCert<TestItem> for AlwaysValidCert {
        type ParsedCert = TestItem;
        type EncodableCert = TestItem;
        type SigningKey = TestItem;

        fn validate(
            cert: Self::ParsedCert,
            _subject: &TestItem,
            _signed_with: &Self::SigningKey,
        ) -> StdResult<Self, InvalidCertError> {
            // AlwaysValidCert is always valid
            Ok(Self(cert))
        }

        /// Convert this cert to a type that implements [`EncodableKey`].
        fn to_encodable_cert(self) -> Self::EncodableCert {
            self.0
        }
    }

    #[derive(thiserror::Error, Debug, Clone, derive_more::Display)]
    enum MockKeystoreError {
        NotFound,
    }

    impl KeystoreError for MockKeystoreError {}

    impl HasKind for MockKeystoreError {
        fn kind(&self) -> ErrorKind {
            // Return a dummy ErrorKind for the purposes of this test
            tor_error::ErrorKind::Other
        }
    }

    fn build_raw_id_path<T: ToString>(key_path: &T, key_type: &KeystoreItemType) -> RawEntryId {
        let mut path = key_path.to_string();
        path.push('.');
        path.push_str(&key_type.arti_extension());
        RawEntryId::Path(PathBuf::from(&path))
    }

    macro_rules! impl_keystore {
        ($name:tt, $id:expr $(,$unrec:expr)?) => {
            struct $name {
                inner: RwLock<
                    Vec<StdResult<(ArtiPath, KeystoreItemType, TestItem), UnrecognizedEntryError>>,
                >,
                id: KeystoreId,
            }

            impl Default for $name {
                fn default() -> Self {
                    let id = KeystoreId::from_str($id).unwrap();
                    let inner: RwLock<
                        Vec<
                            StdResult<
                                (ArtiPath, KeystoreItemType, TestItem),
                                UnrecognizedEntryError,
                            >,
                        >,
                    > = Default::default();
                    // Populate the Keystore with the specified number
                    // of unrecognized entries.
                    $(
                        for i in 0..$unrec {
                            let invalid_key_path =
                                PathBuf::from(&format!("unrecognized_entry{}", i));
                            let raw_id = RawEntryId::Path(invalid_key_path.clone());
                            let entry = RawKeystoreEntry::new(raw_id, id.clone()).into();
                            let entry = UnrecognizedEntryError::new(
                                entry,
                                Arc::new(ArtiNativeKeystoreError::MalformedPath {
                                    path: invalid_key_path,
                                    err: MalformedPathError::NoExtension,
                                }),
                            );
                            inner.write().unwrap().push(Err(entry));
                        }
                    )?
                    Self {
                        inner,
                        id,
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
                    item_type: &KeystoreItemType,
                ) -> Result<bool> {
                    let wanted_arti_path = key_spec.arti_path().unwrap();
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .iter()
                        .find(|res| match res {
                            Ok((spec, ty, _)) => spec == &wanted_arti_path && ty == item_type,
                            Err(_) => false,
                        })
                        .is_some())
                }

                fn id(&self) -> &KeystoreId {
                    &self.id
                }

                fn get(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    item_type: &KeystoreItemType,
                ) -> Result<Option<ErasedKey>> {
                    let key_spec = key_spec.arti_path().unwrap();

                    Ok(self.inner.read().unwrap().iter().find_map(|res| {
                        match res {
                            Ok((arti_path, ty, k)) => {
                                if arti_path == &key_spec && ty == item_type {
                                    let mut k = k.clone();
                                    k.meta.set_retrieved_from(self.id().clone());
                                    return Some(Box::new(k) as Box<dyn ItemType>);
                                }
                            }
                            Err(_) => {}
                        }
                        None
                    }))
                }

                #[cfg(feature = "onion-service-cli-extra")]
                fn raw_entry_id(&self, raw_id: &str) -> Result<RawEntryId> {
                    Ok(RawEntryId::Path(
                        PathBuf::from(raw_id.to_string()),
                    ))
                }

                fn insert(
                    &self,
                    key: &dyn EncodableItem,
                    key_spec: &dyn KeySpecifier,
                ) -> Result<()> {
                    let key = key.downcast_ref::<TestItem>().unwrap();

                    let item = key.as_keystore_item()?;
                    let meta = key.meta.clone();

                    let item_type = item.item_type()?;
                    let key = TestItem { item, meta };

                    self.inner
                        .write()
                        .unwrap()
                        // TODO: `insert` is used instead of `push`, because some of the
                        // tests (mainly `insert_and_get` and `keygen`) fail otherwise.
                        // It could be a good idea to use `push` and adapt the tests,
                        // in order to reduce cognitive complexity.
                        .insert(0, (Ok((key_spec.arti_path().unwrap(), item_type, key))));

                    Ok(())
                }

                fn remove(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    item_type: &KeystoreItemType,
                ) -> Result<Option<()>> {
                    let wanted_arti_path = key_spec.arti_path().unwrap();
                    let index = self.inner.read().unwrap().iter().position(|res| {
                        if let Ok((arti_path, ty, _)) = res {
                            arti_path == &wanted_arti_path && ty == item_type
                        } else {
                            false
                        }
                    });
                    let Some(index) = index else {
                        return Ok(None);
                    };
                    let _ = self.inner.write().unwrap().remove(index);

                    Ok(Some(()))
                }

                #[cfg(feature = "onion-service-cli-extra")]
                fn remove_unchecked(&self, entry_id: &RawEntryId) -> Result<()> {
                    let index = self.inner.read().unwrap().iter().position(|res| match res {
                        Ok((spec, ty, _)) => {
                            let id = build_raw_id_path(spec, ty);
                            entry_id == &id
                        }
                        Err(e) => {
                            e.entry().raw_id() == entry_id
                        }
                    });
                    let Some(index) = index else {
                        return Err(Error::Keystore(Arc::new(MockKeystoreError::NotFound)));
                    };
                    let _ = self.inner.write().unwrap().remove(index);
                    Ok(())
                }

                fn list(&self) -> Result<Vec<KeystoreEntryResult<KeystoreEntry>>> {
                    Ok(self
                        .inner
                        .read()
                        .unwrap()
                        .iter()
                        .map(|res| match res {
                            Ok((arti_path, ty, _)) => {
                                let raw_id = RawEntryId::Path(
                                    PathBuf::from(
                                        &arti_path.to_string(),
                                    )
                                );

                                Ok(KeystoreEntry::new(KeyPath::Arti(arti_path.clone()), ty.clone(), self.id(), raw_id))
                            }
                            Err(e) => Err(e.clone()),
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
    impl_keystore!(KeystoreUnrec1, "keystore_unrec1", 1);

    impl_specifier!(TestKeySpecifier1, "spec1");
    impl_specifier!(TestKeySpecifier2, "spec2");
    impl_specifier!(TestKeySpecifier3, "spec3");
    impl_specifier!(TestKeySpecifier4, "spec4");

    impl_specifier!(TestPublicKeySpecifier1, "pub-spec1");

    /// Create a test `KeystoreEntry`.
    fn entry_descriptor(specifier: impl KeySpecifier, keystore_id: &KeystoreId) -> KeystoreEntry {
        let arti_path = specifier.arti_path().unwrap();
        let raw_id = RawEntryId::Path(PathBuf::from(arti_path.as_ref()));
        KeystoreEntry {
            key_path: arti_path.into(),
            key_type: TestItem::item_type(),
            keystore_id,
            raw_id,
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn insert_and_get() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        // Insert a key into Keystore2
        let old_key = mgr
            .insert(
                TestItem::new("coot"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                true,
            )
            .unwrap();

        assert!(old_key.is_none());
        let key = mgr.get::<TestItem>(&TestKeySpecifier1).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "coot");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        // Insert a different key using the _same_ key specifier.
        let old_key = mgr
            .insert(
                TestItem::new("gull"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                true,
            )
            .unwrap()
            .unwrap();
        assert_eq!(old_key.meta.item_id(), "coot");
        assert_eq!(
            old_key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(old_key.meta.is_generated(), false);
        // Check that the original value was overwritten:
        let key = mgr.get::<TestItem>(&TestKeySpecifier1).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "gull");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        // Insert a different key using the _same_ key specifier (overwrite = false)
        let err = mgr
            .insert(
                TestItem::new("gull"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                false,
            )
            .unwrap_err();
        assert!(matches!(err, crate::Error::KeyAlreadyExists));

        // Insert a new key into Keystore2 (overwrite = false)
        let old_key = mgr
            .insert(
                TestItem::new("penguin"),
                &TestKeySpecifier2,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                false,
            )
            .unwrap();
        assert!(old_key.is_none());

        // Insert a key into the primary keystore
        let old_key = mgr
            .insert(
                TestItem::new("moorhen"),
                &TestKeySpecifier3,
                KeystoreSelector::Primary,
                true,
            )
            .unwrap();
        assert!(old_key.is_none());
        let key = mgr.get::<TestItem>(&TestKeySpecifier3).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "moorhen");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore1").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        // The key doesn't exist in any of the stores yet.
        assert!(mgr.get::<TestItem>(&TestKeySpecifier4).unwrap().is_none());

        // Insert the same key into all 3 key stores, in reverse order of keystore priority
        // (otherwise KeyMgr::get will return the key from the primary store for each iteration and
        // we won't be able to see the key was actually inserted in each store).
        for store in ["keystore3", "keystore2", "keystore1"] {
            let old_key = mgr
                .insert(
                    TestItem::new("cormorant"),
                    &TestKeySpecifier4,
                    KeystoreSelector::Id(&KeystoreId::from_str(store).unwrap()),
                    true,
                )
                .unwrap();
            assert!(old_key.is_none());

            // Ensure the key now exists in `store`.
            let key = mgr.get::<TestItem>(&TestKeySpecifier4).unwrap().unwrap();
            assert_eq!(key.meta.item_id(), "cormorant");
            assert_eq!(
                key.meta.retrieved_from(),
                Some(&KeystoreId::from_str(store).unwrap())
            );
            assert_eq!(key.meta.is_generated(), false);
        }

        // The key exists in all key stores, but if no keystore_id is specified, we return the
        // value from the first key store it is found in (in this case, Keystore1)
        let key = mgr.get::<TestItem>(&TestKeySpecifier4).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "cormorant");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore1").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);
    }

    #[test]
    #[cfg(feature = "onion-service-cli-extra")]
    fn get_from() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        let keystore1_id = KeystoreId::from_str("keystore1").unwrap();
        let keystore2_id = KeystoreId::from_str("keystore2").unwrap();
        let key_id_1 = "mantis shrimp";
        let key_id_2 = "tardigrade";

        // Insert a key into Keystore1
        let _ = mgr
            .insert(
                TestItem::new(key_id_1),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&keystore1_id),
                true,
            )
            .unwrap();

        // Insert a key into Keystore2
        let _ = mgr
            .insert(
                TestItem::new(key_id_2),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&keystore2_id),
                true,
            )
            .unwrap();

        // Retrieve key
        let key = mgr
            .get_from::<TestItem>(&TestKeySpecifier1, &keystore2_id)
            .unwrap()
            .unwrap();

        assert_eq!(key.meta.item_id(), key_id_2);
        assert_eq!(key.meta.retrieved_from(), Some(&keystore2_id));
    }

    #[test]
    fn remove() {
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        assert!(
            !mgr.secondary_stores[0]
                .contains(&TestKeySpecifier1, &TestItem::item_type())
                .unwrap()
        );

        // Insert a key into Keystore2
        mgr.insert(
            TestItem::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
            true,
        )
        .unwrap();
        let key = mgr.get::<TestItem>(&TestKeySpecifier1).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "coot");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        // Try to remove the key from a non-existent key store
        assert!(
            mgr.remove::<TestItem>(
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("not_an_id_we_know_of").unwrap())
            )
            .is_err()
        );
        // The key still exists in Keystore2
        assert!(
            mgr.secondary_stores[0]
                .contains(&TestKeySpecifier1, &TestItem::item_type())
                .unwrap()
        );

        // Try to remove the key from the primary key store
        assert!(
            mgr.remove::<TestItem>(&TestKeySpecifier1, KeystoreSelector::Primary)
                .unwrap()
                .is_none()
        );

        // The key still exists in Keystore2
        assert!(
            mgr.secondary_stores[0]
                .contains(&TestKeySpecifier1, &TestItem::item_type())
                .unwrap()
        );

        // Removing from Keystore2 should succeed.
        let removed_key = mgr
            .remove::<TestItem>(
                &TestKeySpecifier1,
                KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(removed_key.meta.item_id(), "coot");
        assert_eq!(
            removed_key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(removed_key.meta.is_generated(), false);

        // The key doesn't exist in Keystore2 anymore
        assert!(
            !mgr.secondary_stores[0]
                .contains(&TestKeySpecifier1, &TestItem::item_type())
                .unwrap()
        );
    }

    #[test]
    fn keygen() {
        let mut rng = FakeEntropicRng(testing_rng());
        let mgr = KeyMgrBuilder::default()
            .primary_store(Box::<Keystore1>::default())
            .build()
            .unwrap();

        mgr.insert(
            TestItem::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Primary,
            true,
        )
        .unwrap();

        // There is no corresponding public key entry.
        assert!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1)
                .unwrap()
                .is_none()
        );

        // Try to generate a new key (overwrite = false)
        let err = mgr
            .generate::<TestItem>(
                &TestKeySpecifier1,
                KeystoreSelector::Primary,
                &mut rng,
                false,
            )
            .unwrap_err();

        assert!(matches!(err, crate::Error::KeyAlreadyExists));

        // The previous entry was not overwritten because overwrite = false
        let key = mgr.get::<TestItem>(&TestKeySpecifier1).unwrap().unwrap();
        assert_eq!(key.meta.item_id(), "coot");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore1").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        // We don't store public keys in the keystore
        assert!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1)
                .unwrap()
                .is_none()
        );

        // Try to generate a new key (overwrite = true)
        let generated_key = mgr
            .generate::<TestItem>(
                &TestKeySpecifier1,
                KeystoreSelector::Primary,
                &mut rng,
                true,
            )
            .unwrap();

        assert_eq!(generated_key.meta.item_id(), "generated_test_key");
        // Not set in a freshly generated key, because KeyMgr::generate()
        // returns it straight away, without going through Keystore::get()
        assert_eq!(generated_key.meta.retrieved_from(), None);
        assert_eq!(generated_key.meta.is_generated(), true);

        // Retrieve the inserted key
        let retrieved_key = mgr.get::<TestItem>(&TestKeySpecifier1).unwrap().unwrap();
        assert_eq!(retrieved_key.meta.item_id(), "generated_test_key");
        assert_eq!(
            retrieved_key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore1").unwrap())
        );
        assert_eq!(retrieved_key.meta.is_generated(), true);

        // We don't store public keys in the keystore
        assert!(
            mgr.get::<TestPublicKey>(&TestPublicKeySpecifier1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_or_generate() {
        let mut rng = FakeEntropicRng(testing_rng());
        let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();

        let keystore2 = KeystoreId::from_str("keystore2").unwrap();
        let entry_desc1 = entry_descriptor(TestKeySpecifier1, &keystore2);
        assert!(mgr.get_entry::<TestItem>(&entry_desc1).unwrap().is_none());

        mgr.insert(
            TestItem::new("coot"),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&keystore2),
            true,
        )
        .unwrap();

        // The key already exists in keystore 2 so it won't be auto-generated.
        let key = mgr
            .get_or_generate::<TestItem>(&TestKeySpecifier1, KeystoreSelector::Primary, &mut rng)
            .unwrap();
        assert_eq!(key.meta.item_id(), "coot");
        assert_eq!(
            key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore2").unwrap())
        );
        assert_eq!(key.meta.is_generated(), false);

        assert_eq!(
            mgr.get_entry::<TestItem>(&entry_desc1)
                .unwrap()
                .map(|k| k.meta),
            Some(ItemMetadata::Key(KeyMetadata {
                item_id: "coot".to_string(),
                retrieved_from: Some(keystore2.clone()),
                is_generated: false,
            }))
        );

        // This key doesn't exist in any of the keystores, so it will be auto-generated and
        // inserted into keystore 3.
        let keystore3 = KeystoreId::from_str("keystore3").unwrap();
        let generated_key = mgr
            .get_or_generate::<TestItem>(
                &TestKeySpecifier2,
                KeystoreSelector::Id(&keystore3),
                &mut rng,
            )
            .unwrap();
        assert_eq!(generated_key.meta.item_id(), "generated_test_key");
        // Not set in a freshly generated key, because KeyMgr::get_or_generate()
        // returns it straight away, without going through Keystore::get()
        assert_eq!(generated_key.meta.retrieved_from(), None);
        assert_eq!(generated_key.meta.is_generated(), true);

        // Retrieve the inserted key
        let retrieved_key = mgr.get::<TestItem>(&TestKeySpecifier2).unwrap().unwrap();
        assert_eq!(retrieved_key.meta.item_id(), "generated_test_key");
        assert_eq!(
            retrieved_key.meta.retrieved_from(),
            Some(&KeystoreId::from_str("keystore3").unwrap())
        );
        assert_eq!(retrieved_key.meta.is_generated(), true);

        let entry_desc2 = entry_descriptor(TestKeySpecifier2, &keystore3);
        assert_eq!(
            mgr.get_entry::<TestItem>(&entry_desc2)
                .unwrap()
                .map(|k| k.meta),
            Some(ItemMetadata::Key(KeyMetadata {
                item_id: "generated_test_key".to_string(),
                retrieved_from: Some(keystore3.clone()),
                is_generated: true,
            }))
        );

        let arti_pat = KeyPathPattern::Arti("*".to_string());
        let matching = mgr.list_matching(&arti_pat).unwrap();

        assert_eq!(matching.len(), 2);
        assert!(matching.contains(&entry_desc1));
        assert!(matching.contains(&entry_desc2));

        assert_eq!(mgr.remove_entry(&entry_desc2).unwrap(), Some(()));
        assert!(mgr.get_entry::<TestItem>(&entry_desc2).unwrap().is_none());
        assert!(mgr.remove_entry(&entry_desc2).unwrap().is_none());
    }

    #[test]
    fn list_matching_ignores_unrecognized_keys() {
        let builder = KeyMgrBuilder::default().primary_store(Box::new(KeystoreUnrec1::default()));

        let mgr = builder.build().unwrap();

        let unrec_1 = KeystoreId::from_str("keystore_unrec1").unwrap();
        mgr.insert(
            TestItem::new("whale shark"),
            &TestKeySpecifier1,
            KeystoreSelector::Id(&unrec_1),
            true,
        )
        .unwrap();

        let arti_pat = KeyPathPattern::Arti("*".to_string());
        let valid_key_path = KeyPath::Arti(TestKeySpecifier1.arti_path().unwrap());
        let matching = mgr.list_matching(&arti_pat).unwrap();
        // assert the unrecognized key has been filtered out
        assert_eq!(matching.len(), 1);
        assert_eq!(matching.first().unwrap().key_path(), &valid_key_path);
    }

    #[cfg(feature = "onion-service-cli-extra")]
    #[test]
    /// Test all `arti keys` subcommands
    // TODO: split this in different tests
    fn keys_subcommands() {
        let mut builder =
            KeyMgrBuilder::default().primary_store(Box::new(KeystoreUnrec1::default()));
        builder
            .secondary_stores()
            .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

        let mgr = builder.build().unwrap();
        let ks_unrec1id = KeystoreId::from_str("keystore_unrec1").unwrap();
        let keystore2id = KeystoreId::from_str("keystore2").unwrap();
        let keystore3id = KeystoreId::from_str("keystore3").unwrap();

        // Insert a key into KeystoreUnrec1
        let _ = mgr
            .insert(
                TestItem::new("pangolin"),
                &TestKeySpecifier1,
                KeystoreSelector::Id(&ks_unrec1id),
                true,
            )
            .unwrap();

        // Insert a key into Keystore2
        let _ = mgr
            .insert(
                TestItem::new("coot"),
                &TestKeySpecifier2,
                KeystoreSelector::Id(&keystore2id),
                true,
            )
            .unwrap();

        // Insert a key into Keystore3
        let _ = mgr
            .insert(
                TestItem::new("penguin"),
                &TestKeySpecifier3,
                KeystoreSelector::Id(&keystore3id),
                true,
            )
            .unwrap();

        let assert_key = |path, ty, expected_path: &ArtiPath, expected_type| {
            assert_eq!(ty, expected_type);
            assert_eq!(path, &KeyPath::Arti(expected_path.clone()));
        };
        let item_type = TestItem::new("axolotl").item.item_type().unwrap();
        let unrecognized_entry_id = RawEntryId::Path(PathBuf::from("unrecognized_entry0"));

        // Test `list`
        let entries = mgr.list().unwrap();

        let expected_items = [
            (ks_unrec1id, TestKeySpecifier1.arti_path().unwrap()),
            (keystore2id, TestKeySpecifier2.arti_path().unwrap()),
            (keystore3id, TestKeySpecifier3.arti_path().unwrap()),
        ];

        // Secondary keystores contain 1 valid key each
        let mut recognized_entries = 0;
        let mut unrecognized_entries = 0;
        for entry in entries.iter() {
            match entry {
                Ok(e) => {
                    if let Some((_, expected_arti_path)) = expected_items
                        .iter()
                        .find(|(keystore_id, _)| keystore_id == e.keystore_id())
                    {
                        assert_key(e.key_path(), e.key_type(), expected_arti_path, &item_type);
                        recognized_entries += 1;
                        continue;
                    }

                    panic!("Unexpected key encountered {:?}", e);
                }
                Err(u) => {
                    assert_eq!(u.entry().raw_id(), &unrecognized_entry_id);
                    unrecognized_entries += 1;
                }
            }
        }
        assert_eq!(recognized_entries, 3);
        assert_eq!(unrecognized_entries, 1);

        // Test `list_keystores`
        let keystores = mgr.list_keystores().iter().len();

        assert_eq!(keystores, 3);

        // Test `list_by_id`
        let primary_keystore_id = KeystoreId::from_str("keystore_unrec1").unwrap();
        let entries = mgr.list_by_id(&primary_keystore_id).unwrap();

        // Primary keystore contains a valid key and an unrecognized key
        let mut recognized_entries = 0;
        let mut unrecognized_entries = 0;
        // A list of entries, in a form that can be consumed by remove_unchecked
        let mut all_entries = vec![];
        for entry in entries.iter() {
            match entry {
                Ok(entry) => {
                    assert_key(
                        entry.key_path(),
                        entry.key_type(),
                        &TestKeySpecifier1.arti_path().unwrap(),
                        &item_type,
                    );
                    recognized_entries += 1;
                    all_entries.push(RawKeystoreEntry::new(
                        build_raw_id_path(entry.key_path(), entry.key_type()),
                        primary_keystore_id.clone(),
                    ));
                }
                Err(u) => {
                    assert_eq!(u.entry().raw_id(), &unrecognized_entry_id);
                    unrecognized_entries += 1;
                    all_entries.push(u.entry().into());
                }
            }
        }
        assert_eq!(recognized_entries, 1);
        assert_eq!(unrecognized_entries, 1);

        // Remove a recognized entry and an recognized one
        for entry in all_entries {
            mgr.remove_unchecked(&entry.raw_id().to_string(), entry.keystore_id())
                .unwrap();
        }

        // Check the keys have been removed
        let entries = mgr.list_by_id(&primary_keystore_id).unwrap();
        assert_eq!(entries.len(), 0);
    }

    /// Whether to generate a given item before running the `run_certificate_test`.
    #[cfg(feature = "experimental-api")]
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum GenerateItem {
        Yes,
        No,
    }

    #[cfg(feature = "experimental-api")]
    macro_rules! run_certificate_test {
        (
            generate_subject_key = $generate_subject_key:expr,
            generate_signing_key = $generate_signing_key:expr,
            $($expected_err:tt)?
        ) => {{
            use GenerateItem::*;

            let mut rng = FakeEntropicRng(testing_rng());
            let mut builder = KeyMgrBuilder::default().primary_store(Box::<Keystore1>::default());

            builder
                .secondary_stores()
                .extend([Keystore2::new_boxed(), Keystore3::new_boxed()]);

            let mgr = builder.build().unwrap();

            let spec = crate::test_utils::TestCertSpecifier {
                subject_key_spec: TestKeySpecifier1,
                signing_key_spec: TestKeySpecifier2,
                denotator: vec!["foo".into()],
            };

            if $generate_subject_key == Yes {
                let _ = mgr
                    .generate::<TestItem>(
                        &TestKeySpecifier1,
                        KeystoreSelector::Primary,
                        &mut rng,
                        false,
                    )
                    .unwrap();
            }

            if $generate_signing_key == Yes {
                let _ = mgr
                    .generate::<TestItem>(
                        &TestKeySpecifier2,
                        KeystoreSelector::Id(&KeystoreId::from_str("keystore2").unwrap()),
                        &mut rng,
                        false,
                    )
                    .unwrap();
            }

            let make_certificate = move |subject_key: &TestItem, signed_with: &TestItem| {
                let subject_id = subject_key.meta.as_key().unwrap().item_id.clone();
                let signing_id = signed_with.meta.as_key().unwrap().item_id.clone();

                let meta = ItemMetadata::Cert(CertMetadata {
                    subject_key_id: subject_id,
                    signing_key_id: signing_id,
                    retrieved_from: None,
                    is_generated: true,
                });

                // Note: this is not really a cert for `subject_key` signed with the `signed_with`
                // key!. The two are `TestItem`s and not keys, so we can't really generate a real
                // cert from them. We can, however, pretend we did, for testing purposes.
                // Eventually we might want to rewrite these tests to use real items
                // (like the `ArtiNativeKeystore` tests)
                let mut rng = FakeEntropicRng(testing_rng());
                let keypair = ed25519::Keypair::generate(&mut rng);
                let encoded_cert = Ed25519Cert::constructor()
                    .cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)
                    .expiration(SystemTime::now() + Duration::from_secs(180))
                    .signing_key(keypair.public_key().into())
                    .cert_key(CertifiedKey::Ed25519(keypair.public_key().into()))
                    .encode_and_sign(&keypair)
                    .unwrap();
                let test_cert = CertData::TorEd25519Cert(encoded_cert);
                AlwaysValidCert(TestItem {
                    item: KeystoreItem::Cert(test_cert),
                    meta,
                })
            };

            let res = mgr
                .get_or_generate_key_and_cert::<TestItem, AlwaysValidCert>(
                    &spec,
                    &make_certificate,
                    KeystoreSelector::Primary,
                    &mut rng,
                );

            #[allow(unused_assignments)]
            #[allow(unused_mut)]
            let mut has_error = false;
            $(
                has_error = true;
                let err = res.clone().unwrap_err();
                assert!(
                    matches!(
                        err,
                        crate::Error::Corruption(KeystoreCorruptionError::$expected_err)
                    ),
                    "unexpected error: {err:?}",
                );
            )?

            if !has_error {
                let (key, cert) = res.unwrap();

                let expected_subj_key_id = if $generate_subject_key == Yes {
                    "generated_test_key"
                } else {
                    "generated_test_key"
                };

                assert_eq!(key.meta.item_id(), expected_subj_key_id);
                assert_eq!(
                    cert.0.meta.as_cert().unwrap().subject_key_id,
                    expected_subj_key_id
                );
                assert_eq!(
                    cert.0.meta.as_cert().unwrap().signing_key_id,
                    "generated_test_key"
                );
                assert_eq!(cert.0.meta.is_generated(), true);
            }
        }}
    }

    #[test]
    #[cfg(feature = "experimental-api")]
    #[rustfmt::skip] // preserve the layout for readability
    #[allow(clippy::cognitive_complexity)] // clippy seems confused here...
    fn get_certificate() {
        run_certificate_test!(
            generate_subject_key = No,
            generate_signing_key = No,
            MissingSigningKey
        );

        run_certificate_test!(
            generate_subject_key = Yes,
            generate_signing_key = No,
            MissingSigningKey
        );

        run_certificate_test!(
            generate_subject_key = No,
            generate_signing_key = Yes,
        );

        run_certificate_test!(
            generate_subject_key = Yes,
            generate_signing_key = Yes,
        );
    }
}
