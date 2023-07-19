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

    /// Read a key from the [`Keystore`] specified by `selector` and try to deserialize it as
    /// `K::Key`.
    ///
    /// This function can be used with any [`KeystoreSelector`] .
    ///
    /// Returns `Ok(None)` if the requested key is not found in the keystore described by `selector`.
    pub fn get<K: ToEncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        selector: KeystoreSelector,
    ) -> Result<Option<K>> {
        match selector {
            KeystoreSelector::Id(keystore_id) => {
                let Some(keystore) = self.find_keystore(keystore_id) else { return Ok(None) };
                self.get_from_store(key_spec, iter::once(keystore))
            }
            KeystoreSelector::Default => {
                self.get_from_store(key_spec, iter::once(&self.default_store))
            }
            KeystoreSelector::All => self.get_from_store(key_spec, self.all_stores()),
        }
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

    /// Remove the key identified by `key_spec` from the [`Keystore`] specified by `selector`.
    ///
    /// This function can only be used with [`KeystoreSelector::Default`] and
    /// [`KeystoreSelector::Id`]. It returns an error if the specified `selector`
    /// is not supported.
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
        match selector {
            KeystoreSelector::Id(keystore_id) => {
                let Some(keystore) = self.find_keystore(keystore_id) else {
                    return Err(KeyMgrError::KeystoreNotFound(keystore_id).boxed());
                };
                keystore.remove(key_spec, K::Key::key_type())
            }
            KeystoreSelector::Default => self.default_store.remove(key_spec, K::Key::key_type()),
            KeystoreSelector::All => Err(KeyMgrError::UnsupportedKeystoreSelector {
                op: "remove",
                selector,
            }
            .boxed()),
        }
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
    use std::sync::RwLock;

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

        fn to_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(self.as_bytes().to_vec().into())
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
            #[derive(Default)]
            struct $name(RwLock<HashMap<(ArtiPath, KeyType), TestKey>>);

            #[allow(dead_code)] // this is only dead code for Keystore1
            impl $name {
                fn new_boxed() -> BoxedKeystore {
                    Box::<Self>::default()
                }
            }

            impl Keystore for $name {
                fn id(&self) -> &'static str {
                    $id
                }

                fn get(
                    &self,
                    key_spec: &dyn KeySpecifier,
                    key_type: KeyType,
                ) -> Result<Option<ErasedKey>> {
                    Ok(self
                        .0
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
                    let value = String::from_utf8(key.to_bytes()?.to_vec()).unwrap();

                    self.0.write().unwrap().insert(
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
                        .0
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
            KeystoreSelector::Id("keystore2"),
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1, KeystoreSelector::All)
                .unwrap(),
            Some("keystore2_coot".to_string())
        );

        // Insert a different key using the _same_ key specifier.
        mgr.insert(
            "gull".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id("keystore2"),
        )
        .unwrap();
        // Check that the original value was overwritten:
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1, KeystoreSelector::All)
                .unwrap(),
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
            mgr.get::<TestKey>(&TestKeySpecifier2, KeystoreSelector::All)
                .unwrap(),
            Some("keystore1_moorhen".to_string())
        );

        // Insert the same key into all 3 key stores
        for store in ["keystore1", "keystore2", "keystore3"] {
            // The key doesn't exist in `store` yet.
            assert!(mgr
                .get::<TestKey>(&TestKeySpecifier3, KeystoreSelector::Id(store))
                .unwrap()
                .is_none());

            mgr.insert(
                "cormorant".to_string(),
                &TestKeySpecifier3,
                KeystoreSelector::Id(store),
            )
            .unwrap();

            // Ensure the key now exists in `store`.
            assert_eq!(
                mgr.get::<TestKey>(&TestKeySpecifier3, KeystoreSelector::Id(store))
                    .unwrap(),
                Some(format!("{store}_cormorant"))
            );
        }

        // The key exists in all key stores, but if no keystore_id is specified, we return the
        // value from the first key store it is found in (in this case, Keystore1)
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier3, KeystoreSelector::All)
                .unwrap(),
            Some("keystore1_cormorant".to_string())
        );
    }

    #[test]
    fn remove() {
        let mgr = KeyMgr::new(
            Keystore1::default(),
            vec![Keystore2::new_boxed(), Keystore3::new_boxed()],
        );

        // Insert a key into Keystore2
        mgr.insert(
            "coot".to_string(),
            &TestKeySpecifier1,
            KeystoreSelector::Id("keystore2"),
        )
        .unwrap();
        assert_eq!(
            mgr.get::<TestKey>(&TestKeySpecifier1, KeystoreSelector::All)
                .unwrap(),
            Some("keystore2_coot".to_string())
        );

        // Try to remove the key from a non-existent key store
        assert!(mgr
            .remove::<TestKey>(
                &TestKeySpecifier1,
                KeystoreSelector::Id("not_an_id_we_know_of")
            )
            .is_err());

        // Try to remove the key from the default key store
        assert_eq!(
            mgr.remove::<TestKey>(&TestKeySpecifier1, KeystoreSelector::Default)
                .unwrap(),
            None
        );

        // Removing from Keystore2 should succeed.
        assert_eq!(
            mgr.remove::<TestKey>(&TestKeySpecifier1, KeystoreSelector::Id("keystore2"))
                .unwrap(),
            Some(())
        );
    }
}
