//! The Arti key store.
//!
//! The Arti key store stores the keys on disk in OpenSSH format.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use crate::keystore::{EncodableKey, ErasedKey, KeySpecifier, KeyStore};
use crate::{Error, KeyType, Result};

/// The Arti key store.
pub struct ArtiNativeKeyStore {
    /// The root of the key store.
    keystore_dir: PathBuf,
}

impl ArtiNativeKeyStore {
    /// Create a new [`ArtiNativeKeyStore`] rooted at the specified directory.
    pub fn new(keystore_dir: PathBuf) -> Result<Self> {
        Ok(Self { keystore_dir })
    }

    /// The path on disk of the key with the specified identity and type.
    fn key_path(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<PathBuf> {
        let mut key_path = self.keystore_dir.join(&*key_spec.arti_path()?);
        key_path.set_extension(key_type.arti_extension());

        Ok(key_path)
    }
}

impl KeyStore for ArtiNativeKeyStore {
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<ErasedKey> {
        let key_path = self.key_path(key_spec, key_type)?;

        key_type.read_ssh_format_erased(&key_path)
    }

    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
    ) -> Result<()> {
        let key_path = self.key_path(key_spec, key_type)?;

        key_type.write_ssh_format(key, &key_path)
    }

    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<()> {
        let key_path = self.key_path(key_spec, key_type)?;

        fs::remove_file(&key_path).map_err(|e| {
            if matches!(e.kind(), ErrorKind::NotFound) {
                Error::NotFound { /* TODO hs: add context */ }
            } else {
                Error::Filesystem {
                    action: "remove",
                    path: key_path,
                    err: e.into(),
                }
            }
        })?;

        Ok(())
    }

    fn has_key_bundle(&self, _key_spec: &dyn KeySpecifier) -> Result<bool> {
        // TODO HSS (#903): implement
        Ok(true)
    }
}
