//! The Arti key store.
//!
//! The Arti key store stores the keys on disk in OpenSSH format.

pub(crate) mod err;

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::key_type::ssh::UnparsedOpenSshKey;
use crate::keystore::{EncodableKey, ErasedKey, KeySpecifier, KeyStore};
use crate::{KeyType, Result};
use err::{ArtiNativeKeystoreError, FilesystemAction};

use fs_mistrust::{CheckedDir, Mistrust};

/// The Arti key store.
#[derive(Debug)]
pub struct ArtiNativeKeyStore {
    /// The root of the key store.
    keystore_dir: CheckedDir,
}

impl ArtiNativeKeyStore {
    /// Create a new [`ArtiNativeKeyStore`] rooted at the specified `keystore_dir` directory.
    ///
    /// The `keystore_dir` directory is created if it doesn't exist.
    ///
    /// This function returns an error if `keystore_dir` is not a directory, if it does not conform
    /// to the requirements of the specified `Mistrust`, or if there was a problem creating the
    /// directory.
    pub fn from_path_and_mistrust(
        keystore_dir: impl AsRef<Path>,
        mistrust: &Mistrust,
    ) -> Result<Self> {
        let keystore_dir = mistrust
            .verifier()
            .check_content()
            .make_secure_dir(&keystore_dir)
            .map_err(|e| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Init,
                path: keystore_dir.as_ref().into(),
                err: e.into(),
            })?;

        Ok(Self { keystore_dir })
    }

    /// The path on disk of the key with the specified identity and type, relative to
    /// `keystore_dir`.
    fn key_path(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<PathBuf> {
        let arti_path: String = key_spec.arti_path()?.into();
        let mut rel_path = PathBuf::from(arti_path);
        rel_path.set_extension(key_type.arti_extension());

        Ok(rel_path)
    }
}

impl KeyStore for ArtiNativeKeyStore {
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<ErasedKey>> {
        let path = self.key_path(key_spec, key_type)?;

        let inner = match self.keystore_dir.read(&path) {
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            Err(fs_mistrust::Error::Io { err, .. }) if err.kind() == ErrorKind::NotFound => {
                return Ok(None);
            }
            res => res.map_err(|err| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Read,
                path: path.clone(),
                err: err.into(),
            })?,
        };

        key_type
            .parse_ssh_format_erased(UnparsedOpenSshKey::new(inner, path))
            .map(Some)
    }

    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
    ) -> Result<()> {
        let path = self.key_path(key_spec, key_type)?;
        let openssh_key = key_type.to_ssh_format(key)?;

        Ok(self
            .keystore_dir
            .write_and_replace(&path, openssh_key)
            .map_err(|err| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Write,
                path,
                err: err.into(),
            })?)
    }

    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<()>> {
        let key_path = self.key_path(key_spec, key_type)?;

        let abs_key_path =
            self.keystore_dir
                .join(&key_path)
                .map_err(|e| ArtiNativeKeystoreError::FsMistrust {
                    action: FilesystemAction::Remove,
                    path: key_path.clone(),
                    err: e.into(),
                })?;

        match fs::remove_file(abs_key_path) {
            Ok(()) => Ok(Some(())),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound) => Ok(None),
            Err(e) => Err(ArtiNativeKeystoreError::Filesystem {
                action: FilesystemAction::Remove,
                path: key_path,
                err: e.into(),
            }
            .into()),
        }
    }

    fn has_key_bundle(&self, _key_spec: &dyn KeySpecifier) -> Result<bool> {
        // TODO HSS (#903): implement
        Ok(true)
    }
}
