//! Read-only C Tor key store support.

pub(crate) mod client;
pub(crate) mod err;
pub(crate) mod service;

use crate::keystore::fs_utils::{FilesystemAction, FilesystemError, RelKeyPath};
use crate::{KeystoreId, Result};
use fs_mistrust::{CheckedDir, Mistrust};

use std::path::{Path, PathBuf};

use err::CTorKeystoreError;

pub use client::CTorClientKeystore;
pub use service::CTorServiceKeystore;

/// Common fields for C Tor keystores.
struct CTorKeystore {
    /// The root of the key store.
    ///
    /// All the keys are read from this directory.
    keystore_dir: CheckedDir,
    /// The unique identifier of this instance.
    id: KeystoreId,
}

impl CTorKeystore {
    /// Create a new `CTorKeystore` rooted at the specified `keystore_dir` directory.
    ///
    /// This function returns an error if `keystore_dir` is not a directory,
    /// or if it does not conform to the requirements of the specified `Mistrust`.
    fn from_path_and_mistrust(
        keystore_dir: impl AsRef<Path>,
        mistrust: &Mistrust,
        id: KeystoreId,
    ) -> Result<Self> {
        let keystore_dir = mistrust
            .verifier()
            .check_content()
            .secure_dir(&keystore_dir)
            .map_err(|e| FilesystemError::FsMistrust {
                action: FilesystemAction::Init,
                path: keystore_dir.as_ref().into(),
                err: e.into(),
            })
            .map_err(CTorKeystoreError::Filesystem)?;

        Ok(Self { keystore_dir, id })
    }

    /// Return `rel_path` as a [`RelKeyPath`] relative to `keystore_dir`.
    fn rel_path(&self, rel_path: PathBuf) -> RelKeyPath {
        RelKeyPath::from_parts(&self.keystore_dir, rel_path)
    }
}
