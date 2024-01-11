//! State management utilities for hidden services.

use std::path::Path;

use fs_mistrust::Mistrust;
use tor_error::into_internal;
use tor_hscrypto::pk::{HsId, HsIdKey};
use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder};

use crate::{HsIdPublicKeySpecifier, HsNickname};

/// A helper for managing the persistent state of hidden services.
//
// TODO (#1220) decide what API we want here and implement it
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1837#note_2977513
pub struct StateMgr {
    /// The key manager
    keymgr: KeyMgr,
}

impl StateMgr {
    /// Create a new `StateMgr`.
    pub fn new(keystore_dir: impl AsRef<Path>, permissions: &Mistrust) -> tor_keymgr::Result<Self> {
        let arti_store = ArtiNativeKeystore::from_path_and_mistrust(&keystore_dir, permissions)?;

        // TODO (#1106): make the default store configurable
        let default_store = arti_store;

        let keymgr = KeyMgrBuilder::default()
            .default_store(Box::new(default_store))
            .build()
            .map_err(|e| into_internal!("failed to build KeyMgr")(e))?;

        Ok(Self { keymgr })
    }

    /// Return the onion address of the service with the specified nickname.
    ///
    /// Returns `None` if no such service is configured,
    /// or if the HsId of the service could not be found in the configured keystores.
    pub fn onion_name(&self, nickname: &HsNickname) -> Option<HsId> {
        let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());
        self.keymgr
            .get::<HsIdKey>(&hsid_spec)
            .ok()?
            .map(|hsid| hsid.id())
    }
}
