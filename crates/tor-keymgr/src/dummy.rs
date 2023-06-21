//! A dummy key manager implementation.
//!
//! If arti-client is compiled with the `keymgr` feature, [`TorClient`](crate::TorClient) will use
//! the key manager implementation from the `tor-keymgr` crate.
//!
//! If arti-client is compiled without the `keymgr` feature, then [`TorClient`](crate::TorClient)
//! will use this no-op key manager implementation instead.

use fs_mistrust::Mistrust;
use std::any::Any;
use std::path::Path;
use crate::{Error, Result};

/// A dummy key manager implementation.
///
/// This implementation has the same API as the key manager from the `tor-keymgr` crate, except all
/// its operations are no-ops.
///
/// For operations that normally involve updating the state of the key manager and/or its
/// underlying storage, such as `insert` or `remove`, this `KeyMgr` always returns an [`Error`].
//
// TODO hs: Make KeyMgr have the same constructor API as tor-keymgr::KeyMgr #897
// TODO hs: Remove the generic param and inner error from KeyMgr and expose a KeyMgrError instead.
#[derive(Copy, Clone, Debug)]
pub struct KeyMgr;

/// A dummy key store trait.
pub trait KeyStore {}

/// A dummy `ArtiNativeKeyStore`.
pub struct ArtiNativeKeyStore;

/// A dummy `KeyType`.
pub struct KeyType;

impl ArtiNativeKeyStore {
    /// Create a new [`ArtiNativeKeyStore`].
    ///
    /// The arguments of this constructor are ignored. They only exist because we need this
    /// constructor to have the same API as the constructor of `ArtiNativeKeyStore` from the
    /// `tor-keymgr` crate.
    #[allow(clippy::unnecessary_wraps)]
    pub fn from_path_and_mistrust(_: impl AsRef<Path>, _: &Mistrust) -> Result<Self> {
        Ok(Self)
    }
}

impl KeyStore for ArtiNativeKeyStore {}

impl KeyMgr {
    /// Create a new [`KeyMgr`].
    ///
    /// The argument of this constructor is ignored. It only exists because we need [`KeyMgr::new`]
    /// to have the same API as the constructor of the key manager from the `tor-keymgr` crate.
    pub fn new(_: Vec<Box<dyn KeyStore>>) -> Self {
        Self
    }

    /// A dummy `get` implementation that always behaves like the requested key is not found.
    ///
    /// This function always returns `Ok(None)`.
    //
    // TODO hs: remove
    #[allow(unused)]
    // We need to allow these lints because this impl needs to mirror that of `tor_keymgr::KeyMgr`.
    #[allow(clippy::unnecessary_wraps, clippy::extra_unused_type_parameters)]
    pub fn get<K>(&self, _: &dyn Any) -> Result<Option<K>> {
        Ok(None)
    }

    /// A dummy `insert` implementation that always fails.
    ///
    /// This function always returns [`Error`].
    //
    // TODO hs: remove
    #[allow(unused)]
    // We need to allow these lints because this impl needs to mirror that of `tor_keymgr::KeyMgr`.
    #[allow(clippy::unnecessary_wraps)]
    pub fn insert<K>(&self, _: K, _: &dyn Any) -> Result<()> {
        Err(Error::KeyMgrNotSupported)
    }

    /// A dummy `remove` implementation that always fails.
    ///
    /// This function always returns [`Error`].
    //
    // TODO hs: remove
    #[allow(unused)]
    // We need to allow these lints because this impl needs to mirror that of `tor_keymgr::KeyMgr`.
    #[allow(clippy::unnecessary_wraps, clippy::extra_unused_type_parameters)]
    pub fn remove<K>(&self, _: &dyn Any) -> Result<Option<()>> {
        Err(Error::KeyMgrNotSupported)
    }
}
