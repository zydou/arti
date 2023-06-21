#![allow(clippy::unnecessary_wraps, clippy::extra_unused_type_parameters)]

//! A dummy key manager implementation.
//!
//! This key manager implementation is only used when the `keymgr` feature is disabled.
//!
//! The implementations from this module ignore their arguments. The unused arguments can't be
//! removed, because the dummy implementations must have the same API as their fully-featured
//! counterparts.

use crate::{Error, Result};

use fs_mistrust::Mistrust;
use std::any::Any;
use std::path::Path;

/// A dummy key manager implementation.
///
/// This implementation has the same API as the key manager exposed when the `keymgr` feature is
/// enabled, except all its read operations return `None` and all its write operations will fail.
///
/// For operations that normally involve updating the state of the key manager and/or its
/// underlying storage, such as `insert` or `remove`, this `KeyMgr` always returns an [`Error`].
#[derive(Copy, Clone, Debug)]
pub struct KeyMgr;

/// A dummy key store trait.
pub trait KeyStore {
    // TODO(gabi): Add the missing functions and impls
}

/// A dummy `ArtiNativeKeyStore`.
pub struct ArtiNativeKeyStore;

/// A dummy `KeyType`.
pub struct KeyType;

impl ArtiNativeKeyStore {
    /// Create a new [`ArtiNativeKeyStore`].
    #[allow(clippy::unnecessary_wraps)]
    pub fn from_path_and_mistrust(_: impl AsRef<Path>, _: &Mistrust) -> Result<Self> {
        Ok(Self)
    }
}

impl KeyStore for ArtiNativeKeyStore {}

impl KeyMgr {
    /// Create a new [`KeyMgr`].
    pub fn new(_: Vec<Box<dyn KeyStore>>) -> Self {
        Self
    }

    /// A dummy `get` implementation that always behaves like the requested key is not found.
    ///
    /// This function always returns `Ok(None)`.
    pub fn get<K>(&self, _: &dyn Any) -> Result<Option<K>> {
        Ok(None)
    }

    /// A dummy `insert` implementation that always fails.
    ///
    /// This function always returns [`Error`].
    pub fn insert<K>(&self, _: K, _: &dyn Any) -> Result<()> {
        Err(Error::KeyMgrNotSupported)
    }

    /// A dummy `remove` implementation that always fails.
    ///
    /// This function always returns [`Error`].
    pub fn remove<K>(&self, _: &dyn Any) -> Result<Option<()>> {
        Err(Error::KeyMgrNotSupported)
    }
}
