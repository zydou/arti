#![allow(clippy::unnecessary_wraps, clippy::extra_unused_type_parameters)]

//! A dummy key manager implementation.
//!
//! This key manager implementation is only used when the `keymgr` feature is disabled.
//!
//! The implementations from this module ignore their arguments. The unused arguments can't be
//! removed, because the dummy implementations must have the same API as their fully-featured
//! counterparts.

use crate::{KeystoreError, Result};
use tor_error::HasKind;

use fs_mistrust::Mistrust;
use std::any::Any;
use std::error::Error as StdError;
use std::path::Path;

/// A dummy key manager implementation.
///
/// This implementation has the same API as the key manager exposed when the `keymgr` feature is
/// enabled, except all its read operations return `None` and all its write operations will fail.
///
/// For operations that normally involve updating the state of the key manager and/or its
/// underlying storage, such as `insert` or `remove`, this `KeyMgr` always returns an [`Error`].
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct KeyMgr;

/// A dummy key store trait.
pub trait KeyStore {
    // TODO(gabi): Add the missing functions and impls
}

/// A dummy `ArtiNativeKeyStore`.
#[non_exhaustive]
pub struct ArtiNativeKeyStore;

/// A dummy `KeyType`.
#[non_exhaustive]
pub struct KeyType;

/// A dummy `Error` indicating that key manager support is disabled in cargo features.
#[non_exhaustive]
#[derive(Debug, Clone, thiserror::Error)]
#[error("Key manager support disabled in cargo features")]
struct Error;

impl KeystoreError for Error {}

impl HasKind for Error {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::Other
    }
}

impl AsRef<dyn StdError + 'static> for Error {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        self
    }
}

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
        Err(Box::new(Error))
    }

    /// A dummy `remove` implementation that always fails.
    ///
    /// This function always returns [`Error`].
    pub fn remove<K>(&self, _: &dyn Any) -> Result<Option<()>> {
        Err(Box::new(Error))
    }
}
