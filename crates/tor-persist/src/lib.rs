//! `tor-persist`: Persistent data storage for use with Tor.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! For now, users should construct storage objects directly with (for
//! example) [`FsStateMgr::from_path()`], but use them primarily via the
//! interfaces of the [`StateMgr`] trait.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

#[cfg(not(target_arch = "wasm32"))]
mod fs;
mod handle;
#[cfg(feature = "testing")]
mod testing;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

/// Wrapper type for Results returned from this crate.
type Result<T> = std::result::Result<T, crate::Error>;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::FsStateMgr;
pub use handle::{DynStorageHandle, StorageHandle};
pub use serde_json::Value as JsonValue;
#[cfg(feature = "testing")]
pub use testing::TestingStateMgr;

/// An object that can manage persistent state.
///
/// State is implemented as a simple key-value store, where the values
/// are objects that can be serialized and deserialized.
///
/// # Warnings
///
/// Current implementations may place additional limits on the types
/// of objects that can be stored.  This is not a great example of OO
/// design: eventually we should probably clarify that more.
pub trait StateMgr: Clone {
    /// Try to load the object with key `key` from the store.
    ///
    /// Return None if no such object exists.
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned;
    /// Try to save `val` with key `key` in the store.
    ///
    /// Replaces any previous value associated with `key`.
    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize;
    /// Return true if this is a read-write state manager.
    ///
    /// If it returns false, then attempts to `store` will fail with
    /// [`Error::NoLock`]
    fn can_store(&self) -> bool;

    /// Try to become a read-write state manager if possible, without
    /// blocking.
    ///
    /// This function will return an error only if something really
    /// unexpected went wrong.  It may return `Ok(_)` even if we don't
    /// acquire the lock: check the return value or call
    /// `[StateMgr::can_store()`] to see if the lock is held.
    fn try_lock(&self) -> Result<LockStatus>;

    /// Make a new [`StorageHandle`] to store values of particular type
    /// at a particular key.
    fn create_handle<T>(self, key: impl Into<String>) -> DynStorageHandle<T>
    where
        Self: Send + Sync + Sized + 'static,
        T: Serialize + DeserializeOwned + 'static,
    {
        Arc::new(handle::StorageHandleImpl::new(self, key.into()))
    }
}

/// A possible outcome from calling [`StateMgr::try_lock()`]
#[allow(clippy::exhaustive_enums)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum LockStatus {
    /// We didn't have the lock and were unable to acquire it.
    NoLock,
    /// We already held the lock, and didn't have anything to do.
    AlreadyHeld,
    /// We successfully acquired the lock for the first time.
    NewlyAcquired,
}

impl LockStatus {
    /// Return true if this status indicates that we hold the lock.
    pub fn held(&self) -> bool {
        !matches!(self, LockStatus::NoLock)
    }
}

/// An error type returned from a persistent state manager.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// Tried to save without holding an exclusive lock.
    #[error("Storage not locked")]
    NoLock,

    /// Problem when serializing or deserializing JSON data.
    #[error("JSON serialization error")]
    JsonError(#[source] Arc<serde_json::Error>),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(Arc::new(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::JsonError(Arc::new(e))
    }
}

/// A wrapper type for types whose representation may change in future versions of Arti.
///
/// This uses `#[serde(untagged)]` to attempt deserializing as a type `T` first, and falls back
/// to a generic JSON value representation if that fails.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
#[allow(clippy::exhaustive_enums)]
pub enum Futureproof<T> {
    /// A successfully-deserialized `T`.
    Understandable(T),
    /// A generic JSON value, representing a failure to deserialize a `T`.
    Unknown(JsonValue),
}

impl<T> Futureproof<T> {
    /// Convert the `Futureproof` into an `Option<T>`, throwing away an `Unknown` value.
    pub fn into_option(self) -> Option<T> {
        match self {
            Futureproof::Understandable(x) => Some(x),
            Futureproof::Unknown(_) => None,
        }
    }
}

impl<T> From<T> for Futureproof<T> {
    fn from(inner: T) -> Self {
        Self::Understandable(inner)
    }
}
