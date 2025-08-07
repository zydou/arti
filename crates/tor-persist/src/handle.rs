//! Object-safe, type-safe wrappers for [`StateMgr`].

use crate::{Result, StateMgr};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::sync::Arc;

/// A handle to a storage system that stores objects of a single
/// type to a single location.
///
/// To get an object of this type, call [`StateMgr::create_handle`].
///
/// Unlike StateMgr, this trait is object-safe.
pub trait StorageHandle<T: Serialize + DeserializeOwned> {
    /// Try to load the object from storage.
    ///
    /// If no object exists, return Ok(None).
    fn load(&self) -> Result<Option<T>>;

    /// Try to store a value into storage.
    fn store(&self, val: &T) -> Result<()>;

    /// Return true if we have the lock; see [`StateMgr::can_store`].
    fn can_store(&self) -> bool;
}

/// Type wrapper for a reference-counted `dyn` [`StorageHandle`].
///
/// Most users of this crate will want to access storage via a handle
/// of this kind, so that they don't have to parameterize over
/// [`StateMgr`].  The cost of using a fat pointer here should be
/// pretty small compared to the overhead of persistent storage in
/// general.
pub type DynStorageHandle<T> = Arc<dyn StorageHandle<T> + Send + Sync + 'static>;

/// Concrete implementation of [`StorageHandle`].
#[derive(Debug)]
pub(crate) struct StorageHandleImpl<M, T> {
    /// An underlying [`StateMgr`] to use.
    ///
    /// The type `M` should probably implement Clone, since we store it
    /// here and don't give it back.
    mgr: M,
    /// The key to use when loading and storing from the [`StateMgr`].
    key: String,
    /// A zero-sized type to please the type checker, which will otherwise
    /// complain about the absence of anything in the struct that uses T.
    ///
    /// This uses `fn(T) -> T` to ensure that the type T is mentioned and
    /// has the correct variance, without forcing this type to have
    /// the same `Send`/`Sync` status as T.
    phantom: PhantomData<fn(T) -> T>,
}

impl<M, T> StorageHandle<T> for StorageHandleImpl<M, T>
where
    M: StateMgr,
    T: Serialize + DeserializeOwned + 'static,
{
    fn load(&self) -> Result<Option<T>> {
        self.mgr.load(&self.key)
    }
    fn store(&self, val: &T) -> Result<()> {
        self.mgr.store(&self.key, val)
    }
    fn can_store(&self) -> bool {
        self.mgr.can_store()
    }
}

impl<M, T> StorageHandleImpl<M, T>
where
    M: Send + Sync + 'static,
    T: Serialize + DeserializeOwned + 'static,
{
    /// Construct a new StorageHandleImpl.
    pub(crate) fn new(mgr: M, key: String) -> StorageHandleImpl<M, T> {
        StorageHandleImpl {
            mgr,
            key,
            phantom: PhantomData,
        }
    }
}
