//! Testing-only StateMgr that stores values in a hash table.

use crate::err::{Action, ErrorSource, Resource};
use crate::{Error, LockStatus, Result, StateMgr};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A state manager for testing support, that allows simulating persistence
/// without having to store anything to disk.
///
/// Only available when this crate is built with the `testing` feature.
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[derive(Clone, Debug)]
pub struct TestingStateMgr {
    /// Inner reference-counted storage.
    inner: Arc<Mutex<TestingStateMgrInner>>,
}

/// The inner state of a TestingStateMgr.
#[derive(Debug)]
struct TestingStateMgrInner {
    /// True if this manager, and all references to it, hold the lock on
    /// the storage.
    lock_held: bool,
    /// The underlying shared storage object.
    storage: Arc<Mutex<TestingStateMgrStorage>>,
}

impl TestingStateMgrInner {
    /// Release the lock, if we hold it. Otherwise, do nothing.
    fn unlock(&mut self) {
        if self.lock_held {
            self.lock_held = false;
            let mut storage = self.storage.lock().expect("Lock poisoned");
            storage.lock_available = true;
        }
    }
}

/// Implementation type for [`TestingStateMgr`]: represents an underlying
/// storage system that can be shared by multiple TestingStateMgr instances
/// at a time, only one of which can hold the lock.
#[derive(Debug)]
struct TestingStateMgrStorage {
    /// True if nobody currently holds the lock for this storage.
    lock_available: bool,
    /// Map from key to JSON-encoded values.
    ///
    /// We serialize our values here for convenience (so that we don't
    /// have to use `Any`) and to try to detect any
    /// serialization-related bugs.
    entries: HashMap<String, String>,
}

impl Default for TestingStateMgr {
    fn default() -> Self {
        Self::new()
    }
}

impl TestingStateMgr {
    /// Create a new empty unlocked [`TestingStateMgr`].
    pub fn new() -> Self {
        let storage = TestingStateMgrStorage {
            lock_available: true,
            entries: HashMap::new(),
        };
        let inner = TestingStateMgrInner {
            lock_held: false,
            storage: Arc::new(Mutex::new(storage)),
        };
        TestingStateMgr {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Create a new unlocked [`TestingStateMgr`] that shares the same
    /// underlying storage with this one.
    #[must_use]
    pub fn new_manager(&self) -> Self {
        let inner = self.inner.lock().expect("Lock poisoned.");
        let new_inner = TestingStateMgrInner {
            lock_held: false,
            storage: Arc::clone(&inner.storage),
        };
        TestingStateMgr {
            inner: Arc::new(Mutex::new(new_inner)),
        }
    }

    /// Return an error Resource corresponding to a given `key`.
    fn err_resource(&self, key: &str) -> Resource {
        Resource::Temporary {
            key: key.to_string(),
        }
    }
}

impl StateMgr for TestingStateMgr {
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let inner = self.inner.lock().expect("Lock poisoned.");
        let storage = inner.storage.lock().expect("Lock poisoned.");
        let content = storage.entries.get(key);
        match content {
            Some(value) => {
                Ok(Some(serde_json::from_str(value).map_err(|e| {
                    Error::new(e, Action::Loading, self.err_resource(key))
                })?))
            }
            None => Ok(None),
        }
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        let inner = self.inner.lock().expect("Lock poisoned.");
        if !inner.lock_held {
            return Err(Error::new(
                ErrorSource::NoLock,
                Action::Storing,
                Resource::Manager,
            ));
        }
        let mut storage = inner.storage.lock().expect("Lock poisoned.");

        let val = serde_json::to_string_pretty(val)
            .map_err(|e| Error::new(e, Action::Storing, self.err_resource(key)))?;

        storage.entries.insert(key.to_string(), val);
        Ok(())
    }

    fn can_store(&self) -> bool {
        let inner = self.inner.lock().expect("Lock poisoned.");

        inner.lock_held
    }

    fn try_lock(&self) -> Result<LockStatus> {
        let mut inner = self.inner.lock().expect("Lock poisoned.");
        if inner.lock_held {
            return Ok(LockStatus::AlreadyHeld);
        }

        let mut storage = inner.storage.lock().expect("Lock poisoned");
        if storage.lock_available {
            storage.lock_available = false;
            drop(storage); // release borrow
            inner.lock_held = true;
            Ok(LockStatus::NewlyAcquired)
        } else {
            Ok(LockStatus::NoLock)
        }
    }

    fn unlock(&self) -> Result<()> {
        let mut inner = self.inner.lock().expect("Lock poisoned.");
        inner.unlock();
        Ok(())
    }
}

impl Drop for TestingStateMgrInner {
    fn drop(&mut self) {
        self.unlock();
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    struct Ex1 {
        v1: u32,
        v2: u64,
    }
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    struct Ex2 {
        s1: String,
        s2: String,
    }
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    enum OldEnum {
        Variant1,
    }
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    enum NewEnum {
        Variant1,
        Variant2,
    }

    #[test]
    fn basic_tests() {
        let mgr = TestingStateMgr::new();
        let v1 = Ex1 { v1: 8, v2: 99 };
        let s1 = Ex2 {
            s1: "Hello".into(),
            s2: "World".into(),
        };

        assert_eq!(mgr.load::<Ex1>("item1").unwrap(), None);
        assert!(matches!(
            mgr.store("item1", &v1).unwrap_err().source(),
            ErrorSource::NoLock
        ));

        assert!(!mgr.can_store());
        assert_eq!(mgr.try_lock().unwrap(), LockStatus::NewlyAcquired);
        assert!(mgr.can_store());

        assert!(mgr.store("item1", &v1).is_ok());
        assert_eq!(mgr.load::<Ex1>("item1").unwrap(), Some(v1));
        assert!(mgr.load::<Ex2>("item1").is_err());

        assert!(mgr.store("item2", &s1).is_ok());
        assert_eq!(mgr.load::<Ex2>("item2").unwrap(), Some(s1));
        assert!(mgr.load::<Ex1>("item2").is_err());

        let v2 = Ex1 { v1: 10, v2: 12 };
        assert!(mgr.store("item1", &v2).is_ok());
        assert_eq!(mgr.load::<Ex1>("item1").unwrap(), Some(v2));
    }

    #[test]
    fn lock_blocking() {
        let mgr = TestingStateMgr::new();

        assert!(!mgr.can_store());

        let mgr2 = mgr.new_manager();

        assert_eq!(mgr.try_lock().unwrap(), LockStatus::NewlyAcquired);
        assert_eq!(mgr.try_lock().unwrap(), LockStatus::AlreadyHeld);
        assert!(mgr.can_store());

        assert!(!mgr2.can_store());
        assert_eq!(mgr2.try_lock().unwrap(), LockStatus::NoLock);
        assert!(!mgr2.can_store());

        drop(mgr);
        assert_eq!(mgr2.try_lock().unwrap(), LockStatus::NewlyAcquired);
        assert!(mgr2.can_store());
    }

    #[test]
    fn typesafe_handles() {
        use crate::DynStorageHandle;
        let mgr = TestingStateMgr::new();

        let h1: DynStorageHandle<Ex1> = mgr.clone().create_handle("foo");
        let h2: DynStorageHandle<Ex2> = mgr.clone().create_handle("bar");
        let h3: DynStorageHandle<Ex2> = mgr.clone().create_handle("baz");

        let v1 = Ex1 { v1: 1, v2: 2 };
        let s1 = Ex2 {
            s1: "aaa".into(),
            s2: "bbb".into(),
        };
        let s2 = Ex2 {
            s1: "jj".into(),
            s2: "yrfmstbyes".into(),
        };

        assert!(matches!(
            h1.store(&v1).unwrap_err().source(),
            ErrorSource::NoLock
        ));
        assert!(mgr.try_lock().unwrap().held());
        assert!(h1.can_store());
        assert!(h1.store(&v1).is_ok());

        assert!(h2.can_store());
        assert!(h2.store(&s1).is_ok());
        assert!(h3.load().unwrap().is_none());
        assert!(h3.store(&s2).is_ok());

        assert_eq!(h1.load().unwrap(), Some(v1));
        assert_eq!(h2.load().unwrap(), Some(s1));
        assert_eq!(h3.load().unwrap(), Some(s2));
    }

    #[test]
    fn futureproof() {
        use crate::Futureproof;

        let v1 = Ex1 { v1: 8, v2: 99 };

        let v1_ser = serde_json::to_string(&v1).unwrap();

        let v1_as_ex1: Futureproof<Ex1> = serde_json::from_str(&v1_ser).unwrap();
        let v1_as_ex2: Futureproof<Ex2> = serde_json::from_str(&v1_ser).unwrap();
        assert!(v1_as_ex1.clone().into_option().is_some());
        assert!(v1_as_ex2.into_option().is_none());

        assert_eq!(serde_json::to_string(&v1_as_ex1).unwrap(), v1_ser);
    }

    #[test]
    fn futureproof_enums() {
        use crate::Futureproof;

        let new1 = NewEnum::Variant1;
        let new2 = NewEnum::Variant2;

        let new1_ser = serde_json::to_string(&new1).unwrap();
        let new2_ser = serde_json::to_string(&new2).unwrap();

        let old1: Futureproof<OldEnum> = serde_json::from_str(&new1_ser).unwrap();
        let old2: Futureproof<OldEnum> = serde_json::from_str(&new2_ser).unwrap();

        assert!(old1.into_option().is_some());
        assert!(old2.into_option().is_none());
    }
}
