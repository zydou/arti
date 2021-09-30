//! Testing-only StateMgr that stores values in a hash table.

use crate::{Error, Result, StateMgr};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A state manager for testing support, that allows simulating persistence
/// without having to store anything to disk.
///
/// Only available when this crate is built with the `testing` feature.
#[derive(Clone, Default, Debug)]
pub struct TestingStateMgr {
    /// Inner reference-counted storage.
    inner: Arc<Mutex<TestingStateMgrInner>>,
}

/// Implementation type for [`TestingStateMgr`]
#[derive(Default, Debug)]
struct TestingStateMgrInner {
    /// True if we currently hold the simulated write lock on the
    /// state. Only one process is supposed to hold this at a time,
    lock_held: bool,
    /// True if we are pretending that someone else is holding the
    /// simulated write lock on the state.
    lock_blocked: bool,
    /// Map from key to toml-encoded values.
    ///
    /// We serialize our values here for conveinence (so that we don't
    /// have to use `Any`) and to try to detect any
    /// serialization-related bugs.
    entries: HashMap<String, String>,
}

impl TestingStateMgr {
    /// Create a new empty [`TestingStateMgr`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate another process holding the lock.
    ///
    /// Subsequent attempts to acquire the lock will fail.
    ///
    /// # Panics
    ///
    /// Panics if we've already aquired the lock.
    pub fn block_lock_attempts(&self) {
        let mut inner = self.inner.lock().expect("Lock poisoned.");
        assert!(!inner.lock_held);
        inner.lock_blocked = true;
    }

    /// Simulate another process releasing the lock.
    ///
    /// Subsequent attempts to acquire the lock will succeed.
    pub fn unblock_lock_attempts(&self) {
        self.inner.lock().expect("Lock poisoned.").lock_blocked = false;
    }
}

impl StateMgr for TestingStateMgr {
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let inner = self.inner.lock().expect("Lock poisoned.");
        match inner.entries.get(key) {
            Some(value) => Ok(Some(toml::from_str(value)?)),
            None => Ok(None),
        }
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        let mut inner = self.inner.lock().expect("Lock poisoned.");
        if !inner.lock_held {
            return Err(Error::NoLock);
        }

        let val = toml::ser::to_string(val)?;
        inner.entries.insert(key.to_string(), val);
        Ok(())
    }

    fn can_store(&self) -> bool {
        let inner = self.inner.lock().expect("Lock poisoned.");

        inner.lock_held
    }

    fn try_lock(&self) -> Result<bool> {
        let mut inner = self.inner.lock().expect("Lock poisoned.");
        if inner.lock_blocked {
            Ok(false)
        } else {
            inner.lock_held = true;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
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

    #[test]
    fn basic_tests() {
        let mgr = TestingStateMgr::new();
        let v1 = Ex1 { v1: 8, v2: 99 };
        let s1 = Ex2 {
            s1: "Hello".into(),
            s2: "World".into(),
        };

        assert_eq!(mgr.load::<Ex1>("item1").unwrap(), None);
        assert!(matches!(mgr.store("item1", &v1), Err(Error::NoLock)));

        assert!(!mgr.can_store());
        assert!(mgr.try_lock().unwrap());
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

        mgr.block_lock_attempts();
        assert!(!mgr.try_lock().unwrap()); // can't get the lock.
        assert!(!mgr.can_store()); // can't store.

        mgr.unblock_lock_attempts();
        assert!(!mgr.can_store()); // can't store.
        assert!(mgr.try_lock().unwrap()); // *can* get the lock.
        assert!(mgr.can_store()); // can't store.
    }

    #[test]
    fn typesafe_handles() {
        use crate::DynStorageHandle;
        let mgr = TestingStateMgr::new();

        let h1: DynStorageHandle<Ex1> = mgr.clone().create_handle("foo");
        let h2: DynStorageHandle<Ex2> = mgr.clone().create_handle("bar");
        let h3: DynStorageHandle<Ex2> = mgr.create_handle("baz");

        let v1 = Ex1 { v1: 1, v2: 2 };
        let s1 = Ex2 {
            s1: "aaa".into(),
            s2: "bbb".into(),
        };
        let s2 = Ex2 {
            s1: "jj".into(),
            s2: "yrfmstbyes".into(),
        };

        assert!(matches!(h1.store(&v1), Err(Error::NoLock)));
        assert!(h1.try_lock().unwrap());
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
}
