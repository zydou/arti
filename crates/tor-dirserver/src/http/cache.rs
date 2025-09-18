//! Module for providing cache implementations for the [`http`] module.
//!
//! Each cache is outlined comprehensively in its own section.

use std::sync::{Arc, Mutex, Weak};

use rusqlite::{params, Transaction};
use tor_error::internal;
use weak_table::WeakValueHashMap;

use crate::{
    err::{DatabaseError, StoreCacheError},
    schema::Sha256,
};

/// Representation of the store cache.
///
/// The cache serves the purpose to not store the same document multiple times
/// in memory, when multiple clients request it simultanously.
///
/// It *DOES NOT* serve the purpose to reduce the amount of read system calls.
/// We believe that SQLite and the operating system itself do a good job at
/// buffering reads for us here.
///
/// The cache itself is wrapped in an [`Arc`] as well as in a [`Mutex`],
/// meaning it is safe to share and access around threads/tasks.
///
/// All hash lookups in the `store` table should be performed through this
/// interface, because it will automatically select them from the database in
/// case they are missing.
#[derive(Debug, Clone)]
pub(super) struct StoreCache {
    /// The actual data of the cache.
    ///
    /// We use a [`Mutex`] instead of an [`RwLock`], because we want to assure
    /// that a concurrent cache miss does not lead into two simultanous database
    /// reads and copies into memory.
    data: Arc<Mutex<WeakValueHashMap<Sha256, Weak<[u8]>>>>,
}

impl StoreCache {
    /// Creates a new empty [`StoreCache`].
    pub(super) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(WeakValueHashMap::new())),
        }
    }

    /// Removes all mappings whose values have expired.
    ///
    /// Takes O(n) time.
    pub(super) fn gc(&mut self) -> Result<(), StoreCacheError> {
        self.data
            .lock()
            .map_err(|_| internal!("poisoned lock"))?
            .remove_expired();
        Ok(())
    }

    /// Looks up a [`Sha256`] in the cache or the database.
    ///
    /// If we got a cache miss, this function automatically queries the database
    /// and inserts the result into the cache, before returning it.
    pub(super) fn get(
        &mut self,
        tx: &Transaction,
        sha256: &Sha256,
    ) -> Result<Arc<[u8]>, StoreCacheError> {
        // TODO DIRMIRROR: Do we want to keep the lock while doing db queries?
        let mut lock = self.data.lock().map_err(|_| internal!("poisoned lock"))?;

        // Query the cache for the relevant document.
        if let Some(document) = lock.get(sha256) {
            return Ok(document);
        }

        // Cache miss, let us query the database.
        let document = Self::get_db(tx, sha256)?;

        // Insert it into the cache.
        lock.insert(sha256.clone(), document.clone());

        Ok(document)
    }

    /// Obtains a [`Sha256`] from the database without consulting the cache first.
    ///
    /// TODO DIRMIRROR: This function is only intended for use in [`StoreCache::get`].
    /// Consider to either remove it entirely or move [`StoreCache`] into its own
    /// module.
    fn get_db(tx: &Transaction, sha256: &Sha256) -> Result<Arc<[u8]>, StoreCacheError> {
        let mut stmt = tx
            .prepare_cached("SELECT content FROM store WHERE sha256 = ?1")
            .map_err(DatabaseError::from)?;
        let document: Vec<u8> = stmt
            .query_one(params![sha256], |row| row.get(0))
            .map_err(DatabaseError::from)?;
        Ok(Arc::from(document))
    }
}

// The tests are all performed in the parent module, due to existing test
// vectors there.

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::*;

    #[test]
    fn store_cache() {
        let mut conn = create_test_db_connection();
        let mut cache = StoreCache::new();

        let tx = conn.transaction().unwrap();

        // Obtain the lipsum entry.
        let entry = cache.get(&tx, &String::from(IDENTITY_SHA256)).unwrap();
        assert_eq!(entry.as_ref(), IDENTITY.as_bytes());
        assert_eq!(Arc::strong_count(&entry), 1);

        // Obtain the lipsum entry again but ensure it is not copied in memory.
        let entry2 = cache.get(&tx, &String::from(IDENTITY_SHA256)).unwrap();
        assert_eq!(Arc::strong_count(&entry), 2);
        assert_eq!(Arc::as_ptr(&entry), Arc::as_ptr(&entry2));
        assert_eq!(entry, entry2);

        // Perform a garbage collection and ensure that entry is not removed.
        assert!(cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));
        cache.gc().unwrap();
        assert!(cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));

        // Now drop entry and entry2 and perform the gc again.
        let weak_entry = Arc::downgrade(&entry);
        assert_eq!(weak_entry.strong_count(), 2);
        drop(entry);
        drop(entry2);
        assert_eq!(weak_entry.strong_count(), 0);

        // The strong count zero should already make it impossible to access the element ...
        assert!(!cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));
        // ... but it should not reduce the total size of the hash map ...
        assert_eq!(cache.data.lock().unwrap().len(), 1);
        cache.gc().unwrap();
        // ... however, the garbage collection should actually do.
        assert_eq!(cache.data.lock().unwrap().len(), 0);
    }
}
