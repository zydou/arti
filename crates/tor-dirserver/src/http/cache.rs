//! Module for providing cache implementations for the [`http`] module.
//!
//! Each cache is outlined comprehensively in its own section.

use std::sync::{Arc, Mutex, MutexGuard, Weak};

use rusqlite::{params, Transaction};
use weak_table::WeakValueHashMap;

use crate::{
    database::{sql, Sha256},
    err::DatabaseError,
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
/// The cache itself is wrapped in a [`Mutex`] to ensure secure access across
/// thread boundaries.  Keep in mind, that it is a **synchronous** mutex.
///
/// All hash lookups in the `store` table should be performed through this
/// interface, because it will automatically select them from the database in
/// case they are missing.
#[derive(Debug)]
pub(super) struct StoreCache {
    /// The actual data of the cache.
    ///
    /// We use a [`Mutex`] instead of an [`RwLock`](std::sync::RwLock), because
    /// we want to assure that a concurrent cache miss does not lead into two
    /// simultanous database reads and copies into memory.
    data: Mutex<WeakValueHashMap<Sha256, Weak<[u8]>>>,
}

impl StoreCache {
    /// Creates a new empty [`StoreCache`].
    pub(super) fn new() -> Self {
        Self {
            data: Mutex::new(WeakValueHashMap::new()),
        }
    }

    /// Removes all mappings whose values have expired.
    ///
    /// Takes O(n) time.
    pub(super) fn gc(&self) {
        self.lock().remove_expired();
    }

    /// Looks up a [`Sha256`] in the cache or the database.
    ///
    /// If we got a cache miss, this function automatically queries the database
    /// and inserts the result into the cache, before returning it.
    ///
    /// We do not keep a lock throughout the entire method.  This risks storing
    /// the same document in memory for a very short amount of time, based upon
    /// the number of worker threads we are using.  However, this is fine,
    /// given that reading from the store table is a large performance bottleneck.
    /// Also, the number of simultanous copies that might be risked by that is
    /// limited to the amount of worker threads, which is usually very low
    /// compared to the number of async tasks, which might be in the thousands.
    pub(super) fn get(
        &self,
        tx: &Transaction,
        sha256: &Sha256,
    ) -> Result<Arc<[u8]>, DatabaseError> {
        // Query the cache for the relevant document.
        if let Some(document) = self.lock().get(sha256) {
            return Ok(document);
        }

        // Cache miss, let us query the database.
        let document = Self::get_db(tx, sha256)?;

        // Insert it into the cache.
        //
        // We obtain the lock and check again if it has been added in the
        // meantime.  The idea is to only return one copy of it, not two
        // simultanous ones.
        Ok(self.lock().entry(sha256.clone()).or_insert(document))
    }

    /// Obtains a [`Sha256`] from the database without consulting the cache first.
    fn get_db(tx: &Transaction, sha256: &Sha256) -> Result<Arc<[u8]>, DatabaseError> {
        let mut stmt = tx.prepare_cached(sql!("SELECT content FROM store WHERE sha256 = ?1"))?;
        let document: Vec<u8> = stmt.query_one(params![sha256], |row| row.get(0))?;
        Ok(Arc::from(document))
    }

    /// Obtains a lock of the [`WeakValueHashMap`] even if the lock is poisoned.
    ///
    /// Ignoring the [`PoisonError`](std::sync::PoisonError) is fine here because
    /// the only "danger" in the general case of this might be, that certain
    /// invariants no longer hold true.  However, unless the poison has been
    /// triggered by the implementation of [`WeakValueHashMap`], in which case we
    /// would have much larger problems, doing this is fine.
    ///
    /// TODO DIRMIRROR: Consider cleaning the poison, although that would probably
    /// involve much more complexity and wrapping around the parent type.
    fn lock(&self) -> MutexGuard<'_, WeakValueHashMap<Sha256, Weak<[u8]>>> {
        self.data.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// The tests are all performed in the parent module, due to existing test
// vectors there.

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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::database;

    use super::super::test::*;
    use super::*;

    #[test]
    fn store_cache() {
        let pool = create_test_db_pool();
        let cache = StoreCache::new();

        database::read_tx(&pool, |tx| {
            // Obtain the lipsum entry.
            let entry = cache.get(tx, &String::from(IDENTITY_SHA256)).unwrap();
            assert_eq!(entry.as_ref(), IDENTITY.as_bytes());
            assert_eq!(Arc::strong_count(&entry), 1);

            // Obtain the lipsum entry again but ensure it is not copied in memory.
            let entry2 = cache.get(tx, &String::from(IDENTITY_SHA256)).unwrap();
            assert_eq!(Arc::strong_count(&entry), 2);
            assert_eq!(Arc::as_ptr(&entry), Arc::as_ptr(&entry2));
            assert_eq!(entry, entry2);

            // Perform a garbage collection and ensure that entry is not removed.
            assert!(cache
                .data
                .lock()
                .unwrap()
                .contains_key(&String::from(IDENTITY_SHA256)));
            cache.gc();
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
            cache.gc();
            // ... however, the garbage collection should actually do.
            assert_eq!(cache.data.lock().unwrap().len(), 0);
        })
        .unwrap();
    }
}
