//! Declare types for interning various objects.

use once_cell::sync::OnceCell;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use weak_table::WeakHashSet;

/// An InternCache is a lazily-constructed weak set of objects.
///
/// Let's break that down!  It's "lazily constructed" because it
/// doesn't actually allocate anything until you use it for the first
/// time.  That allows it to have a const [`new`](InternCache::new)
/// method, so you can make these static.
///
/// It's "weak" because it only holds weak references to its objects;
/// once every strong reference is gone, the object is unallocated.
/// Later, the hash entry is (lazily) removed.
pub(crate) struct InternCache<T: ?Sized> {
    /// Underlying hashset for interned objects
    cache: OnceCell<Mutex<WeakHashSet<Weak<T>>>>,
}

impl<T: ?Sized> InternCache<T> {
    /// Create a new, empty, InternCache.
    pub(crate) const fn new() -> Self {
        InternCache {
            cache: OnceCell::new(),
        }
    }
}

impl<T: Eq + Hash + ?Sized> InternCache<T> {
    /// Helper: initialize the cache if needed, then lock it.
    fn cache(&self) -> MutexGuard<'_, WeakHashSet<Weak<T>>> {
        let cache = self.cache.get_or_init(|| Mutex::new(WeakHashSet::new()));
        cache.lock().expect("Poisoned lock lock for cache")
    }
}

impl<T: Eq + Hash> InternCache<T> {
    /// Intern a given value into this cache.
    ///
    /// If `value` is already stored in this cache, we return a
    /// reference to the stored value.  Otherwise, we insert `value`
    /// into the cache, and return that.
    pub(crate) fn intern(&self, value: T) -> Arc<T> {
        let mut cache = self.cache();
        if let Some(pp) = cache.get(&value) {
            pp
        } else {
            let arc = Arc::new(value);
            cache.insert(Arc::clone(&arc));
            arc
        }
    }
}

impl<T: Hash + Eq + ?Sized> InternCache<T> {
    /// Intern an object by reference.
    ///
    /// Works with unsized types, but requires that the reference implements
    /// `Into<Arc<T>>`.
    pub(crate) fn intern_ref<'a, V>(&self, value: &'a V) -> Arc<T>
    where
        V: Hash + Eq + ?Sized,
        &'a V: Into<Arc<T>>,
        T: std::borrow::Borrow<V>,
    {
        let mut cache = self.cache();
        if let Some(arc) = cache.get(value) {
            arc
        } else {
            let arc = value.into();
            cache.insert(Arc::clone(&arc));
            arc
        }
    }
}
