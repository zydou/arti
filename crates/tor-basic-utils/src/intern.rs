//! Declare types for interning various objects.

use std::fmt::Debug;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use derive_deftly::define_derive_deftly;
use derive_more::{Deref, Display, Into};
use educe::Educe;

/// Alias to force use of RandomState, regardless of features enabled in `weak_tables`.
///
/// See <https://github.com/tov/weak-table-rs/issues/23> for discussion.
type WeakHashSet<T> = weak_table::WeakHashSet<T, std::hash::RandomState>;

/// A wrapper around [`Arc`] representing owned [`InternCache`] entries.
///
/// The wrapper type serves the purpose of semantic meaning only, implying that
/// this value is cached in some way or another by this module.
///
/// We only conveniently allow obtaining the underlying [`Arc`] with a [`From`] but not the
/// other way around.  This means that interfacing code can make the type to
/// "forget" it originated from an [`InternCache`] but not the other way around,
/// i.e. cannot accidentally create fake entries that look like they came from an
/// [`InternCache`].  If one really has to circumvent this, then the
/// [`Intern::new_uncached_uninterned()`] method exists.
///
/// This ensures that interning is done everywhere that it's expected,
/// avoiding excess memory usage.
//
// Right now, this is the bare minimum of derives; it may need more in the
// future.  If so, just add them.
#[derive(Debug, Default, PartialEq, Eq, Hash, Display, Into, Deref, Educe)]
#[educe(Clone)]
pub struct Intern<T: ?Sized>(Arc<T>);

impl<T: ?Sized> Intern<T> {
    /// Creates an [`Intern`] from an arbitrary [`Arc`].
    ///
    /// The use of this is generally discouraged, as it effectively destroys
    /// the boundary of implying that certain cache entries come from the
    /// [`InternCache`].
    pub fn new_uncached_uninterned(value: Arc<T>) -> Intern<T> {
        Intern(value)
    }
}

// Some Arti code is pretty keen on using &Arc<T>.
impl<'a, T: ?Sized> From<&'a Intern<T>> for &'a Arc<T> {
    fn from(value: &'a Intern<T>) -> Self {
        &value.0
    }
}

/// Offers access to globally available cache for [`InternCache`].
///
/// Typically derived using [`crate::derive_deftly_template_GloballyInternable`].
pub trait GloballyInternable: Sized {
    /// Returns a reference to the global cache instance of this type.
    ///
    /// Implemented by implementors of this trait.
    /// Users of the trait should usually use [`GloballyInternable::into_intern()`].
    fn intern_cache() -> &'static InternCache<Self>;

    /// Places `self` into the global cache.
    ///
    /// Please use this instead of `T::intern_cache().intern(value)`.
    fn into_intern(self) -> Intern<Self>
    where
        Self: Eq + Hash + 'static,
    {
        Self::intern_cache().intern(self)
    }
}

define_derive_deftly! {
    /// Implement the [`GloballyInternable`] trait for a specific type.
    ///
    /// The implementation in itself is trivial and straightforward with this
    /// macro primarily serving as a convenience method.
    export GloballyInternable for struct:

    impl $crate::intern::GloballyInternable for $ttype {
        fn intern_cache() -> &'static $crate::intern::InternCache<Self> {
            static S: $crate::intern::InternCache::<$ttype> = $crate::intern::InternCache::new();
            &S
        }
    }
}

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
pub struct InternCache<T: ?Sized> {
    /// Underlying hashset for interned objects
    //
    // TODO: If WeakHashSet::new is someday const, we can do away with OnceLock here.
    cache: OnceLock<Mutex<WeakHashSet<Weak<T>>>>,
}

impl<T: ?Sized> InternCache<T> {
    /// Create a new, empty, InternCache.
    pub const fn new() -> Self {
        InternCache {
            cache: OnceLock::new(),
        }
    }
}

impl<T: ?Sized> Default for InternCache<T> {
    fn default() -> Self {
        Self::new()
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
    pub fn intern(&self, value: T) -> Intern<T> {
        let mut cache = self.cache();
        if let Some(pp) = cache.get(&value) {
            Intern(pp)
        } else {
            let arc = Arc::new(value);
            cache.insert(Arc::clone(&arc));
            Intern(arc)
        }
    }
}

impl<T: Hash + Eq + ?Sized> InternCache<T> {
    /// Intern an object by reference.
    ///
    /// Works with unsized types, but requires that the reference implements
    /// `Into<Arc<T>>`.
    pub fn intern_ref<'a, V>(&self, value: &'a V) -> Intern<T>
    where
        V: Hash + Eq + ?Sized,
        &'a V: Into<Arc<T>>,
        T: std::borrow::Borrow<V>,
    {
        let mut cache = self.cache();
        if let Some(arc) = cache.get(value) {
            Intern(arc)
        } else {
            let arc = value.into();
            cache.insert(Arc::clone(&arc));
            Intern(arc)
        }
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn interning_by_value() {
        // "intern" case.
        let c: InternCache<String> = InternCache::new();

        let s1: Arc<String> = c.intern("abc".to_string()).into();
        let s2 = c.intern("def".to_string()).into();
        let s3 = c.intern("abc".to_string()).into();
        assert!(Arc::ptr_eq(&s1, &s3));
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(s2.as_ref(), "def");
        assert_eq!(s3.as_ref(), "abc");
    }

    #[test]
    fn interning_by_ref() {
        // "intern" case.
        let c: InternCache<str> = InternCache::new();

        let s1: Arc<str> = c.intern_ref("abc").into();
        let s2 = c.intern_ref("def").into();
        let s3 = c.intern_ref("abc").into();
        assert!(Arc::ptr_eq(&s1, &s3));
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(&*s2, "def");
        assert_eq!(&*s3, "abc");
    }
}
