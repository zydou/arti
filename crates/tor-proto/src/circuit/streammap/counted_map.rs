//! Implement a HashMap wrapper that counts whether a given property applies to one of its members.
//!
//! This module is structured so that we could eventually move it into a different crate and make it
//! public; For now, we are keeping in private until we find that there's a use for it somewhere else.

// So that we can declare these things as if they were in their own crate.
#![allow(unreachable_pub)]

use std::{
    borrow::Borrow,
    collections::{hash_map, HashMap},
    hash::Hash,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use educe::Educe;

/// A property that can be true or false of a given item.
pub trait Predicate {
    /// The type of item that this predicate can check.
    type Item;
    /// Return true if this property is true of `item`.
    ///
    /// # Correctness
    ///
    /// We require that `check()` always returns the same answer
    /// for the same item, even if items have interior mutability.
    //
    // TODO: Arguably this should take `&self`.
    fn check(item: &Self::Item) -> bool;
}

/// A `HashMap` that counts how many items have a given property.
///
/// This type behaves more or less the same as the standard `HashMap`,
/// but also keeps track of how many of its values
/// have `P::check(value)` return `true`.
/// It exposes this number through its [`count`](CountedHashMap::count) method,
/// which runs in O(1) time.
///
/// ## Handling of panics
///
/// If `P::check` or `K as Hash` panics, the `CountedHashMap`'s count may become incorrect,
/// and it is even possible that future accesses to the map might panic.
#[derive(Clone, Debug, Educe)]
#[educe(Default)]
pub struct CountedHashMap<K, V, P> {
    /// The underlying hashmap.
    map: HashMap<K, V>,
    /// The number of elements in `map` for which `P::check` is true
    count: usize,
    /// Marker to declare that `P` is used.
    _phantom: PhantomData<fn(P) -> P>,
}

impl<K, V, P> CountedHashMap<K, V, P> {
    /// Return a new empty `CountedHashMap`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<K, V, P> CountedHashMap<K, V, P>
where
    P: Predicate<Item = V>,
{
    /// Return the number of elements whose values have the given property.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the number of elements in this map.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return true if this map has no elements.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// If we're compiled in testing mode, assert that our count invariant holds.
    fn testing_assert_recount_ok(&self) {
        #[cfg(all(test, debug_assertions))]
        {
            let recount = self.map.values().filter(|val| P::check(val)).count();
            debug_assert_eq!(recount, self.count);
        }
    }

    /// Return a mutable iterator over the items in this map.
    ///
    /// # Correctness
    ///
    /// This iterator does not re-check `P` for the items.
    ///
    /// Therefore, the caller must ensure that any changes made to the items
    /// preserve the original values of `P::check`.
    ///
    /// If the caller does not enforce this property, the count will become incorrect.
    pub fn iter_mut_unchecked(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.map.iter_mut()
    }

    /// Return an iterator over the items in this map.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }
}

impl<K, V, P> CountedHashMap<K, V, P>
where
    K: Hash + Eq + PartialEq,
    P: Predicate<Item = V>,
{
    /// Return a reference to a value in this map.
    #[allow(dead_code)]
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.map.get(k)
    }

    /// Unsafely return a mutable reference to a value in this map.
    ///
    /// # Correctness
    ///
    /// This function does not re-check `P` for the returned value.
    ///
    /// Therefore, the caller must ensure that any changes made to the value
    /// preserve the original value of `P::check`.
    /// If the caller does not enforce this property, the count will become incorrect.
    ///
    /// Most callers should use use `get_mut` instead.
    pub fn get_mut_unchecked<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.map.get_mut(k)
    }

    /// Return a mutable reference to an value in this map.
    ///
    /// The caller may modify the values via this reference.
    #[allow(dead_code)]
    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<MutRef<'_, V, P>>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        if let Some(base) = self.map.get_mut(k) {
            let contributed_to_count = P::check(base);
            Some(MutRef {
                base,
                contributed_to_count,
                count_ref: &mut self.count,
                phantom: PhantomData,
            })
        } else {
            None
        }
    }

    /// Add a new entry to this map.
    ///
    /// Return the old entry for the provided key(if any).
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        if P::check(&v) {
            self.count += 1;
        }
        let old_val = self.map.insert(k, v);
        if old_val.as_ref().is_some_and(P::check) {
            self.count -= 1;
        }

        self.testing_assert_recount_ok();
        old_val
    }

    /// Remove an entry from this map.
    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let old_val = self.map.remove(k);
        if old_val.as_ref().is_some_and(P::check) {
            self.count -= 1;
            self.testing_assert_recount_ok();
        }
        old_val
    }

    /// Return an Entry that can be used to modify a (key,value) pair in this map.
    pub fn entry(&mut self, k: K) -> Entry<'_, K, V, P> {
        match self.map.entry(k) {
            hash_map::Entry::Occupied(base) => {
                let contributed_to_count = P::check(base.get());
                Entry::Occupied(OccupiedEntry {
                    base,
                    contributed_to_count,
                    count_ref: &mut self.count,
                    phantom: PhantomData,
                })
            }

            hash_map::Entry::Vacant(base) => Entry::Vacant(VacantEntry {
                base,
                count_ref: &mut self.count,
                phantom: PhantomData,
            }),
        }
    }
}

/// A mutable location in a map associated with a given key.
///
/// Analogous to [`hash_map::Entry`].
pub enum Entry<'a, K, V, P> {
    /// A location with no value.
    Vacant(VacantEntry<'a, K, V, P>),
    /// A location that hsa a value.
    Occupied(OccupiedEntry<'a, K, V, P>),
}

/// A vacant location in a map associated with a given key.
///
/// Analogous to [`hash_map::VacantEntry`].
pub struct VacantEntry<'a, K, V, P> {
    /// The underlying hashmap entry.
    base: hash_map::VacantEntry<'a, K, V>,
    /// A mutable reference to the map's count field.
    count_ref: &'a mut usize,
    /// Marker to declare that `P` is used.
    phantom: PhantomData<fn(P) -> P>,
}

/// An occupied location in a map associated with a given key.
///
/// Analogous to [`hash_map::OccupiedEntry`].
pub struct OccupiedEntry<'a, K, V, P> {
    /// The underlying hashmap entry.
    base: hash_map::OccupiedEntry<'a, K, V>,
    /// If true, P::check is true for the current value of this entry.
    contributed_to_count: bool,
    /// A mutable reference to the map's count field.
    count_ref: &'a mut usize,
    /// Marker to declare that `P` is used.
    phantom: PhantomData<fn(P) -> P>,
}

impl<'a, K, V, P> OccupiedEntry<'a, K, V, P>
where
    P: Predicate<Item = V>,
{
    /// Remove this entry from the map and return it as a (key,value) pair.
    pub fn remove_entry(self) -> (K, V) {
        if self.contributed_to_count {
            *self.count_ref -= 1;
        }
        self.base.remove_entry()
    }

    /// Return a reference to the current value of this entry.
    pub fn get(&self) -> &V {
        self.base.get()
    }

    /// Replace the current value of this entry with `value`.
    ///
    /// Return the old value of this entry.
    pub fn insert(&mut self, value: V) -> V {
        if self.contributed_to_count {
            *self.count_ref -= 1;
        }
        self.contributed_to_count = P::check(&value);
        if self.contributed_to_count {
            *self.count_ref += 1;
        }
        self.base.insert(value)
    }
}

impl<'a, K, V, P> VacantEntry<'a, K, V, P>
where
    P: Predicate<Item = V>,
{
    /// Fill this vacant entry with a new value.
    ///
    /// Return a mutable reference to the value inserted.
    pub fn insert(self, value: V) -> MutRef<'a, V, P> {
        let contributed_to_count = P::check(&value);
        if contributed_to_count {
            *self.count_ref += 1;
        }
        MutRef {
            base: self.base.insert(value),
            contributed_to_count,
            count_ref: self.count_ref,
            phantom: PhantomData,
        }
    }
}

/// Smart pointer implementing a mutable reference to a value in a [`CountedHashMap`].
///
/// # Panic safety
///
/// This type does NOT preserve the map invariant if its `drop` method is not called;
/// if the caller holds this reference while a panic occurs,
/// the count may become incorrect.
///
/// TODO: we could use some kind of poisoning trickery to regain this property.
pub struct MutRef<'a, V, P>
where
    P: Predicate<Item = V>,
{
    /// The underlying value.
    base: &'a mut V,
    /// If true, P::check is true for the current value of this entry.
    contributed_to_count: bool,
    /// A mutable reference to the map's count field.
    count_ref: &'a mut usize,
    /// Marker to declare that `P` is used.
    phantom: PhantomData<fn(P) -> P>,
}

impl<'a, V, P> Deref for MutRef<'a, V, P>
where
    P: Predicate<Item = V>,
{
    type Target = V;

    fn deref(&self) -> &Self::Target {
        self.base
    }
}

impl<'a, V, P> DerefMut for MutRef<'a, V, P>
where
    P: Predicate<Item = V>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.base
    }
}

impl<'a, V, P> Drop for MutRef<'a, V, P>
where
    P: Predicate<Item = V>,
{
    fn drop(&mut self) {
        match (self.contributed_to_count, P::check(self.base)) {
            (true, true) | (false, false) => {}
            (true, false) => *self.count_ref -= 1,
            (false, true) => *self.count_ref += 1,
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::collections::HashSet;

    use super::*;

    struct IsEven;
    impl Predicate for IsEven {
        type Item = u32;

        fn check(item: &Self::Item) -> bool {
            *item & 1 == 0
        }
    }

    #[test]
    fn basics() {
        let mut m = CountedHashMap::<u32, u32, IsEven>::new();
        assert_eq!(m.count(), 0);
        assert!(m.is_empty());

        m.insert(1, 1);
        m.insert(10, 10);
        m.insert(20, 20);
        m.insert(21, 21);
        assert_eq!(m.count(), 2);
        assert_eq!(m.len(), 4);
        assert!(!m.is_empty());

        // Does get work?
        assert_eq!(m.get(&3), None);
        assert_eq!(m.get(&1), Some(&1));
        assert_eq!(m.get(&20), Some(&20));

        // Does iter act as expected?
        assert_eq!(
            m.iter().collect::<HashSet<_>>(),
            m.map.iter().collect::<HashSet<_>>()
        );

        // Try replacing.
        assert_eq!(m.insert(20, 40), Some(20)); // true => true
        assert_eq!(m.count(), 2);
        assert_eq!(m.insert(21, 41), Some(21)); // false => false
        assert_eq!(m.count(), 2);
        assert_eq!(m.insert(20, 99), Some(40)); // true => false
        assert_eq!(m.count(), 1);
        assert_eq!(m.insert(21, 100), Some(41)); // false => true
        assert_eq!(m.count(), 2);
        assert_eq!(m.len(), 4);

        // Try removing.
        assert_eq!(m.remove(&10), Some(10)); // remove true
        assert_eq!(m.count(), 1);
        assert_eq!(m.remove(&1), Some(1)); // remove false
        assert_eq!(m.count(), 1);
        assert_eq!(m.remove(&1), None); // remove absent
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn get_mut() {
        let mut m = CountedHashMap::<&'static str, u32, IsEven>::new();
        m.insert("first", 1);
        m.insert("second", 2);
        assert_eq!(m.count(), 1);
        assert_eq!(m.len(), 2);

        *m.get_mut("first").unwrap() = 7; // false => false
        assert_eq!(m.count(), 1);

        *m.get_mut("first").unwrap() = 8; // false => true
        assert_eq!(m.count(), 2);

        *m.get_mut("second").unwrap() = 8; // true => true
        assert_eq!(m.count(), 2);

        *m.get_mut("second").unwrap() = 1; // true => false
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn entry() {
        let mut m = CountedHashMap::<&'static str, u32, IsEven>::new();
        m.insert("first", 1);
        m.insert("second", 2);
        assert_eq!(m.count(), 1);
        assert_eq!(m.len(), 2);

        // -----
        // First, try insert on an occupied entry.
        let Entry::Occupied(mut e) = m.entry("first") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.get(), &1);
        assert_eq!(e.insert(7), 1); // false => false
        assert_eq!(m.count(), 1);

        let Entry::Occupied(mut e) = m.entry("first") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.get(), &7);
        assert_eq!(e.insert(8), 7); // false => true
        assert_eq!(m.count(), 2);

        let Entry::Occupied(mut e) = m.entry("first") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.get(), &8);
        assert_eq!(e.insert(100), 8); // true => true
        assert_eq!(m.count(), 2);

        let Entry::Occupied(mut e) = m.entry("first") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.get(), &100);
        assert_eq!(e.insert(3), 100); // true => false
        assert_eq!(m.count(), 1);

        // TODO: test calling e.insert() on the same e several times.

        assert_eq!(m.get("first"), Some(&3));
        assert_eq!(m.get("second"), Some(&2));

        // -----
        // Now try insert on an unoccupied entry.
        let Entry::Vacant(e) = m.entry("third") else {
            panic!("Expected a vacant entry");
        };
        e.insert(7); // None => false
        assert_eq!(m.count(), 1);

        let Entry::Vacant(e) = m.entry("fourth") else {
            panic!("Expected a vacant entry");
        };
        e.insert(42); // None => true
        assert_eq!(m.count(), 2);

        // TODO: Check MutRef returned by insert().

        // ----
        // Now try removing an occupied entry.
        let Entry::Occupied(e) = m.entry("third") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.remove_entry(), ("third", 7)); // Remove false.
        assert_eq!(m.count(), 2);

        let Entry::Occupied(e) = m.entry("first") else {
            panic!("Expected an occupied entry.");
        };
        assert_eq!(e.remove_entry(), ("first", 3)); // Remove true.
        assert_eq!(m.count(), 2);
    }
}
