#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod key_data;

pub use slotmap::{
    new_key_type, secondary, DefaultKey, Key, KeyData, SecondaryMap, SparseSecondaryMap,
};

use key_data::key_version_serde as key_version;

//use key_version::key_version_serde;

/// A single entry in one of our careful slotmaps.
///
/// An entry can either be `Present` (in which case we treat it normally),
/// or `Unusable`, in which case we
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
enum Entry<V> {
    /// The entry is available.
    Present(V),
    /// The entry can no longer be used, removed, or set to anything else.
    ///
    /// It must not be removed from the slot map, since doing so would
    /// increase its slot's version number too high.
    Unusable,
}

impl<V> Entry<V> {
    /// Remove the value of `self` (if any), and make it unusable.
    fn take_and_mark_unusable(&mut self) -> Option<V> {
        match std::mem::replace(self, Entry::Unusable) {
            Entry::Present(v) => Some(v),
            Entry::Unusable => None,
        }
    }
    /// Return a reference to the value of `self`, if there is one.
    fn value(&self) -> Option<&V> {
        match self {
            Entry::Present(val) => Some(val),
            Entry::Unusable => None,
        }
    }
    /// Return a mutable reference to the value of `self``, if there is one.
    fn value_mut(&mut self) -> Option<&mut V> {
        match self {
            Entry::Present(val) => Some(val),
            Entry::Unusable => None,
        }
    }
    /// Consume this entry (which must be `Present`), and return its value.
    ///
    /// # Panics
    ///
    /// Panics if this entry is `Unusable`.
    fn unwrap(self) -> V {
        match self {
            Entry::Present(val) => val,
            Entry::Unusable => panic!("Tried to unwrap an unusable slot."),
        }
    }
}

/// Helper: Define a wrapper for a single SlotMap type.
///
/// This works for SlotMap, DenseSlotMap, and HopSlotMap.
///
/// (The alternative to using a macro here would be to define a new trait
/// implemented by all of the SlotMaps, and then to define our own SlotMap as a wrapper around an
/// instance of that trait.)
macro_rules! define_implementation {
        { $mapname:ident } => {paste::paste!{

        /// A variation of
        #[doc = concat!("[`slotmap::", stringify!($mapname), "`]")]
        /// that can never give the same key for multiple objects.
        ///
        /// Unlike a regular version of
        #[doc = concat!("`", stringify!($mapname), "`,")]
        /// this version will not allow a slot's version counter to roll over to
        /// 0 if it reaches 2^31.  Instead, it will mark the slot as unusable for future values.
        ///
        /// # Limitations
        ///
        /// The possibility of marking a slot as unusable
        /// makes it possible, given enough removals and re-insertions,
        /// for a slotmap to use an unbounded amount of memory, even if it is not storing much actual data.
        /// (From a DOS point of view: Given the ability to re-insert an entry ~2^31 times, an attacker can
        /// cause a slot-map to render approximately `4+sizeof(V)` bytes unusable.)
        ///
        /// This type does not include implementations for:
        ///   * `get_unchecked_mut()`
        ///   * `get_disjoint_unchecked_mut()`
        ///   * `IntoIterator`.
        ///   * `serde::{Serialize, Deserialize}`.
        ///
        /// # Risky business!
        ///
        /// This code relies upon stability of some undocumented properties of `slotmap` keys.
        /// In particular, it assumes:
        ///  * that the slotmap KeyData `serde` format is stable,
        ///  * that slot versions are represented as `u32`.
        ///  * that the least significant bit of a slot version is 1 if the slot is full,
        ///    and 0 if the slot is empty.
        ///  * that slot versions start at 0, and increase monotonically as the slot is
        ///    emptied and reused.
        ///
        /// Note that these assumptions are _probably_ okay: if `slotmap` were to change them,
        /// it would thereby create a breaking change in its serde version.
        //
        // Invariants:
        //
        // For every `(key,value)` that is present in `base`:
        //   - `key_okay(key)` is true.
        //   - if `value` is `Entry::Unusable`, then `key_version(key) == SATURATE_AT_VERSION`.
        //
        // `n_unusable` is the number of entries in `base` whose value is `Entry::Unusable`.
        //
        // To maintain these invariants:
        //   - Never remove a key with `key_version(key) == SATURATE_AT_VERSION`
        //   - Whenever setting a value to `Unusable`, increment `n_unusable`.
        #[derive(Clone, Debug)]
        pub struct $mapname<K: Key, V> {
            /// An underlying SlotMap, obeying the invariants above.
            base: slotmap::$mapname<K, Entry<V>>,
            /// The number of entries in this SlotMap that are filled with [`Entry::Unusable`] values.
            n_unusable: usize,
            /// A ZST, used to guarantee that we have spot-checked the behavior of the underlying
            /// SlotMap implementation.
            _valid: [<$mapname ValidationToken>],
        }

        impl<V> $mapname<DefaultKey, V> {
            /// Construct a new empty map, using a default key type.
            ///
            /// See
            #[doc = concat!("[`slotmap::", stringify!($mapname), "::new()`].")]
            pub fn new() -> Self {
                Self::with_key()
            }

            /// Construct a new empty map with a specified capacity, using a default key type.
            ///
            /// See
            #[doc = concat!("[`slotmap::", stringify!($mapname), "::with_capacity()`].")]
            /// ::with_capacity()`].
            pub fn with_capacity(capacity: usize) -> Self {
                Self::with_capacity_and_key(capacity)
            }
        }

        impl<K: Key, V> Default for $mapname<K, V> {
            fn default() -> Self {
                Self::with_key()
            }
        }

        impl<K: Key, V> $mapname<K, V> {
            /// Construct a new empty map, using a specialized key type.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::with_key()`].")]
            pub fn with_key() -> Self {
                Self::with_capacity_and_key(0)
            }

            /// Construct a new empty map with a specified capacity, using a specialized key type.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::with_capacity_and_key()`].")]
            pub fn with_capacity_and_key(capacity: usize) -> Self {
                Self {
                    base: slotmap::$mapname::with_capacity_and_key(capacity),
                    n_unusable: 0,
                    _valid: [<validate_ $mapname:snake _behavior>](),
                }
            }

            /// Return the number of items in this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::len()`].")]
            pub fn len(&self) -> usize {
                self.base
                    .len()
                    .checked_sub(self.n_unusable)
                    .expect("logic error")
            }

            /// Return true if this map has no items.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::is_empty()`].")]
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            /// Return the total number of slots available for entries in this map.
            ///
            /// This number includes used slots, as well as empty slots that may become used.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::capacity()`],")]
            /// but note that a `slotmap-careful` implementation may _lose_ capacity over time,
            /// as slots are marked unusable.
            pub fn capacity(&self) -> usize {
                self.base
                    .capacity()
                    .checked_sub(self.n_unusable)
                    .expect("logic error")
            }

            /// Reserve space as needed.
            ///
            /// Allocates if needed, so that this map can hold `additional` new entries
            /// without having to resize.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::reserve()`].")]
            pub fn reserve(&mut self, additional: usize) {
                // Note that we don't need to check n_unusable here: the underlying
                // map type thinks that unusable entries are full, and so will allocate
                // correctly.
                self.base.reserve(additional);
            }

            /// Return true if the map contains an entry with a given key.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::contains_key()`].")]
            pub fn contains_key(&self, key: K) -> bool {
                // Calling self.get, not self.base.get, so it will be None if the
                // slot is unusable.
                self.get(key).is_some()
            }

            /// Insert a new value into the map, and return the key used for it.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::insert()`].")]
            pub fn insert(&mut self, value: V) -> K {
                let key = self.base.insert(Entry::Present(value));
                debug_assert!(key_okay(key));
                key
            }

            /// Insert a new value into the map, constructing it using its own new key.
            ///
            /// This method is useful for the case where a value needs to refer to the
            /// key that will be assigned to it.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::insert_with_key()`].")]
            pub fn insert_with_key<F>(&mut self, f: F) -> K
            where
                F: FnOnce(K) -> V,
            {
                let key = self.base.insert_with_key(|k| Entry::Present(f(k)));
                debug_assert!(key_okay(key));
                key
            }

            /// As [`Self::insert_with_key`], but may return an `Err`.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::try_insert_with_key()`].")]
            pub fn try_insert_with_key<F, E>(&mut self, f: F) -> Result<K, E>
            where
                F: FnOnce(K) -> Result<V, E>,
            {
                let key = self
                    .base
                    .try_insert_with_key(|k| Ok(Entry::Present(f(k)?)))?;
                debug_assert!(key_okay(key));
                Ok(key)
            }

            /// Remove and return the element of this map with a given key.
            ///
            /// Return None if the key is not present in the map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::remove()`].")]
            pub fn remove(&mut self, key: K) -> Option<V> {
                if key_version_is_maximal(key) {
                    // The key is as large as it is allowed to get,
                    // so we should not actually remove this Entry.
                    match self.base.get_mut(key) {
                        Some(slot) => {
                            // The entry is Present: extract its value and mark it unusable.
                            let rv = slot.take_and_mark_unusable();
                            if rv.is_some() {
                                self.n_unusable += 1;
                            }
                            rv
                        }
                        // The entry is Unusable; treat it as if it weren't there.
                        None => None,
                    }
                } else {
                    // The Entry::unwrap function will panic if its argument is
                    // Entry::Unusable.  But that is impossible in this case,
                    // since we already checked key_version_is_maximal() for this key,
                    // and our invariant guarantees that, if the value is Entry::Unusable,
                    // then key_version(key) == SATURATE_AT_VERSION,
                    // so key_version_is_maximal is true.
                    self.base.remove(key).map(Entry::unwrap)
                }
            }

            /// Remove every element of this map that does not satisfy a given predicate.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::retain()`].")]
            pub fn retain<F>(&mut self, mut f: F)
            where
                F: FnMut(K, &mut V) -> bool,
            {
                self.base.retain(|k, v| {
                    let Entry::Present(v_inner) = v else {
                        return true;
                    };

                    if f(k, v_inner) {
                        true
                    } else if key_version_is_maximal(k) {
                        self.n_unusable += 1;
                        *v = Entry::Unusable;
                        true
                    } else {
                        false
                    }
                });
            }

            /// Remove every element of this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::clear()`].")]
            pub fn clear(&mut self) {
                self.retain(|_, _| false);
            }

            /// Return a reference to the element of this map with a given key.
            ///
            /// Return None if there is no such element.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::get()`].")]
            pub fn get(&self, key: K) -> Option<&V> {
                self.base.get(key).and_then(Entry::value)
            }
            /// Return a mutable reference to the element of this map with a given key.
            ///
            /// Return None if there is no such element.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::get_mut()`].")]
            pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
                self.base.get_mut(key).and_then(|ent| ent.value_mut())
            }

            /// Return an array of mutable references to the elements of this map with a given list
            /// of keys.
            ///
            /// Return None if any key is not present, or if the same key is given twice.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::get_disjoint_mut()`].")]
            pub fn get_disjoint_mut<const N: usize>(&mut self, keys: [K; N]) -> Option<[&mut V; N]> {
                let vals = self.base.get_disjoint_mut(keys)?;
                // TODO array::try_map would be preferable, but it isn't stable.
                if vals.iter().all(|e| matches!(e, Entry::Present(_))) {
                    // Cannot panic, since we checked that every entry is present.
                    Some(vals.map(|v| match v {
                        Entry::Present(v) => v,
                        Entry::Unusable => panic!("Logic error"),
                    }))
                } else {
                    None
                }
            }

            /// Return an iterator over the elements of this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::iter()`].")]
            ///
            /// # Current limitations
            ///
            /// Does not return a named type.
            pub fn iter(&self) -> impl Iterator<Item = (K, &V)> + '_ {
                self.base.iter().filter_map(|(k, v)| match v {
                    Entry::Present(v) => Some((k, v)),
                    Entry::Unusable => None,
                })
            }

            /// Remove every element of this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::drain()`].")]
            pub fn drain(&mut self) -> impl Iterator<Item = (K, V)> + '_ {
                self.base.drain().filter_map(|(k, v)| match v {
                    Entry::Present(v) => Some((k, v)),
                    Entry::Unusable => None,
                })
            }

            /// Return a mutable iterator over the elements of this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::iter_mut()`].")]
            ///
            /// # Current limitations
            ///
            /// Does not return a named type.
            pub fn iter_mut(&mut self) -> impl Iterator<Item = (K, &mut V)> + '_ {
                self.base.iter_mut().filter_map(|(k, v)| match v {
                    Entry::Present(v) => Some((k, v)),
                    Entry::Unusable => None,
                })
            }

            /// Return an iterator over all the keys in this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::keys()`].")]
            ///
            /// # Current limitations
            ///
            /// Does not return a named type.
            pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
                self.iter().map(|(k, _)| k)
            }

            /// Return an iterator over the values in this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::values()`].")]
            ///
            /// # Current limitations
            ///
            /// Does not return a named type.
            pub fn values(&self) -> impl Iterator<Item = &V> + '_ {
                self.base.values().filter_map(Entry::value)
            }

            /// Return a mutable iterator over the values in this map.
            ///
            /// See
            #[doc= concat!("[`slotmap::", stringify!($mapname), "::values_mut()`].")]
            ///
            /// # Current limitations
            ///
            /// Does not return a named type.
            pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> + '_ {
                self.base.values_mut().filter_map(Entry::value_mut)
            }

            /// Testing helper: Assert that every invariant holds for this map.
            ///
            /// # Panics
            ///
            /// Panics if any invariant does not hold.
            #[cfg(test)]
            fn assert_rep_ok(&self) {
                let mut n_unusable_found = 0;
                for (k, v) in self.base.iter() {
                    assert!(key_okay(k), "Key {:?} was invalid", k.data());
                    if matches!(v, Entry::Unusable) {
                        n_unusable_found += 1;
                        assert_eq!(key_version(k), SATURATE_AT_VERSION);
                    }
                }
                assert_eq!(n_unusable_found, self.n_unusable);
            }
        }

        /// Helper: a token constructed if the slotmap behavior matches our expectations.
        ///
        /// See `validate_*_behavior()`
        #[derive(Clone, Debug)]
        struct [<$mapname ValidationToken>];

        /// Spot-check whether `SlotMap` has changed its key encoding behavior; panic if so.
        ///
        /// (Our implementation relies on our ability to check whether a version number is about to
        /// overflow. But the only efficient way to access a version number is via `KeyData::as_ffi`,
        /// which does not guarantee anything about the actual encoding of the versions.)
        ///
        /// This function returns a ZST ValidationToken; nothing else must return one.
        /// Being able to construct a ValidationToken implies
        /// that `slotmap` has probably not changed its behavior in a way that will break us.
        ///
        /// # Panics
        ///
        /// May panic if slotmap does not encode its keys in the expected manner.
        fn [<validate_ $mapname:snake _behavior>]() -> [<$mapname ValidationToken>] {
            use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
            /// Helper:
            static VALIDATED: AtomicBool = AtomicBool::new(false);
            if VALIDATED.load(Relaxed) {
                // We have already validated it at least once.
                return [<$mapname ValidationToken>];
            }
            /// Helper: assert that key has bit 32 set.
            fn ver_lsb_check<K: Key>(key: K) {
                let (ver, _) = key_data::key_data_parts(key.data()).expect("slotmap has changed its serde representation");
                assert_eq!(ver & 1, 1,
                    "Key version LSB not set as expected"
                );
            }

            let mut map = slotmap::$mapname::new();
            let k1 = map.insert("a");
            assert_eq!(key_version(k1), 0, "Keys do not begin with version 0.");
            assert_eq!(key_slot(k1), 1, "Keys do not begin with index 1.");
            ver_lsb_check(k1);

            // This is a basic correctness check.
            map.remove(k1).expect("insert+remove failed");
            let k2 = map.insert("b");
            assert_eq!(key_slot(k1), key_slot(k2), "Slot not re-used as expected.");
            assert_eq!(
                key_version(k1) + 1,
                key_version(k2),
                "Key version did not increment by 1 after slot reuse"
            );
            ver_lsb_check(k2);

            let k3 = map.insert("c");
            assert_eq!(
                key_version(k3),
                0,
                "A different slot did not begin with version 0.",
            );
            assert_eq!(
                key_slot(k3),
                key_slot(k1) + 1,
                "Slots not allocated in expected order."
            );
            ver_lsb_check(k3);

            // Remember that we've validated SlotMap.
            VALIDATED.store(true, Relaxed);
            [<$mapname ValidationToken>]
        }
    }

    impl<K:Key, V> std::ops::Index<K> for $mapname<K,V> {
        type Output = V;
        fn index(&self, key: K) -> &V {
            self.get(key).expect("key invalid")
        }
    }
    impl<K:Key, V> std::ops::IndexMut<K> for $mapname<K,V> {
        fn index_mut(&mut self, key: K) -> &mut V {
            self.get_mut(key).expect("key invalid")
        }
    }
}} // END OF MACRO.

define_implementation! { SlotMap }

define_implementation! { DenseSlotMap }

define_implementation! { HopSlotMap }

/// Return true if this key is apparently valid.
///
/// We should use debug_assert! to test this on every new key, every time an entry is inserted.
///
/// If inserting an entry results in a _not_ valid key,
/// we have messed up, and allowed a version counter to grow too high.
fn key_okay<K: Key>(key: K) -> bool {
    key_version(key) <= SATURATE_AT_VERSION
}

/// Return true if the version number for this key should not be allowed to grow any larger.
///
/// We should call this whenever we are about to remove an entry with a given key.
/// If it returns true, we should instead replace the entry with [`Entry::Unusable`]
fn key_version_is_maximal<K: Key>(key: K) -> bool {
    key_version(key) == SATURATE_AT_VERSION
}
/// The maximal version that we allow a key to reach.
///
/// When it reaches this version, we do not remove the entry with the key any longer;
/// instead, when we would remove the entry, we instead set its value to [`Entry::Unusable`]
///
/// This value is deliberately chosen to be less than the largest possible value (`0x7fff_ffff`),
/// so that we can detect any bugs that would risk overflowing the version.
const SATURATE_AT_VERSION: u32 = 0x7fff_fffe;

/// Helper: return the slot of a key, assuming that the representation is as we expect.
///
/// Used for testing and verify functions.
fn key_slot<K: Key>(key: K) -> u32 {
    let (_, idx) =
        key_data::key_data_parts(key.data()).expect("slotmap has changed its serde representation");
    idx
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

    /// Create a new key, using `ver` as its version field (includes trailing 1)
    /// and `idx` as its index field.
    fn construct_key(ver: u32, idx: u32) -> slotmap::DefaultKey {
        let j = serde_json::json! {
            {
                "version": ver,
                "idx": idx,
            }
        };
        serde_json::from_value(j).expect("invalid representation")
    }

    /// Define a set of tests for one of the map variants, in a module named after that variant.
    macro_rules! tests_for {
            { $mapname:ident } => {paste::paste!{

            mod [<$mapname:snake>] {

                use slotmap::DefaultKey;
                use crate::*;

            #[test]
            fn validate() {
                let _tok = [<validate_ $mapname:snake _behavior>]();
            }

            #[test]
            fn empty() {
                let mut m: $mapname<DefaultKey, ()> = $mapname::default();

                for _ in 1..=3 {
                    assert_eq!(m.len(), 0);
                    assert!(m.is_empty());
                    m.assert_rep_ok();

                    let k1 = m.insert(());
                    let k2 = m.insert(());
                    let k3 = m.insert(());
                    m.remove(k1);
                    m.remove(k2);
                    m.remove(k3);
                }
            }

            fn construct_near_saturated_slotmap() -> ($mapname<DefaultKey, String>, DefaultKey, DefaultKey) {
                fn encode_ver(v: u32) -> u32 {
                    (v << 1) | 1
                }

                let json = serde_json::json! {
                    [
                        // sentinel entry.
                        { "value": null, "version": 0},
                        { "value": {"Present": "hello"}, "version": encode_ver(SATURATE_AT_VERSION) },
                        { "value": {"Present": "world"}, "version": encode_ver(SATURATE_AT_VERSION - 2) }
                    ]
                };

                let m = $mapname {
                    base: serde_json::from_value(json).expect("invalid json"),
                    n_unusable: 0,
                    _valid: [<validate_ $mapname:snake _behavior>](),
                };
                let mut k1 = None;
                let mut k2 = None;

                for (k, v) in m.iter() {
                    if v == "hello" {
                        k1 = Some(k);
                    }
                    if v == "world" {
                        k2 = Some(k);
                    }
                }
                let (k1, k2) = (k1.unwrap(), k2.unwrap());
                (m, k1, k2)
            }

            #[test]
            #[allow(clippy::cognitive_complexity)]
            fn saturating() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                assert_eq!(key_version(k1), SATURATE_AT_VERSION);
                assert_eq!(key_version(k2), SATURATE_AT_VERSION - 2);

                // Replace k1, and make sure that the index is _not_ reused.
                let v = m.remove(k1);
                assert_eq!(v.unwrap(), "hello");
                assert!(matches!(m.base.get(k1), Some(Entry::Unusable)));
                let k1_new = m.insert("HELLO".into());
                assert_ne!(key_slot(k1), key_slot(k1_new));
                assert_eq!(key_version(k1_new), 0);
                assert!(matches!(m.base.get(k1), Some(Entry::Unusable)));
                assert_eq!(m.get(k1_new).unwrap(), "HELLO");
                assert!(m.get(k1).is_none());
                m.assert_rep_ok();

                // Replace k2 and make sure that that the index gets reused twice.
                let v = m.remove(k2);
                assert_eq!(v.unwrap(), "world");
                let k2_2 = m.insert("WoRlD".into());
                assert_eq!(key_version(k2_2), SATURATE_AT_VERSION - 1);
                m.remove(k2_2);
                m.assert_rep_ok();
                assert!(m.base.get(k2_2).is_none());
                let k2_3 = m.insert("WORLD".into());
                assert_eq!(key_slot(k2), key_slot(k2_2));
                assert_eq!(key_slot(k2), key_slot(k2_3));
                assert_eq!(key_version(k2_3), SATURATE_AT_VERSION);
                m.remove(k2_3);
                assert!(m.base.get(k2_2).is_none());
                m.assert_rep_ok();

                let k2_4 = m.insert("World!".into());
                assert!(matches!(m.base.get(k2_3), Some(Entry::Unusable)));
                assert_eq!(m.get(k2_4).unwrap(), "World!");
                assert_ne!(key_slot(k2_4), key_slot(k2));
                assert!(m.contains_key(k2_4));
                assert!(!m.contains_key(k2_3));
                m.assert_rep_ok();
            }

            #[test]
            fn insert_variations() {
                let mut m = $mapname::new();
                let k1 = m.insert("hello".to_string());
                let k2 = m.insert_with_key(|k| format!("{:?}", k));
                let k3 = m
                    .try_insert_with_key(|k| Result::<_, ()>::Ok(format!("{:?}", k)))
                    .unwrap();
                let () = m.try_insert_with_key(|_k| Err(())).unwrap_err();

                assert!(m.contains_key(k1));
                assert!(m.contains_key(k2));
                assert!(m.contains_key(k3));
                assert_eq!(m.len(), 3);
            }

            #[test]
            fn remove_large_but_bogus() {
                let mut m: $mapname<DefaultKey, String> = $mapname::with_capacity(0);
                let _k1 = m.insert("hello".to_string());
                // Construct a key with maximal version (so we would expect to freeze it),
                // but which won't actually be present.
                let k_fake = super::construct_key((SATURATE_AT_VERSION << 1) | 1, 1);

                let v = m.remove(k_fake);
                assert!(v.is_none());
                m.assert_rep_ok();
            }

            #[test]
            fn remove_many_times() {
                let (mut m, k1, _k2) = construct_near_saturated_slotmap();

                let mut n_removed = 0;
                for _ in 0..10 {
                    if m.remove(k1).is_some() {
                        n_removed += 1;
                    }
                    m.assert_rep_ok();
                    assert_eq!(m.n_unusable, 1);
                    assert_eq!(m.len(), 1);
                }
                assert_eq!(n_removed, 1);
            }

            #[test]
            fn clear() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();
                assert_eq!(m.len(), 2);
                assert_eq!(m.is_empty(), false);
                assert_eq!(m.n_unusable, 0);

                for _ in 0..=2 {
                    m.clear();
                    m.assert_rep_ok();

                    assert_eq!(m.len(), 0);
                    assert_eq!(m.is_empty(), true);
                    assert!(m.get(k1).is_none());
                    assert!(m.get(k2).is_none());
                    assert!(matches!(m.base.get(k1), Some(Entry::Unusable)));
                    assert_eq!(m.n_unusable, 1);
                }

                let k_next = m.insert("probe".into());
                assert_eq!(key_slot(k_next), key_slot(k2));
                assert_eq!(key_version(k_next), SATURATE_AT_VERSION - 1);
            }

            #[test]
            fn retain() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                // drop all but the nearly-saturated (but not saturated) "world" item.
                m.retain(|_k, v| v == "world");
                m.assert_rep_ok();
                assert_eq!(m.len(), 1);
                assert!(!m.is_empty());
                assert_eq!(m.n_unusable, 1);
                assert_eq!(m.contains_key(k1), false);
                assert_eq!(m.contains_key(k2), true);
                assert_eq!(m.base.contains_key(k1), true); // key still internally present as Unusable.

                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                // drop all but the saturated (but not saturated) "hello" item.
                m.retain(|_k, v| v == "hello");
                m.assert_rep_ok();
                assert_eq!(m.len(), 1);
                assert!(!m.is_empty());
                assert_eq!(m.n_unusable, 0);
                assert_eq!(m.contains_key(k1), true);
                assert_eq!(m.contains_key(k2), false);
                assert_eq!(m.base.contains_key(k2), false); // key not present.
            }

            #[test]
            fn retain_and_panic() {
                use std::panic::AssertUnwindSafe;
                let (mut m, k1, _k2) = construct_near_saturated_slotmap();

                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    m.retain(|k,_| if k == k1 { false } else { panic!() })
                })).unwrap_err();
                m.assert_rep_ok();
            }

            #[test]
            fn modify() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                *m.get_mut(k1).unwrap() = "HELLO".to_string();
                *m.get_mut(k2).unwrap() = "WORLD".to_string();

                let v: Vec<_> = m.values().collect();
                assert_eq!(v, vec![&"HELLO".to_string(), &"WORLD".to_string()]);
            }

            #[test]
            fn iterators() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                m.remove(k1);
                assert_eq!(m.n_unusable, 1);

                for v in m.values_mut() {
                    *v = "WORLD".to_string();
                }

                let v: Vec<_> = m.values().collect();
                assert_eq!(v, vec![&"WORLD".to_string()]);

                let v: Vec<_> = m.iter().collect();
                assert_eq!(v, vec![(k2, &"WORLD".to_string())]);

                for (k, v) in m.iter_mut() {
                    assert_eq!(k, k2);
                    *v = "World".to_string();
                }

                let v: Vec<_> = m.iter().collect();
                assert_eq!(v, vec![(k2, &"World".to_string())]);

                let v: Vec<_> = m.keys().collect();
                assert_eq!(v, vec![k2]);

                m.assert_rep_ok();
            }

            #[test]
            fn get_mut_multiple() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                assert!(m.get_disjoint_mut([k1,k1]).is_none());

                if let Some([v1, v2]) = m.get_disjoint_mut([k1, k2]) {
                    assert_eq!(v1, "hello");
                    assert_eq!(v2, "world");
                    *v1 = "HELLO".into();
                    *v2 = "WORLD".into();
                } else {
                    panic!("get_disjoint_mut failed.");
                };

                m.remove(k1);
                assert_eq!(m.contains_key(k1), false);
                assert_eq!(m.base.contains_key(k1), true);
                m.assert_rep_ok();

                if let Some([_v1, _v2]) = m.get_disjoint_mut([k1, k2]) {
                    panic!("get_disjoint_mut succeeded unexpectedly.")
                }
            }

            #[test]
            fn get_capacity() {
                let (mut m, k1, _) = construct_near_saturated_slotmap();

                let cap_orig = dbg!(m.capacity());
                m.remove(k1);
                m.assert_rep_ok();

                assert_eq!(m.n_unusable, 1);
                assert_eq!(m.capacity(), cap_orig - 1); // capacity decreased, since there is an unusable slot.

                m.reserve(5);
                assert!(m.capacity() >= 5);
            }

            #[test]
            fn index() {
                let (mut m, k1, k2) = construct_near_saturated_slotmap();

                assert_eq!(m[k1], "hello");
                assert_eq!(*(&mut m[k2]), "world");
            }
        } // end module.
        }}} // End macro rules

    tests_for! {SlotMap}
    tests_for! {DenseSlotMap}
    tests_for! {HopSlotMap}
}
