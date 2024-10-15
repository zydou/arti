//! Data structure `MultikeyIsolatedMap` indexed by multiple keys and an isolation

use std::collections::HashMap;
use std::hash::Hash;

use derive_more::{Deref, DerefMut};
use educe::Educe;

use slotmap_careful::{DenseSlotMap, Key};

use tor_circmgr::isolation::Isolation;

/// Data structure indexed by multiple keys and an isolation
///
/// This is a map keyed by:
///  * `K1`, a hashable key type
///  * `K2`, a possibly-non-hashable key type,
///  * [`Box<dyn Isolation>`](Isolation), a circuit/client isolation
///
/// Lookup/inserts will look for a suitable entry with a compatible isolation
/// and, if found, narrow that entry's isolation.
///
/// A lookup/insert yields a **table index** `I`,
/// which can later be used to do an O(1) lookup of the same entry.
/// (This is particularly useful given that an isolation cannot be simply compared;
/// a proper lookup might narrow the isolation of an existing record.)
///
/// `I` must implement `slotmap:Key`.
///
/// The values are `V`.
///
/// Internally, it looks like this:
///
/// ```text
///           index                                         table
///           HashMap           Vec_______________          SlotMap_____________________
///           |     | contains  | table_index    |  t._i.   | K2, isol, V  /  <vacant> |
///     K1 -> |  ---+---------> | table_index    | -------> | K2, isol, V  /  <vacant> |
///           |_____|           | table_index    | 1      1 | K2, isol, V  /  <vacant> |
///                             | table_index    |          | K2, isol, V  /  <vacant> |
///   K2, isol ---------------> | .............. |          | K2, isol, V  /  <vacant> |
///             linear search   |________________|          | ...             ....     |
/// ```                                                     |__________________________|
#[derive(Debug, Educe)]
#[educe(Default)]
pub(crate) struct MultikeyIsolatedMap<I, K1, K2, V>
where
    I: Key,
    K1: Hash + Eq,
    K2: Eq,
{
    /// The first stage index, mapping `K1` to `I`
    index: HashMap<K1, Vec<I>>,

    /// Actual table containing the entries, including `K2` and the isolation, and `V`
    ///
    /// ### Invariant
    ///
    /// Entries in `table` and `index` correspond precisely, one-to-one:
    /// each `Vec` element in `index` refers to an (occupied) entry in `table`, and
    /// each (occupied) entry in `table` is referenced precisely once from `index`.
    table: DenseSlotMap<I, Record<K2, V>>,
}

/// Record within a `MultikeyIsolatedMap`
///
/// This contains `K2`, the isolation, and the value.
/// It derefs to the value, which you may mutate.
///
/// (You can't mutate the key parts; that would be wrong.)
#[derive(Debug, Deref, DerefMut)]
pub(crate) struct Record<K2, V>
where
    K2: Eq,
{
    /// K2 (part of the data structure key)
    k2: K2,
    /// Circuit isolation (part of the data structure key)
    isolation: Box<dyn Isolation>,
    /// Actual value
    #[deref]
    #[deref_mut]
    value: V,
}

impl<K2, V> Record<K2, V>
where
    K2: Eq,
{
    /// Obtain a reference to this record's 2nd-stage key `K2`
    #[allow(dead_code)] // TODO remove if and when we make this all pub
    pub(crate) fn k2(&self) -> &K2 {
        &self.k2
    }

    /// Obtain a reference to this record's isolation
    #[allow(dead_code)] // TODO remove if and when we make this all pub
    pub(crate) fn isolation(&self) -> &dyn Isolation {
        &*self.isolation
    }
}

impl<I, K1, K2, V> MultikeyIsolatedMap<I, K1, K2, V>
where
    I: Key,
    K1: Hash + Eq,
    K2: Eq,
{
    /// Lookup, or insert, an entry
    ///
    /// Looks for an entry with keys `k1` and `k2` and a compatible isolation.
    /// If it finds one, narrows the isolation and returns the entry's index.
    ///
    /// If no entry is found, inserts a new value made by `create`.
    pub(crate) fn index_or_insert_with(
        &mut self,
        k1: &K1,
        k2: &K2,
        isolation: Box<dyn Isolation>,
        create: impl FnOnce() -> V,
    ) -> I
    where
        K1: Clone,
        K2: Clone,
    {
        let indices = self.index.entry(k1.clone()).or_default();

        match indices.iter().find_map(|&t_index| {
            // Deconstruct so that we can't accidentally fail to check some of the key fields
            let Record {
                k2: t_k2,
                isolation: t_isolation,
                value: _,
            } = self.table.get(t_index)
                // should be Some, unless data structure corrupted, but don't panic here
                    ?;
            (t_k2 == k2).then_some(())?;
            let new_isolation = t_isolation.join(&*isolation)?;
            Some((t_index, new_isolation))
        }) {
            Some((t_index, new_isolation)) => {
                self.table
                    .get_mut(t_index)
                    .expect("table entry disappeared")
                    .isolation = new_isolation;
                t_index
            }
            None => {
                let value = create();
                let record = Record {
                    k2: k2.clone(),
                    isolation,
                    value,
                };
                let table_index = self.table.insert(record);
                indices.push(table_index);
                table_index
            }
        }
    }

    /// Look up an existing entry by index
    ///
    /// If the entry was removed in the meantime, will return `None`
    #[allow(dead_code)] // TODO remove if and when we make this all pub
    pub(crate) fn by_index(&self, t_index: I) -> Option<&Record<K2, V>> {
        self.table.get(t_index)
    }

    /// Look up an existing entry by index (mutably)
    ///
    /// If the entry was removed in the meantime, will return `None`
    pub(crate) fn by_index_mut(&mut self, t_index: I) -> Option<&mut Record<K2, V>> {
        self.table.get_mut(t_index)
    }

    /// Keep only entries that match a predicate
    ///
    /// Each entry is passed to `test`, and removed unless `test` returned `true`.
    #[allow(dead_code)] // TODO HS remove
    pub(crate) fn retain(&mut self, mut test: impl FnMut(&K1, &Record<K2, V>, I) -> bool) {
        self.index.retain(|k1, indices| {
            indices.retain(|&t_index| {
                let record = match self.table.get(t_index) {
                    Some(record) => record,
                    None => return false, // shouldn't happen
                };
                let keep = test(k1, record, t_index);
                if !keep {
                    self.table.remove(t_index);
                }
                keep
            });
            !indices.is_empty()
        });
    }

    /// Checks that the structure is consistent
    ///
    /// # Panics
    ///
    /// If it is found not to be.
    #[cfg(test)]
    fn check_or_panic(&self) {
        let mut referenced = slotmap_careful::SecondaryMap::default();

        for indices in self.index.values() {
            assert!(!indices.is_empty(), "empty Vec not GC'd");
            for (vi1, &ti1) in indices.iter().enumerate() {
                let rec1 = self.table.get(ti1).expect("dangling index");
                match referenced.entry(ti1) {
                    Some(slotmap_careful::secondary::Entry::Vacant(ve)) => ve.insert(()),
                    _ => panic!("colliding references or something {ti1:?}"),
                };
                for &ti2 in &indices[vi1 + 1..] {
                    let rec2 = &self.table[ti2];
                    assert!(
                        !(rec1.k2 == rec2.k2 && rec1.isolation.compatible(&*rec2.isolation)),
                        "Vec contains entries that should have been merged",
                    );
                }
            }
        }

        for ti in self.table.keys() {
            let () = referenced.get(ti).expect("unreferenced entry");
        }
    }
}

// TODO HS: Currently tested via state.rs's stests, which do exercise this fairly well,
// but some more dedicated unit tests would be good.
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

    slotmap_careful::new_key_type! {
        struct Idx;
    }

    use crate::state::test::NarrowableIsolation;

    fn mk_isol(s: impl Into<String>) -> Box<dyn Isolation> {
        NarrowableIsolation(s.into()).into()
    }

    fn mk() -> MultikeyIsolatedMap<Idx, u32, u16, String> {
        let mut out = MultikeyIsolatedMap::<Idx, u32, u16, String>::default();
        let ti = out.index_or_insert_with(&1, &22, mk_isol("a"), || "hi".into());
        assert_eq!(out.by_index(ti).unwrap().k2(), &22);
        out.check_or_panic();
        out
    }

    #[test]
    fn simple() {
        mk();
    }

    #[test]
    fn retain() {
        let mut m = mk();
        m.index_or_insert_with(&2, &22, mk_isol("ab"), || "22".into());
        m.check_or_panic();
        m.index_or_insert_with(&2, &23, mk_isol("ac"), || "23".into());
        m.check_or_panic();
        m.index_or_insert_with(&2, &24, mk_isol("dd"), || "24".into());
        m.check_or_panic();
        dbg!(&m);
        m.retain(|_k1, rec, _ti| (rec.k2 % 2) == 1);
        dbg!(&m);
        m.check_or_panic();
    }
}
