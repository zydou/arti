//! Data structure `MultikeyIsolatedMap` indexed by multiple keys and an isolation

use std::collections::HashMap;
use std::hash::Hash;

use derive_more::{Deref, DerefMut};
use educe::Educe;
use slotmap::dense::DenseSlotMap;

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
///           HashMap           Vec_______________          SlotMap____________________
///           |     | contains  | table_index    |  t._i.   | K2, isol, V  /  <empty> |
///     K1 -> |  ---+---------> | table_index    | -------> | K2, isol, V  /  <empty> |
///           |_____|           | table_index    |          | K2, isol, V  /  <empty> |
///                             | table_index    |          | K2, isol, V  /  <empty> |
///   K2, isol ---------------> | .............. |          | K2, isol, V  /  <empty> |
///             linear search   |________________|          | ...             ....    |
/// ```                                                     |_________________________|
#[derive(Debug, Educe)]
#[educe(Default)]
pub(crate) struct MultikeyIsolatedMap<I, K1, K2, V>
where
    I: slotmap::Key,
    K1: Hash + Eq,
    K2: Eq,
{
    /// The first stage index, mapping `K1` to `I`
    index: HashMap<K1, Vec<I>>,

    /// Actual table containing the
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
    I: slotmap::Key,
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
            (t_k2 == k2).then(|| ())?;
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
}

// TODO HS: Currently tested via state.rs's stests, which do exercise this fairly well,
// but some dedicated unit tests would be good.
