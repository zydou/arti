//! Support for weak references.
//!
//! Currently, this is unused in Arti; we may eventually remove it, which will let us simplify our
//! code.
//!
//! In any case, we should not use this until we have a solid idea about how weak references should
//! behave; see #868.

#![allow(dead_code)]

use std::{
    any,
    sync::{Arc, Weak},
};

use super::{GenIdx, ObjMap, TaggedAddr, raw_addr_of, raw_addr_of_weak};
use tor_rpcbase as rpc;

/// A single entry to a weak Object stored in the generational arena.
pub(super) struct WeakArenaEntry {
    /// The actual Arc or Weak reference for the object that we're storing here.
    pub(super) obj: Weak<dyn rpc::Object>,
    ///
    /// This contains a strong or weak reference, along with the object's true TypeId.
    /// See the [`TaggedAddr`] for more info on
    /// why this is needed.
    id: any::TypeId,
}

impl WeakArenaEntry {
    /// Create a new `WeakArenaEntry` for a weak reference.
    pub(super) fn new(object: &Arc<dyn rpc::Object>) -> Self {
        let id = (**object).type_id();
        Self {
            obj: Arc::downgrade(object),
            id,
        }
    }

    /// Return true if this `ArenaEntry` is really present.
    ///
    /// Note that this function can produce false positives (if the entry's
    /// last strong reference is dropped in another thread), but it can
    /// never produce false negatives.
    pub(super) fn is_present(&self) -> bool {
        // This is safe from false negatives because: if we can ever
        // observe strong_count == 0, then there is no way for anybody
        // else to "resurrect" the object.
        self.obj.strong_count() > 0
    }

    /// Return a strong reference to the object in this entry, if possible.
    pub(super) fn strong(&self) -> Option<Arc<dyn rpc::Object>> {
        Weak::upgrade(&self.obj)
    }

    /// Return the [`TaggedAddr`] that can be used to identify this entry's object.
    pub(super) fn tagged_addr(&self) -> TaggedAddr {
        TaggedAddr {
            addr: raw_addr_of_weak(&self.obj),
            type_id: self.id,
        }
    }
}

impl TaggedAddr {
    /// Return the `TaggedAddr` to uniquely identify `obj` over the course of
    /// its existence.
    pub(super) fn for_object(obj: &Arc<dyn rpc::Object>) -> Self {
        let type_id = (*obj).type_id();
        let addr = raw_addr_of(obj);
        TaggedAddr { addr, type_id }
    }
}

impl ObjMap {
    /// Reclaim unused space in this map's weak arena.
    ///
    /// This runs in `O(n)` time.
    pub(super) fn tidy(&mut self) {
        #[cfg(test)]
        {
            self.n_tidies += 1;
        }
        self.weak_arena.retain(|index, entry| {
            let present = entry.is_present();
            if !present {
                // For everything we are removing from the `arena`, we must also
                // remove it from `reverse_map`.
                let ptr = entry.tagged_addr();
                let found = self.reverse_map.remove(&ptr);
                debug_assert_eq!(found, Some(index));
            }
            present
        });
    }

    /// If needed, clean the weak arena and resize it.
    ///
    /// (We call this whenever we're about to add an entry.  This ensures that
    /// our insertion operations run in `O(1)` time.)
    fn adjust_size(&mut self) {
        // If we're about to fill the arena...
        if self.weak_arena.len() >= self.weak_arena.capacity() {
            // ... we delete any dead `Weak` entries.
            self.tidy();
            // Then, if the arena is still above half-full, we double the
            // capacity of the arena.
            //
            // (We have to grow the arena this even if tidy() removed _some_
            // entries, or else we might re-run tidy() too soon.  But we don't
            // want to grow the arena if tidy() removed _most_ entries, or some
            // normal usage patterns will lead to unbounded growth.)
            if self.weak_arena.len() > self.weak_arena.capacity() / 2 {
                self.weak_arena.reserve(self.weak_arena.capacity());
            }
        }
    }

    /// Ensure that there is a weak entry for `value` in self, and return an
    /// index for it.
    /// If there is no entry, create a weak entry.
    #[allow(clippy::needless_pass_by_value)] // TODO: Decide whether to make this take a reference.
    pub(crate) fn insert_weak(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        let ptr = TaggedAddr::for_object(&value);
        if let Some(idx) = self.reverse_map.get(&ptr) {
            #[cfg(debug_assertions)]
            match self.weak_arena.get(*idx) {
                Some(entry) => debug_assert!(entry.tagged_addr() == ptr),
                None => panic!("Found a dangling reference"),
            }
            return GenIdx::Weak(*idx);
        }

        self.adjust_size();
        let idx = self.weak_arena.insert(WeakArenaEntry::new(&value));
        self.reverse_map.insert(ptr, idx);
        GenIdx::Weak(idx)
    }
}
