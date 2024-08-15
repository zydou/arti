//! An object mapper for looking up `rpc::Object`s by ID.
//!
//! This mapper stores strong or weak references, and uses a generational index
//! to keep track of names for them.
//!
//! TODO RPC: Add an object diagram here once the implementation settles down.

#![allow(dead_code)] // TODO RPC: Remove this once the crate is stable.

use std::any;
use std::collections::HashMap;
use std::sync::{Arc, Weak};

use slotmap_careful::{Key as _, KeyData, SlotMap};
use tor_rpcbase as rpc;

slotmap_careful::new_key_type! {
    pub(crate) struct WeakIdx;
    pub(crate) struct StrongIdx;
}

/// A mechanism to look up RPC `Objects` by their `ObjectId`.
#[derive(Default)]
pub(crate) struct ObjMap {
    /// Generationally indexed arena of strong object references.
    strong_arena: SlotMap<StrongIdx, Arc<dyn rpc::Object>>,
    /// Generationally indexed arena of weak object references.
    ///
    /// Invariants:
    /// * No object has more than one reference in this arena.
    /// * Every `entry` in this arena at position `idx` has a corresponding
    ///   entry in `reverse_map` entry such that
    ///   `reverse_map[entry.tagged_addr()] == idx`.
    weak_arena: SlotMap<WeakIdx, WeakArenaEntry>,
    /// Backwards reference to look up weak arena references by the underlying
    /// object identity.
    ///
    /// Invariants:
    /// * For every weak `(addr,idx)` entry in this map, there is a
    ///   corresponding ArenaEntry in `arena` such that
    ///   `arena[idx].tagged_addr() == addr`
    reverse_map: HashMap<TaggedAddr, WeakIdx>,
    /// Testing only: How many times have we tidied this map?
    #[cfg(test)]
    n_tidies: usize,
}

/// A single entry to a weak Object stored in the generational arena.
///
struct WeakArenaEntry {
    /// The actual Arc or Weak reference for the object that we're storing here.
    obj: Weak<dyn rpc::Object>,
    ///
    /// This contains a strong or weak reference, along with the object's true TypeId.
    /// See the [`TaggedAddr`] for more info on
    /// why this is needed.
    id: any::TypeId,
}

/// The raw address of an object held in an Arc or Weak.
///
/// This will be the same for every clone of an Arc, and the same for every Weak
/// derived from an Arc.
///
/// Note that this is not on its own sufficient to uniquely identify an object;
/// we must also know the object's TypeId.  See [`TaggedAddr`] for more information.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
struct RawAddr(usize);

/// An address, type identity, and ownership status, used to identify a `Arc<dyn rpc::Object>`.
///
/// This type is necessary because of the way that Rust implements `Arc<dyn
/// Foo>`. It's represented as a "fat pointer", containing:
///    * A pointer to the  object itself (and the reference counts that make the
///      `Arc<>` work.)
///    * A vtable pointer explaining how to invoke the methods of `Foo` on this
///      particular object.
///
/// The trouble here is that `Arc::ptr_eq()` can give an incorrect result, since
/// a single type can be instantiated with multiple instances of its vtable
/// pointer, which [breaks pointer comparison on `dyn`
/// pointers](https://doc.rust-lang.org/std/ptr/fn.eq.html).
///
/// Thus, instead of comparing objects by (object pointer, vtable pointer)
/// tuples, we have to compare them by (object pointer, type id).
///
/// (We _do_ have to look at type ids, and not just the pointers, since
/// `repr(transparent)` enables people to have two `Arc<dyn Object>`s that have
/// the same object pointer but different types.)[^1]
///
/// # Limitations
///
/// This type only uniquely identifies an Arc/Weak object for that object's
/// lifespan. After the last (strong or weak) reference is dropped, this
/// `TaggedAddr` may refer to a different object.
///
/// [^1]: TODO: Verify whether the necessary transmutation here is actually
///     guaranteed to work.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
struct TaggedAddr {
    /// The address of the object.
    addr: RawAddr,
    /// The type of the object.
    type_id: any::TypeId,
}

/// A generational index for [`ObjMap`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum GenIdx {
    /// An index into the arena of weak references.
    Weak(WeakIdx),
    /// An index into the arena of strong references
    Strong(StrongIdx),
}

/// Return the [`RawAddr`] of an arbitrary `Arc<T>`.
fn raw_addr_of<T: ?Sized>(arc: &Arc<T>) -> RawAddr {
    // I assure you, each one of these 'as'es was needed in the version of
    // Rust I wrote them in.
    RawAddr(Arc::as_ptr(arc) as *const () as usize)
}

/// Return the [`RawAddr`] of an arbitrary `Weak<T>`.
fn raw_addr_of_weak<T: ?Sized>(arc: &Weak<T>) -> RawAddr {
    RawAddr(Weak::as_ptr(arc) as *const () as usize)
}

impl WeakArenaEntry {
    /// Create a new `WeakArenaEntry` for a weak reference.
    fn new(object: &Arc<dyn rpc::Object>) -> Self {
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
    fn is_present(&self) -> bool {
        // This is safe from false negatives because: if we can ever
        // observe strong_count == 0, then there is no way for anybody
        // else to "resurrect" the object.
        self.obj.strong_count() > 0
    }

    /// Return a strong reference to the object in this entry, if possible.
    fn strong(&self) -> Option<Arc<dyn rpc::Object>> {
        Weak::upgrade(&self.obj)
    }

    /// Return the [`TaggedAddr`] that can be used to identify this entry's object.
    fn tagged_addr(&self) -> TaggedAddr {
        TaggedAddr {
            addr: raw_addr_of_weak(&self.obj),
            type_id: self.id,
        }
    }
}

impl TaggedAddr {
    /// Return the `TaggedAddr` to uniquely identify `obj` over the course of
    /// its existence.
    fn for_object(obj: &Arc<dyn rpc::Object>) -> Self {
        let type_id = (*obj).type_id();
        let addr = raw_addr_of(obj);
        TaggedAddr { addr, type_id }
    }
}

/// Encoding functions for GenIdx.
///
/// The encoding is deliberately nondeterministic: we want to avoid situations
/// where applications depend on the details of our ObjectIds, or hardcode the
/// ObjectIds they expect, or rely on the same  weak generational index getting
/// encoded the same way every time they see it.
///
/// The encoding is deliberately non-cryptographic: we do not want to imply
/// that this gives any security. It is just a mild deterrent to misuse.
///
/// If you find yourself wanting to reverse-engineer this code so that you can
/// analyze these object IDs, please contact the Arti developers instead and let
/// us give you a better way to do whatever you want.
impl GenIdx {
    /// The length of a byte-encoded (but not base-64 encoded) GenIdx.
    pub(crate) const BYTE_LEN: usize = 16;

    /// Return true if this is a strong (owning) reference.
    pub(crate) fn is_strong(&self) -> bool {
        matches!(self, GenIdx::Strong(_))
    }

    /// Encode `self` into an rpc::ObjectId that we can give to a client.
    pub(crate) fn encode(self) -> rpc::ObjectId {
        self.encode_with_rng(&mut rand::thread_rng())
    }

    /// As `encode`, but take a Rng as an argument. For testing.
    fn encode_with_rng<R: rand::RngCore>(self, rng: &mut R) -> rpc::ObjectId {
        use base64ct::Encoding;
        let bytes = self.to_bytes(rng);
        rpc::ObjectId::from(base64ct::Base64UrlUnpadded::encode_string(&bytes[..]))
    }

    /// As `encode_with_rng`, but return an array of bytes.
    pub(crate) fn to_bytes<R: rand::RngCore>(self, rng: &mut R) -> [u8; Self::BYTE_LEN] {
        use rand::Rng;
        use tor_bytes::Writer;
        let (weak_bit, ffi_idx) = match self {
            GenIdx::Weak(idx) => (1, idx.data().as_ffi()),
            GenIdx::Strong(idx) => (0, idx.data().as_ffi()),
        };
        let x = rng.gen::<u64>() << 1;
        let mut bytes = Vec::with_capacity(Self::BYTE_LEN);
        bytes.write_u64(x | weak_bit);
        bytes.write_u64(ffi_idx.wrapping_add(x));

        bytes.try_into().expect("Length was wrong!")
    }

    /// Attempt to decode `id` into a `GenIdx` than an ObjMap can use.
    pub(crate) fn try_decode(id: &rpc::ObjectId) -> Result<Self, rpc::LookupError> {
        use base64ct::Encoding;

        let bytes = base64ct::Base64UrlUnpadded::decode_vec(id.as_ref())
            .map_err(|_| rpc::LookupError::NoObject(id.clone()))?;
        Self::from_bytes(&bytes).ok_or_else(|| rpc::LookupError::NoObject(id.clone()))
    }

    /// As `try_decode`, but take a slice of bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        use tor_bytes::Reader;
        let mut r = Reader::from_slice(bytes);
        let x = r.take_u64().ok()?;
        let is_weak = (x & 1) == 1;
        let x = x & !1;
        let ffi_idx = r.take_u64().ok()?;
        r.should_be_exhausted().ok()?;

        let ffi_idx = ffi_idx.wrapping_sub(x);

        if is_weak {
            Some(GenIdx::Weak(WeakIdx::from(KeyData::from_ffi(ffi_idx))))
        } else {
            Some(GenIdx::Strong(StrongIdx::from(KeyData::from_ffi(ffi_idx))))
        }
    }
}

impl ObjMap {
    /// Create a new empty ObjMap.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reclaim unused space in this map's weak arena.
    ///
    /// This runs in `O(n)` time.
    fn tidy(&mut self) {
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

    /// Unconditionally insert a strong entry for `value` in self, and return its index.
    pub(crate) fn insert_strong(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        GenIdx::Strong(self.strong_arena.insert(value))
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

    /// Return the entry from this ObjMap for `idx`.
    pub(crate) fn lookup(&self, idx: GenIdx) -> Option<Arc<dyn rpc::Object>> {
        match idx {
            GenIdx::Weak(idx) => self.weak_arena.get(idx).and_then(WeakArenaEntry::strong),
            GenIdx::Strong(idx) => self.strong_arena.get(idx).cloned(),
        }
    }

    /// Remove and return the entry at `idx`, if any.
    pub(crate) fn remove(&mut self, idx: GenIdx) -> Option<Arc<dyn rpc::Object>> {
        match idx {
            GenIdx::Weak(idx) => {
                if let Some(entry) = self.weak_arena.remove(idx) {
                    let old_idx = self.reverse_map.remove(&entry.tagged_addr());
                    debug_assert_eq!(old_idx, Some(idx));
                    entry.obj.upgrade()
                } else {
                    None
                }
            }
            GenIdx::Strong(idx) => self.strong_arena.remove(idx),
        }
    }

    /// Testing only: Assert that every invariant for this structure is met.
    #[cfg(test)]
    fn assert_okay(&self) {
        for (index, entry) in self.weak_arena.iter() {
            let ptr = entry.tagged_addr();
            assert_eq!(self.reverse_map.get(&ptr), Some(&index));
            assert_eq!(ptr, entry.tagged_addr());
        }

        for (ptr, idx) in self.reverse_map.iter() {
            let entry = self
                .weak_arena
                .get(*idx)
                .expect("Dangling pointer in reverse map");

            assert_eq!(&entry.tagged_addr(), ptr);
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

    use super::*;
    use derive_deftly::Deftly;
    use tor_rpcbase::templates::*;

    #[derive(Clone, Debug, Deftly)]
    #[derive_deftly(Object)]
    struct ExampleObject(String);

    impl ExampleObject {
        fn wrap_arc(self: Arc<Self>) -> Arc<Wrapper> {
            // SAFETY: Using `repr(transparent)` on Wrapper guarantees that
            // transmuting an ExampleObject to a Wrapper will work correctly.
            //
            // Given this, and the fact that they have the same alignment and
            // size, the documentation for `Arc::from_raw` says that this should
            // be safe.
            //
            // Also this is only a test.
            unsafe { Arc::from_raw(Arc::into_raw(self) as *const Wrapper) }
        }
    }

    #[derive(Clone, Debug, Deftly)]
    #[derive_deftly(Object)]
    #[repr(transparent)]
    struct Wrapper(ExampleObject);

    #[test]
    fn arc_to_addr() {
        let a1 = Arc::new("Hello world");
        let a2 = Arc::clone(&a1);
        let a3 = Arc::new("Hello world");
        let w1 = Arc::downgrade(&a2);

        assert_eq!(raw_addr_of(&a1), raw_addr_of(&a2));
        assert_eq!(raw_addr_of(&a1), raw_addr_of_weak(&w1));
        assert_ne!(raw_addr_of(&a1), raw_addr_of(&a3));

        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("Hello world".into()));
        let obj2 = Arc::clone(&obj1);
        let obj3: Arc<dyn rpc::Object> = Arc::new(ExampleObject("Hello world".into()));
        let obj4 = Arc::clone(&obj3);
        let weak1 = Arc::downgrade(&obj1);
        let weak2 = Arc::downgrade(&obj3);

        assert_eq!(raw_addr_of(&obj1), raw_addr_of(&obj2));
        assert_eq!(raw_addr_of(&obj1), raw_addr_of_weak(&weak1));
        assert_eq!(raw_addr_of(&obj3), raw_addr_of(&obj4));
        assert_eq!(raw_addr_of(&obj3), raw_addr_of_weak(&weak2));
        assert_ne!(raw_addr_of(&obj1), raw_addr_of(&obj3));
        assert_ne!(raw_addr_of(&obj1), raw_addr_of(&a1));
    }

    #[test]
    fn obj_ptr() {
        let object = Arc::new(ExampleObject("Ten tons of flax".into()));
        let object2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("Ten tons of flax".into()));

        let wrapped: Arc<Wrapper> = object.clone().wrap_arc();
        let object_dyn = object.clone() as Arc<dyn rpc::Object>;
        let wrapped_dyn = wrapped.clone() as Arc<dyn rpc::Object>;

        let object_dyn2 = Arc::clone(&object_dyn);
        let wrapped_dyn2 = Arc::clone(&wrapped_dyn);
        let wrapped_weak = Arc::downgrade(&wrapped_dyn);

        assert_eq!(
            TaggedAddr::for_object(&object_dyn),
            TaggedAddr::for_object(&object_dyn2)
        );
        assert_ne!(
            TaggedAddr::for_object(&object_dyn),
            TaggedAddr::for_object(&object2)
        );

        assert_eq!(
            TaggedAddr::for_object(&wrapped_dyn),
            TaggedAddr::for_object(&wrapped_dyn2)
        );

        assert_ne!(
            TaggedAddr::for_object(&object_dyn),
            TaggedAddr::for_object(&wrapped_dyn)
        );

        assert_eq!(
            TaggedAddr::for_object(&object_dyn).addr,
            TaggedAddr::for_object(&wrapped_dyn).addr
        );
        assert_eq!(
            TaggedAddr::for_object(&wrapped_dyn).addr,
            raw_addr_of_weak(&wrapped_weak)
        );

        assert_eq!(
            TaggedAddr::for_object(&object_dyn).type_id,
            any::TypeId::of::<ExampleObject>()
        );
        assert_eq!(
            TaggedAddr::for_object(&wrapped_dyn).type_id,
            any::TypeId::of::<Wrapper>()
        );

        assert_eq!(
            TaggedAddr::for_object(&object_dyn).addr,
            raw_addr_of(&object)
        );
        assert_eq!(
            TaggedAddr::for_object(&wrapped_dyn).addr,
            raw_addr_of(&wrapped)
        );
        assert_ne!(
            TaggedAddr::for_object(&object_dyn).addr,
            raw_addr_of(&object2)
        );
    }

    #[test]
    fn map_basics() {
        // Insert an object, make sure it only gets inserted once, and look it up.
        let obj1 = Arc::new(ExampleObject("abcdef".to_string()));
        let mut map = ObjMap::new();
        map.assert_okay();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_strong(obj1.clone());
        assert_ne!(id1, id2);
        let obj_out1 = map.lookup(id1).unwrap();
        let obj_out2 = map.lookup(id2).unwrap();
        assert_eq!(raw_addr_of(&obj1), raw_addr_of(&obj_out1));
        assert_eq!(raw_addr_of(&obj1), raw_addr_of(&obj_out2));
        map.assert_okay();
    }

    #[test]
    fn strong_and_weak() {
        // Make sure that a strong object behaves like one, and so does a weak
        // object.
        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("hello".to_string()));
        let obj2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("world".to_string()));
        let mut map = ObjMap::new();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_weak(obj2.clone());

        {
            let out1 = map.lookup(id1);
            let out2 = map.lookup(id2);
            assert_eq!(raw_addr_of(&obj1), raw_addr_of(&out1.unwrap()));
            assert_eq!(raw_addr_of(&obj2), raw_addr_of(&out2.unwrap()));
        }
        let addr1 = raw_addr_of(&obj1);
        map.assert_okay();

        // Now drop every object we've got, and see what we can still find.
        drop(obj1);
        drop(obj2);
        {
            let out1 = map.lookup(id1);
            let out2 = map.lookup(id2);

            // This one was strong, so it is still there.
            assert!(out1.is_some());
            assert_eq!(raw_addr_of(&out1.unwrap()), addr1);

            // This one is weak so it went away.
            assert!(out2.is_none());
        }
        map.assert_okay();
    }

    #[test]
    fn remove() {
        // Make sure that removing an object makes it go away.
        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("hello".to_string()));
        let obj2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("world".to_string()));
        let mut map = ObjMap::new();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_weak(obj2.clone());
        map.assert_okay();

        map.remove(id1);
        map.assert_okay();
        assert!(map.lookup(id1).is_none());
        assert!(map.lookup(id2).is_some());

        map.remove(id2);
        map.assert_okay();
        assert!(map.lookup(id1).is_none());
        assert!(map.lookup(id2).is_none());
    }

    #[test]
    fn duplicates() {
        // Make sure that inserting duplicate objects behaves right.
        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("hello".to_string()));
        let obj2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("world".to_string()));
        let mut map = ObjMap::new();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_weak(obj2.clone());

        {
            assert_ne!(id2, map.insert_weak(obj1.clone()));
            assert_eq!(id2, map.insert_weak(obj2.clone()));
        }

        {
            assert_ne!(id1, map.insert_strong(obj1.clone()));
            assert_ne!(id2, map.insert_strong(obj2.clone()));
        }
    }

    #[test]
    fn upgrade() {
        // Make sure that inserting an object as weak and strong (in either
        // order) makes two separate entries.
        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("hello".to_string()));
        let obj2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("world".to_string()));
        let addr1 = raw_addr_of(&obj1);
        let addr2 = raw_addr_of(&obj2);

        let mut map = ObjMap::new();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_weak(obj2.clone());

        assert_ne!(id2, map.insert_weak(obj1.clone()));
        assert_ne!(id1, map.insert_strong(obj2.clone()));
        map.assert_okay();

        drop(obj1);
        drop(obj2);
        let out1 = map.lookup(id1).unwrap();
        let out2 = map.lookup(id2).unwrap();
        assert_eq!(raw_addr_of(&out1), addr1);
        assert_eq!(raw_addr_of(&out2), addr2);
    }

    #[test]
    fn tidy() {
        let mut map = ObjMap::new();
        let mut keep_these = vec![];
        let mut s = vec![];
        let mut w = vec![];
        for _ in 0..100 {
            let mut t = vec![];
            for _ in 0..10 {
                let o = Arc::new(ExampleObject("dump".into()));
                w.push(map.insert_weak(o.clone()));
                t.push(o);
            }
            let obj = Arc::new(ExampleObject("cafe".into()));
            keep_these.push(obj.clone());
            s.push(map.insert_weak(obj));
            drop(t);
            map.assert_okay();
        }

        assert_eq!(s.len(), 100);
        assert_eq!(w.len(), 1000);
        assert!(w.iter().all(|id| map.lookup(*id).is_none()));
        assert!(s.iter().all(|id| map.lookup(*id).is_some()));

        assert_ne!(map.weak_arena.len() + map.strong_arena.len(), 1100);
        map.assert_okay();
        map.tidy();
        map.assert_okay();
        assert_eq!(map.weak_arena.len() + map.strong_arena.len(), 100);

        // This number is a bit arbitrary.
        assert!(dbg!(map.n_tidies) < 30);
    }

    #[test]
    fn wrapper_magic() {
        // Make sure that the wrapper transmutation trick works well.
        let obj = Arc::new(ExampleObject("dump".into()));
        let wrap = obj.clone().wrap_arc();

        let mut map = ObjMap::new();
        map.insert_strong(obj);
        map.insert_strong(wrap);
        assert_eq!(map.strong_arena.len(), 2);
    }

    #[test]
    fn objid_encoding() {
        use rand::Rng;
        fn test_roundtrip(a: u32, b: u32, rng: &mut tor_basic_utils::test_rng::TestingRng) {
            let a: u64 = a.into();
            let b: u64 = b.into();
            let data = KeyData::from_ffi((a << 33) | 1_u64 << 32 | b);
            let idx = if rng.gen_bool(0.5) {
                GenIdx::Strong(StrongIdx::from(data))
            } else {
                GenIdx::Weak(WeakIdx::from(data))
            };
            let s1 = idx.encode_with_rng(rng);
            let s2 = idx.encode_with_rng(rng);
            assert_ne!(s1, s2);
            assert_eq!(idx, GenIdx::try_decode(&s1).unwrap());
            assert_eq!(idx, GenIdx::try_decode(&s2).unwrap());
        }
        let mut rng = tor_basic_utils::test_rng::testing_rng();

        test_roundtrip(0, 1, &mut rng);
        test_roundtrip(0, 2, &mut rng);
        test_roundtrip(1, 1, &mut rng);
        test_roundtrip(0xffffffff, 0xffffffff, &mut rng);

        for _ in 0..256 {
            test_roundtrip(rng.gen(), rng.gen(), &mut rng);
        }
    }
}
