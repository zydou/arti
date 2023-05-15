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

use fake_generational_arena::{self as generational_arena, FakeArena as Arena};
// use generational_arena::Arena;
use tor_rpcbase as rpc;

/// Fake implementation of `generational_arena` while we sort out which MPL-2.0
/// they meant.
///
/// (See issue #845)
///
/// TODO RPC: Replace this with `generational_arena` if they agree with us that
/// they meant "no exhibit B", or with something else if they don't.
mod fake_generational_arena {
    #![allow(missing_docs, unreachable_pub)]
    #![allow(clippy::missing_docs_in_private_items)]
    use std::collections::HashMap;
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub(crate) struct Index(u64);
    #[derive(Clone, Debug)]
    pub(crate) struct FakeArena<T> {
        nextkey: u64,
        map: HashMap<u64, T>,
    }

    impl Index {
        pub fn into_raw_parts(self) -> (usize, u64) {
            (0, self.0)
        }
        pub fn from_raw_parts(_: usize, idx: u64) -> Self {
            Self(idx)
        }
    }
    impl<T> FakeArena<T> {
        pub fn new() -> Self {
            Self {
                nextkey: 0,
                map: HashMap::new(),
            }
        }
        pub fn capacity(&self) -> usize {
            self.map.capacity()
        }
        pub fn len(&self) -> usize {
            self.map.len()
        }
        pub fn reserve(&mut self, additional: usize) {
            self.map.reserve(additional);
        }
        pub fn get(&self, index: Index) -> Option<&T> {
            self.map.get(&index.0)
        }
        pub fn get_mut(&mut self, index: Index) -> Option<&mut T> {
            self.map.get_mut(&index.0)
        }
        pub fn insert(&mut self, value: T) -> Index {
            let key = self.nextkey;
            self.nextkey += 1;
            self.map.insert(key, value);
            Index(key)
        }
        pub fn remove(&mut self, index: Index) -> Option<T> {
            self.map.remove(&index.0)
        }
        pub fn iter(&self) -> impl Iterator<Item = (Index, &T)> {
            self.map.iter().map(|(idx, val)| (Index(*idx), val))
        }
        pub fn retain<F>(&mut self, mut func: F)
        where
            F: FnMut(Index, &T) -> bool,
        {
            self.map.retain(|k, v| func(Index(*k), v));
        }
    }
    impl<T> Default for FakeArena<T> {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// A mechanism to look up RPC `Objects` by their `ObjectId`.
#[derive(Default)]
pub(crate) struct ObjMap {
    /// Generationally indexed arena of object references.
    ///
    /// Invariants:
    /// * No object has more than one weak reference in this arena.
    /// * Every weak `entry` in this arena at position `idx` has a corresponding
    ///   entry in `reverse_map` entry such that
    ///   `reverse_map[entry.tagged_addr()] == idx`.
    arena: Arena<ArenaEntry>,
    /// Backwards reference to look up arena references by the underlying object identity.
    ///
    /// Invariants:
    /// * For every weak `(addr,idx)` entry in this map, there is a corresponding
    ///   ArenaEntry in `arena` such that `arena[idx].tagged_addr() == addr`
    reverse_map: HashMap<TaggedAddr, GenIdx>,
    /// Testing only: How many times have we tidied this map?
    #[cfg(test)]
    n_tidies: usize,
}

/// A single entry to an Object stored in the generational arena.
///
struct ArenaEntry {
    /// The actual Arc or Weak reference for the object that we're storing here.
    obj: ObjRef,
    ///
    /// This contains a strong or weak reference, along with the object's true TypeId.
    /// See the [`TaggedAddr`] for more info on
    /// why this is needed.
    id: any::TypeId,
}

/// Strong or weak reference to an Object.
enum ObjRef {
    /// A strong reference
    Strong(Arc<dyn rpc::Object>),
    /// A weak reference
    Weak(Weak<dyn rpc::Object>),
}

impl ObjRef {
    /// Try to return a strong reference to this object, upgrading a weak
    /// reference if needed.
    ///
    /// A `None` return indicates a dangling weak reference.
    fn strong(&self) -> Option<Arc<dyn rpc::Object>> {
        match self {
            ObjRef::Strong(s) => Some(s.clone()),
            ObjRef::Weak(w) => Weak::upgrade(w),
        }
    }

    /// Return the [`RawAddr`] associated with this object.
    fn raw_addr(&self) -> RawAddr {
        match self {
            ObjRef::Strong(s) => raw_addr_of(s),
            ObjRef::Weak(w) => raw_addr_of_weak(w),
        }
    }
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
pub(crate) struct GenIdx(generational_arena::Index);

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

impl ArenaEntry {
    /// Create a new `ArenaEntry` for a strong reference.
    fn new_strong(object: Arc<dyn rpc::Object>) -> Self {
        let id = (*object).type_id();
        Self {
            obj: ObjRef::Strong(object),
            id,
        }
    }

    /// Create a new `ArenaEntry` for a weak reference.
    fn new_weak(object: &Arc<dyn rpc::Object>) -> Self {
        let id = (**object).type_id();
        Self {
            obj: ObjRef::Weak(Arc::downgrade(object)),
            id,
        }
    }

    /// Return true if this `ArenaEntry` is really present.
    ///
    /// Note that this function can produce false positives (if the entry is Weak
    /// and its last strong reference is dropped in another thread), but it can
    /// never produce false negatives.
    fn is_present(&self) -> bool {
        match &self.obj {
            ObjRef::Strong(_) => true,
            ObjRef::Weak(w) => {
                // This is safe from false negatives because: if we can ever
                // observe strong_count == 0, then there is no way for anybody
                // else to "resurrect" the object.
                w.strong_count() > 0
            }
        }
    }

    /// Return a strong reference to the object in this entry, if possible.
    fn strong(&self) -> Option<Arc<dyn rpc::Object>> {
        match &self.obj {
            ObjRef::Strong(s) => Some(Arc::clone(s)),
            ObjRef::Weak(w) => Weak::upgrade(w),
        }
    }

    /// Return true if this is a weak reference.
    fn is_weak(&self) -> bool {
        matches!(&self.obj, ObjRef::Weak(_))
    }

    /// Return the [`TaggedAddr`] that can be used to identify this entry's object.
    fn tagged_addr(&self) -> TaggedAddr {
        TaggedAddr {
            addr: self.obj.raw_addr(),
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
    /// Encode `self` into an rpc::ObjectId that we can give to a client.
    pub(crate) fn encode(self) -> rpc::ObjectId {
        self.encode_with_rng(&mut rand::thread_rng())
    }

    /// As `encode`, but take a Rng as an argument. For testing.
    fn encode_with_rng<R: rand::RngCore>(self, rng: &mut R) -> rpc::ObjectId {
        use base64ct::Encoding;
        use rand::Rng;
        use tor_bytes::Writer;
        let (a, b) = self.0.into_raw_parts();
        let x = rng.gen::<u64>();
        let mut bytes = Vec::new();
        bytes.write_u64(x);
        bytes.write_u64((a as u64).wrapping_add(x));
        bytes.write_u64(b.wrapping_sub(x));
        rpc::ObjectId::from(base64ct::Base64UrlUnpadded::encode_string(&bytes[..]))
    }

    /// Attempt to decode `id` into a `GenIdx` than an ObjMap can use.
    pub(crate) fn try_decode(id: &rpc::ObjectId) -> Result<Self, rpc::LookupError> {
        use base64ct::Encoding;
        use tor_bytes::Reader;

        let bytes = base64ct::Base64UrlUnpadded::decode_vec(id.as_ref())
            .map_err(|_| rpc::LookupError::NoObject(id.clone()))?;
        let mut r = Reader::from_slice(&bytes);
        let mut get_u64 = || {
            r.take_u64()
                .map_err(|_| rpc::LookupError::NoObject(id.clone()))
        };
        let x = get_u64()?;
        let a = get_u64()?;
        let b = get_u64()?;
        r.should_be_exhausted()
            .map_err(|_| rpc::LookupError::NoObject(id.clone()))?;

        let a = a.wrapping_sub(x) as usize;
        let b = b.wrapping_add(x);

        Ok(GenIdx(generational_arena::Index::from_raw_parts(a, b)))
    }
}

impl ObjMap {
    /// Create a new empty ObjMap.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reclaim unused space in this map.
    ///
    /// This runs in `O(n)` time.
    fn tidy(&mut self) {
        #[cfg(test)]
        {
            self.n_tidies += 1;
        }
        self.arena.retain(|index, entry| {
            let present = entry.is_present();
            if !present {
                // For everything we are removing from the `arena`, we must also
                // remove it from `reverse_map`.
                let ptr = entry.tagged_addr();
                let found = self.reverse_map.remove(&ptr);
                debug_assert_eq!(found, Some(GenIdx(index)));
            }
            present
        });
    }

    /// If needed, clean this arena and resize it.
    ///
    /// (We call this whenever we're about to add an entry.  This ensures that
    /// our insertion operations run in `O(1)` time.)
    fn adjust_size(&mut self) {
        // If we're about to fill the arena...
        if self.arena.len() >= self.arena.capacity() {
            // ... we delete any dead `Weak` entries.
            self.tidy();
            // Then, if the arena is still above half-full, we double the
            // capacity of the arena.
            //
            // (We have to grow the arena this even if tidy() removed _some_
            // entries, or else we might re-run tidy() too soon.  But we don't
            // want to grow the arena if tidy() removed _most_ entries, or some
            // normal usage patterns will lead to unbounded growth.)
            if self.arena.len() > self.arena.capacity() / 2 {
                self.arena.reserve(self.arena.capacity());
            }
        }
    }

    /// Unconditionally insert a strong entry for `value` in self, and return its index.
    pub(crate) fn insert_strong(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        self.adjust_size();

        GenIdx(self.arena.insert(ArenaEntry::new_strong(value)))
    }

    /// Ensure that there is a weak entry for `value` in self, and return an
    /// index for it.
    /// If there is no entry, create a weak entry.
    #[allow(clippy::needless_pass_by_value)] // TODO: Decide whether to make this take a reference.
    pub(crate) fn insert_weak(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        let ptr = TaggedAddr::for_object(&value);
        if let Some(idx) = self.reverse_map.get(&ptr) {
            #[cfg(debug_assertions)]
            match self.arena.get(idx.0) {
                Some(entry) => debug_assert!(entry.tagged_addr() == ptr),
                None => panic!("Found a dangling reference"),
            }
            return *idx;
        }

        self.adjust_size();

        let idx = GenIdx(self.arena.insert(ArenaEntry::new_weak(&value)));
        self.reverse_map.insert(ptr, idx);
        idx
    }

    /// Return the entry from this ObjMap for `idx`.
    pub(crate) fn lookup(&self, idx: GenIdx) -> Option<Arc<dyn rpc::Object>> {
        self.arena.get(idx.0).and_then(ArenaEntry::strong)
    }

    /// Remove the entry at `idx`, if any.
    pub(crate) fn remove(&mut self, idx: GenIdx) {
        if let Some(entry) = self.arena.remove(idx.0) {
            if entry.is_weak() {
                let old_idx = self.reverse_map.remove(&entry.tagged_addr());
                debug_assert_eq!(old_idx, Some(idx));
            }
        }
    }

    /// Testing only: Assert that every invariant for this structure is met.
    #[cfg(test)]
    fn assert_okay(&self) {
        for (index, entry) in self.arena.iter() {
            if !entry.is_weak() {
                continue;
            };
            let ptr = entry.tagged_addr();
            assert_eq!(self.reverse_map.get(&ptr), Some(&GenIdx(index)));
            assert_eq!(ptr, entry.tagged_addr());
        }

        for (ptr, idx) in self.reverse_map.iter() {
            let entry = self
                .arena
                .get(idx.0)
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[derive(Clone, Debug)]
    struct ExampleObject(String);
    impl rpc::Object for ExampleObject {}
    rpc::decl_object! {ExampleObject}
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

    #[derive(Clone, Debug)]
    #[repr(transparent)]
    struct Wrapper(ExampleObject);
    impl rpc::Object for Wrapper {}
    rpc::decl_object! {Wrapper}

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
        let mut s = vec![];
        let mut w = vec![];
        for _ in 0..100 {
            let mut t = vec![];
            for _ in 0..10 {
                let o = Arc::new(ExampleObject("dump".into()));
                w.push(map.insert_weak(o.clone()));
                t.push(o);
            }
            s.push(map.insert_strong(Arc::new(ExampleObject("cafe".into()))));
            drop(t);
            map.assert_okay();
        }

        assert_eq!(s.len(), 100);
        assert_eq!(w.len(), 1000);
        assert!(w.iter().all(|id| map.lookup(*id).is_none()));
        assert!(s.iter().all(|id| map.lookup(*id).is_some()));

        assert_ne!(dbg!(map.arena.len()), 1100);
        map.assert_okay();
        map.tidy();
        map.assert_okay();
        assert_eq!(map.arena.len(), 100);

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
        assert_eq!(map.arena.len(), 2);
    }

    #[test]
    fn objid_encoding() {
        use rand::Rng;
        fn test_roundtrip(a: usize, b: u64, rng: &mut tor_basic_utils::test_rng::TestingRng) {
            let idx = GenIdx(generational_arena::Index::from_raw_parts(a, b));
            let s1 = dbg!(idx.encode_with_rng(rng));
            let s2 = dbg!(idx.encode_with_rng(rng));
            assert_ne!(s1, s2);
            assert_eq!(idx, GenIdx::try_decode(&s1).unwrap());
            assert_eq!(idx, GenIdx::try_decode(&s2).unwrap());
        }
        let mut rng = tor_basic_utils::test_rng::testing_rng();

        test_roundtrip(0, 0, &mut rng);
        test_roundtrip(0, 1, &mut rng);
        test_roundtrip(1, 0, &mut rng);
        test_roundtrip(0xffffffff, 0xffffffffffffffff, &mut rng);

        for _ in 0..256 {
            test_roundtrip(rng.gen(), rng.gen(), &mut rng);
        }
    }
}
