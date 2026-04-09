//! An object mapper for looking up `rpc::Object`s by ID.
//!
//! This mapper stores strong or weak references, and uses a generational index
//! to keep track of names for them.
//!
//! TODO RPC: Add an object diagram here once the implementation settles down.

use std::sync::Arc;

use slotmap_careful::{Key as _, KeyData, SlotMap};
use tor_rpcbase as rpc;

pub(crate) mod methods;

slotmap_careful::new_key_type! {
    pub(crate) struct GenIdx;

}

/// A mechanism to look up RPC `Objects` by their `ObjectId`.
#[derive(Default)]
pub(crate) struct ObjMap {
    /// Generationally indexed arena of strong object references.
    // XXXX rename.
    strong_arena: SlotMap<GenIdx, Arc<dyn rpc::Object>>,
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

    /// Encode `self` into an rpc::ObjectId that we can give to a client.
    pub(crate) fn encode(self) -> rpc::ObjectId {
        self.encode_with_rng(&mut rand::rng())
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
        let ffi_idx = self.data().as_ffi();
        let x = rng.random::<u64>();
        let mut bytes = Vec::with_capacity(Self::BYTE_LEN);
        bytes.write_u64(x);
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
        let ffi_idx = r.take_u64().ok()?;
        r.should_be_exhausted().ok()?;

        let ffi_idx = ffi_idx.wrapping_sub(x);
        Some(GenIdx::from(KeyData::from_ffi(ffi_idx)))
    }
}

impl ObjMap {
    /// Create a new empty ObjMap.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Unconditionally insert a strong entry for `value` in self, and return its index.
    pub(crate) fn insert_strong(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        self.strong_arena.insert(value)
    }

    /// Unconditionally insert a weak entry for `value` in self, and return its index.
    #[allow(dead_code)] // XXXX
    pub(crate) fn insert_weak(&mut self, value: Arc<dyn rpc::Object>) -> GenIdx {
        // XXXX todo; make this actually weak.
        self.strong_arena.insert(value)
    }

    /// Return the entry from this ObjMap for `idx`.
    pub(crate) fn lookup(&self, idx: GenIdx) -> Option<Arc<dyn rpc::Object>> {
        self.strong_arena.get(idx).cloned()
    }

    /// Remove and return the entry at `idx`, if any.
    pub(crate) fn remove(&mut self, idx: GenIdx) -> Option<Arc<dyn rpc::Object>> {
        self.strong_arena.remove(idx)
    }

    /// Testing only: Assert that every invariant for this structure is met.
    #[cfg(test)]
    fn assert_okay(&self) {}
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use derive_deftly::Deftly;
    use tor_rpcbase::templates::*;

    #[derive(Clone, Debug, Deftly)]
    #[derive_deftly(Object)]
    struct ExampleObject(#[allow(unused)] String);

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

    /*
    #[cfg(feature = "weakref")] // XXXX restore
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

    #[cfg(feature = "weakref")] // XXXX restore
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
        #[cfg(feature = "weakref")]
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
    */

    #[test]
    fn map_basics() {
        // Insert an object, make sure it gets inserted twice, and look it up.
        let obj1 = Arc::new(ExampleObject("abcdef".to_string()));
        let mut map = ObjMap::new();
        map.assert_okay();
        let id1 = map.insert_strong(obj1.clone());
        let id2 = map.insert_strong(obj1.clone());
        assert_ne!(id1, id2);
        let obj1: Arc<dyn rpc::Object> = obj1;
        let obj_out1 = map.lookup(id1).unwrap();
        let obj_out2 = map.lookup(id2).unwrap();
        assert!(Arc::ptr_eq(&obj1, &obj_out1));
        assert!(Arc::ptr_eq(&obj1, &obj_out2));
        map.assert_okay();

        map.remove(id1);
        assert!(map.lookup(id1).is_none());
        let obj_out2b = map.lookup(id2).unwrap();
        assert!(Arc::ptr_eq(&obj_out2, &obj_out2b));

        map.assert_okay();
    }

    /*
    #[cfg(feature = "weakref")] // XXXX restore
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

    #[cfg(feature = "weakref")] // XXXX restore
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

    #[cfg(feature = "weakref")] // XXXX restore
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

    #[cfg(feature = "weakref")] // XXXX restore
    #[test]
    fn upgrade() {
        // Make sure that inserting an object as weak and strong (in either
        // order) makes two separate entries.
        let obj1: Arc<dyn rpc::Object> = Arc::new(ExampleObject("hello".to_string()));
        let obj2: Arc<dyn rpc::Object> = Arc::new(ExampleObject("world".to_string()));

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
        assert!(Arc::ptr_eq(&obj1, &out1));
        assert!(Arc::ptr_eq(&obj2, &out2));
    }

    #[cfg(feature = "weakref")]
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

        map.assert_okay();

        // This number is a bit arbitrary.
        assert!(dbg!(map.n_tidies) < 30);
    }
    */

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
            let data = KeyData::from_ffi((a << 33) | (1_u64 << 32) | b);
            let idx = GenIdx::from(data);
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
            test_roundtrip(rng.random(), rng.random(), &mut rng);
        }
    }
}
