//! Helpers for reference counting
//!
//! Two main purposes:
//!
//!  * Consistent handling of overflow and underflow
//!  * Assurance of incrementing/decrementing as appropriate,
//!    including in combination with a slotmap containing the referenced data.
//!
//! The caller is responsible for making sure that the *right instance*'s
//! [`Count`] is passed to the methods on [`Ref`].
//
// There are no separate tests for this module.  Many of the tests would want to
// exercise the `Ref`s drop bomb, which is troublesome since it's panic in drop,
// which they're making Rust treat as an abort upstream.
// (This scheme did detect a bug or two during development testing,
// so the drop bomb is known to work.)
//
// Anyway, these functions are mostly newtype veneers over existing functionality.
// They're tested by the MemoryQuotaTracker's tests.

use crate::internal_prelude::*;

/// Local alias for the counter type
pub(crate) type RawCount = u32;

/// Decrement a refcount and maybe remove a corresponding slotmap entry
///
/// ```rust,ignore
/// fn slotmap_dec_ref!<K, V>(
///    slotmap: &mut SlotMap<K, V>,
///    ref_: Ref<K>,
///    refcount: &mut Count<K>, // (typically) borrows from slotmap
/// )
/// ```
//
// This macro is a bit out-of-position, up here, because we want to be able to link
// to it in our rustdocs.
macro_rules! slotmap_dec_ref { { $slotmap:expr, $ref_:expr, $refcount:expr } => { { {
    use $crate::refcount::*;
    let key: Ref<_> = $ref_;
    let refcount: &mut Count<_> = $refcount;
    if let Some(Garbage(key)) = key.dispose(refcount) {
        let slotmap: &mut SlotMap<_, _> = $slotmap;
        let removed = slotmap.remove(key).expect("entry vanished or wrong key passed?!");
        Some(Garbage(removed))
    } else {
        None
    }
} } } }

/// A reference count, counting references with id type `K`
#[derive(Default, Educe, Ord, PartialOrd, Eq, PartialEq, Deref)]
#[educe(Debug)]
pub(crate) struct Count<K> {
    /// Actual count of references
    #[deref]
    count: RawCount,
    /// Bind to the specific key type
    // K is generally Send + Sync + 'static so we don't care about variance etc.
    #[educe(Debug(ignore))]
    marker: PhantomData<K>,
}

/// An copy of a [`slotmap::Key`] `K`, which is counted by a `RefCount`
///
/// Ie, a key of type `K` with the property that it
/// keeps the refcounted data structure alive.
///
/// Must always be deleted using [`dispose`](Ref::dispose), not dropped.
/// In tests, dropping a `RefCounted` will panic.
///
/// The `Default` value does *not* contribute to a reference count,
/// and is fine to drop.
#[derive(Deref, Educe)]
#[educe(Debug, Default, Ord, Eq, PartialEq)]
pub(crate) struct Ref<K: slotmap::Key> {
    /// Actual key (without generics)
    #[deref]
    raw_key: K,
    /// Bind to the specific key type
    #[educe(Debug(ignore))]
    marker: PhantomData<K>,
    /// Drop bomb
    ///
    /// Also forces `Ref` not to be Clone
    #[educe(Debug(ignore), Ord(ignore), Eq(ignore), PartialEq(ignore))]
    #[allow(dead_code)]
    bomb: DropBombCondition,
}

// educe's Ord is open-coded and triggers clippy::non_canonical_partial_ord_impl
impl<K: slotmap::Key> PartialOrd for Ref<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Ideally we'd assert_not_impl on Ref but it has generics
assert_not_impl_any!(DropBombCondition: Clone);

/// Error: refcount overflowed
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("memory tracking refcount overflowed")]
pub(crate) struct Overflow;

/// Something which has become garbage
///
/// Often used within `Option`, for clarity.  Examples:
///
///  * Key whose reference count has reached zero - see [`Ref::dispose`]
///  * Value removed from a SlotMap - see [`slotmap_dec_ref!`]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Garbage<K>(pub(crate) K);

impl<K> Count<K> {
    /// Make a new refcount with a specified value
    const fn new_raw(count: RawCount) -> Self {
        Count {
            count,
            marker: PhantomData,
        }
    }

    /// Obtain this counter as a `usize`
    ///
    /// (Reference counts are `u32`, so this might be a conversion.)
    pub(crate) fn as_usize(&self) -> usize {
        // On a 16-bit platform this could theoretically overflow,
        // but there would have to be >2^16 clones, which would be impossible.
        let r: u32 = **self;
        r as usize
    }
}

/// Increment this refcount, but don't care about any [`Ref`]s
fn inc_raw(c: &mut RawCount) -> Result<(), Overflow> {
    *c = c.checked_add(1).ok_or(Overflow)?;
    Ok(())
}

/// Decrement this refcount, but don't care about any [`Ref`]s
///
/// Returns [`Some(Garbage(()))`] if the count reached zero
fn dec_raw(c: &mut RawCount) -> Option<Garbage<()>> {
    *c = c
        .checked_sub(1)
        // if this happens, our data structure is corrupted, very bad
        .expect("refcount underflow");
    (*c == 0).then_some(Garbage(()))
}

impl<K: slotmap::Key> Ref<K> {
    /// Create a refcounted reference `Ref` from an un-counted key, incrementing the count
    pub(crate) fn new(key: K, count: &mut Count<K>) -> Result<Self, Overflow> {
        inc_raw(&mut count.count)?;
        Ok(Ref::from_raw(key))
    }

    /// Creates a null `Ref`, which doesn't refer to any slot (lookups always give `None`)
    pub(crate) fn null() -> Self {
        Ref::from_raw(K::null())
    }

    /// Internal function for creating a `Ref`
    fn from_raw(raw_key: K) -> Self {
        Ref {
            raw_key,
            marker: PhantomData,
            bomb: DropBombCondition::new_armed(),
        }
    }

    /// Dispose of a refcounted reference `Ref`, decrementing the count
    ///
    /// If the count reaches zero, the raw key is returned;
    /// the caller should remove the corresponding data from the data structure.
    pub(crate) fn dispose(mut self, refcount: &mut Count<K>) -> Option<Garbage<K>> {
        let was = mem::take(&mut self.raw_key);
        assert!(!was.is_null());
        dec_raw(&mut refcount.count).map(|_: Garbage<()>| Garbage(was))
    }

    /// Dispose of a refcounted reference whose container no longer exists
    ///
    /// # CORRECTNESS
    ///
    /// This just forgets the reference, without decrementing any refcount.
    /// If the container *does* still exist, a ref count ref will be leaked.
    pub(crate) fn dispose_container_destroyed(mut self) {
        let _: K = mem::take(&mut self.raw_key);
    }
}

impl<K: slotmap::Key> DefaultExtTake for Ref<K> {}

/// Insert a new entry into a slotmap using refcounted keys
///
/// `value_maker` should take the provided `Count`,
/// and incorporate it into a new value.
///
/// On return, the entry will be in the map, and there will be one reference,
/// which is returned.
///
/// There is no corresponding `slotmap_remove` in this module.
/// Use [`Ref::dispose`] and handle any [`Garbage`] it returns.
pub(crate) fn slotmap_insert<K: slotmap::Key, V>(
    slotmap: &mut SlotMap<K, V>,
    value_maker: impl FnOnce(Count<K>) -> V,
) -> Ref<K> {
    let (ref_, ()) = slotmap_try_insert(slotmap, move |refcount| {
        Ok::<_, Void>((value_maker(refcount), ()))
    })
    .void_unwrap();
    ref_
}

/// Insert a new entry into a slotmap using refcounted keys, fallibly and with extra data
///
/// Like [`slotmap_insert`] but:
///  * `value_maker` can also return extra return data `RD` to the caller
///  * `value_maker` is allowed to fail.
///
/// On successful return, the entry will be in the map, and
/// the new `Ref` is returned along with the data `D`.
pub(crate) fn slotmap_try_insert<K: slotmap::Key, V, E, RD>(
    slotmap: &mut SlotMap<K, V>,
    value_maker: impl FnOnce(Count<K>) -> Result<(V, RD), E>,
) -> Result<(Ref<K>, RD), E> {
    let refcount = Count::new_raw(1);
    let (value, data) = value_maker(refcount)?;
    let raw_key = slotmap.insert(value);
    let ref_ = Ref {
        raw_key,
        marker: PhantomData,
        bomb: DropBombCondition::new_armed(),
    };
    Ok((ref_, data))
}

#[cfg(test)]
impl<K: slotmap::Key> Drop for Ref<K> {
    fn drop(&mut self) {
        drop_bomb_disarm_assert!(self.bomb, self.raw_key.is_null(),);
    }
}

impl From<Overflow> for Error {
    fn from(_overflow: Overflow) -> Error {
        internal!("reference count overflow in memory tracking (out-of-control subsystem?)").into()
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
    #![allow(clippy::let_and_return)] // TODO this lint is annoying and we should disable it

    use super::*;

    slotmap::new_key_type! {
        struct Id;
    }
    #[derive(Eq, PartialEq, Debug)]
    struct Record {
        refcount: Count<Id>,
    }
    type Map = SlotMap<Id, Record>;

    fn setup() -> (Map, Ref<Id>) {
        let mut map = Map::default();
        let ref_ = slotmap_insert(&mut map, |refcount| Record { refcount });
        (map, ref_)
    }

    #[test]
    fn good() {
        let (mut map, ref1) = setup();

        let ent = map.get_mut(*ref1).unwrap();
        let ref2 = Ref::new(*ref1, &mut ent.refcount).unwrap();

        let g1: Option<Garbage<Record>> = slotmap_dec_ref!(&mut map, ref1, &mut ent.refcount);
        assert_eq!(g1, None);

        let ent = map.get_mut(*ref2).unwrap();
        let g2: Option<Garbage<Record>> = slotmap_dec_ref!(&mut map, ref2, &mut ent.refcount);
        assert!(g2.is_some());
    }

    #[test]
    fn try_insert_fail() {
        let mut map = Map::default();
        let () = slotmap_try_insert::<_, _, _, String>(&mut map, |_refcount| Err(())).unwrap_err();
    }

    #[test]
    fn drop_ref_without_decrement() {
        let (_map, mut ref1) = setup();
        let h = ref1.bomb.make_simulated();
        drop(ref1);
        h.expect_exploded();
    }
}
