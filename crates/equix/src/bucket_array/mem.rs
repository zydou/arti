//! Memory management internals for the bucket array
//!
//! The solver needs sparse arrays of sorting buckets as temporary space. To
//! minimize peak memory usage, we need to dynamically reallocate portions
//! of that space between usages. A naive solution could use a separate Vec for
//! each array of bucket keys/values. A quick benchmark confirms that this is
//! between 2% and 10% worse than if the solver could use a single block of
//! memory with predetermined packed layout.
//!
//! Using a static layout presents some challenges in initialization, since the
//! entire struct is now too large to fit on the stack reliably. Creating an
//! instance using Box::new() would cause a stack overflow.
//!
//! We can solve several of these problems by orienting the data structure
//! around MaybeUninit memory: No initialization needed, we can easily switch
//! between space layouts using a union without risk of transmuting live values,
//! and we avoid an additional redundant zeroing of memory.
//!
//! This module provides a trait, [`Uninit`], for memory that we can safely
//! treat as uninitialized when it isn't being used. We track that use via a
//! mutable reference, so that gives us mutually exclusive access enforced at
//! compile-time.
//!
//! That uninitialized memory can be used to build backing layouts that are
//! made from instances of [`BucketArrayMemory`]. The whole backing layout is
//! then instantiated using freshly allocated uninitialized memory.
//!
//! A [`BucketArrayMemory`] can be temporarily, using a mutable reference,
//! wrapped into a [`BucketArray`] or half of a [`BucketArrayPair`].
//! Internally, a [`BucketState`] tracks how many items are in each bucket.
//! The only supported write operation is appending to an underfull bucket.
//! Once initialized by such a write, bucket items may be randomly accessed
//! via the methods on the [`BucketArray`] or [`BucketArrayPair`].
//!
//! It's critical for memory safety that we only read from a [`MaybeUninit`]
//! that has definitely been initialized. The static lifetimes of the mutable
//! reference and our `counts` array ensure we always start out with zeroed
//! counts and fully assumed-uninitialized memory. Our write method must be
//! certain to never increment the counter without actually writing to the
//! [`MaybeUninit`]. See [`BucketState::insert`].

// We need to allow this warning because we conditionally make some private
// functions public, but their documentation links to private types.
#![allow(rustdoc::private_intra_doc_links)]

use num_traits::{One, Zero};
use std::alloc;
use std::mem::MaybeUninit;
use std::ops::{Add, Range};

/// Marker trait for types that are normally assumed uninitialized
///
/// # Safety
///
/// By implementing this trait, it's a guarantee that uninitialized memory
/// may be transmuted into this type safely. It implies that the type is `Copy`.
/// It should contain no bits except for [`MaybeUninit`] fields. Structs and
/// arrays made entirely of [`MaybeUninit`] are fine.
///
/// This memory is always assumed to be uninitialized unless we hold a mutable
/// reference that's associated with information about specific fields that
/// were initialized during the reference's lifetime.
#[cfg_attr(feature = "bucket-array", visibility::make(pub))]
pub(crate) unsafe trait Uninit: Copy {
    /// Allocate new uninitialized memory, returning a new Box.
    fn alloc() -> Box<Self> {
        // SAFETY: Any type implementing Uninit guarantees that creating an
        //         instance from uninitialized memory is sound. We pass this
        //         pointer's ownership immediately to Box.
        unsafe {
            let layout = alloc::Layout::new::<Self>();
            let ptr: *mut Self = std::mem::transmute(alloc::alloc(layout));
            Box::from_raw(ptr)
        }
    }
}

/// Backing memory for a single key or value bucket array
///
/// Describes `N` buckets which each hold at most `M` items of type `T`.
///
/// Implements [`Uninit`]. Structs and unions made from `BucketArrayMemory`
/// can be soundly marked as [`Uninit`].
#[cfg_attr(feature = "bucket-array", visibility::make(pub))]
#[derive(Copy, Clone)]
pub(crate) struct BucketArrayMemory<
    // Number of buckets
    const N: usize,
    // Number of item slots in each bucket
    const M: usize,
    // Item type
    T: Copy,
>([[MaybeUninit<T>; M]; N]);

/// Implements the [`Uninit`] trait. This memory is always assumed to be
/// uninitialized unless we hold a mutable reference paired with bucket
/// usage information.
///
/// SAFETY: We can implement [`Uninit`] for [`BucketArrayMemory`]
///         because it's `Copy` and it contains only `MaybeUninit` bits.
unsafe impl<const N: usize, const M: usize, T: Copy> Uninit for BucketArrayMemory<N, M, T> {}

/// Types that can be used as a count of items in a bucket
#[cfg_attr(feature = "bucket-array", visibility::make(pub))]
pub(crate) trait Count: Copy + Zero + One + Into<usize> + Add<Self, Output = Self> {}

impl<T: Copy + Zero + One + Into<usize> + Add<Self, Output = Self>> Count for T {}

/// Common implementation for key/value and value-only bucket arrays
///
/// Tracks the number of items in each bucket. This is used by [`BucketArray`]
/// and [`BucketArrayPair`] implementations to safely access only initialized
/// items in the [`BucketArrayMemory`].
struct BucketState<
    // Number of buckets
    const N: usize,
    // Maximum number of items per bucket
    const CAP: usize,
    // Type for bucket item counts
    C: Count,
> {
    /// Number of initialized items in each bucket
    ///
    /// Each bucket B's valid item range would be `(0 .. counts[B])`
    counts: [C; N],
}

impl<const N: usize, const CAP: usize, C: Count> BucketState<N, CAP, C> {
    /// Create a new counter store.
    ///
    /// This will happen inside the lifetime of our mutable reference
    /// to the backing store memory.
    fn new() -> Self {
        Self {
            counts: [C::zero(); N],
        }
    }

    /// Append a new item to a specific bucket using a writer callback.
    ///
    /// The writer is invoked with an item index, after checking
    /// bucket capacity but before marking the new item as written.
    ///
    /// The writer must unconditionally write to the index it's given, in
    /// each of the backing memories covered by this state tracker.
    #[inline(always)]
    fn insert<F: FnMut(usize)>(&mut self, bucket: usize, mut writer: F) -> Result<(), ()> {
        let item_count = self.counts[bucket];
        let count_usize: usize = item_count.into();
        if count_usize < CAP {
            writer(count_usize);
            self.counts[bucket] = item_count + C::one();
            Ok(())
        } else {
            Err(())
        }
    }

    /// Look up the valid item range for a particular bucket.
    ///
    /// Panics if the bucket index is out of range. Item indices inside the
    /// returned range are initialized, and any outside may be uninitialized.
    #[inline(always)]
    fn item_range(&self, bucket: usize) -> Range<usize> {
        0..self.counts[bucket].into()
    }
}

/// Concrete binding between one [`BucketState`] and one [`BucketArrayMemory`]
#[cfg_attr(feature = "bucket-array", visibility::make(pub))]
pub(crate) struct BucketArray<
    // Lifetime for mutable reference to the backing memory
    'a,
    // Number of buckets
    const N: usize,
    // Maximum number of items per bucket
    const CAP: usize,
    // Type for bucket item counts
    C: Count,
    // Item type
    A: Copy,
> {
    /// Reference to external backing memory for type A
    mem: &'a mut BucketArrayMemory<N, CAP, A>,
    /// Tracking for which items are in use within each bucket
    state: BucketState<N, CAP, C>,
}

impl<'a, const N: usize, const CAP: usize, C: Count, A: Copy> BucketArray<'a, N, CAP, C, A> {
    /// A new [`BucketArray`] wraps a new [`BucketState`] and some possibly-recycled [`BucketArrayMemory`]
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    pub(crate) fn new(mem: &'a mut BucketArrayMemory<N, CAP, A>) -> Self {
        Self {
            mem,
            state: BucketState::new(),
        }
    }

    /// Look up the valid item range for a particular bucket.
    ///
    /// Panics if the bucket index is out of range.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    #[inline(always)]
    pub(crate) fn item_range(&self, bucket: usize) -> Range<usize> {
        self.state.item_range(bucket)
    }

    /// Look up the value of one item in one bucket.
    ///
    /// Panics if the indices are out of range.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    #[inline(always)]
    pub(crate) fn item_value(&self, bucket: usize, item: usize) -> A {
        assert!(self.state.item_range(bucket).contains(&item));
        // SAFETY: This requires that our [`BucketState`] instance accurately
        //         represents which fields in [`mem`] have been initialized.
        unsafe { self.mem.0[bucket][item].assume_init() }
    }

    /// Append a new item to a bucket.
    ///
    /// If the bucket is full, returns `Err(())` and makes no changes.
    #[cfg_attr(
        feature = "bucket-array",
        visibility::make(pub),
        allow(clippy::result_unit_err)
    )]
    #[inline(always)]
    pub(crate) fn insert(&mut self, bucket: usize, value: A) -> Result<(), ()> {
        self.state.insert(bucket, |item| {
            self.mem.0[bucket][item].write(value);
        })
    }
}

/// Concrete binding between one [`BucketState`] and a pair of [`BucketArrayMemory`]
#[cfg_attr(feature = "bucket-array", visibility::make(pub))]
pub(crate) struct BucketArrayPair<
    // Lifetime for mutable reference to the first backing memory
    'a,
    // Lifetime for mutable reference to the second backing memory
    'b,
    // Number of buckets
    const N: usize,
    // Maximum number of items per bucket
    const CAP: usize,
    // Type for bucket item counts
    C: Count,
    // Type for items in the first backing memory
    A: Copy,
    // Type for items in the second backing memory
    B: Copy,
> {
    /// Reference to external backing memory for type `A`
    mem_a: &'a mut BucketArrayMemory<N, CAP, A>,
    /// Reference to external backing memory for type `B`
    mem_b: &'b mut BucketArrayMemory<N, CAP, B>,
    /// Tracking for which items are in use within each bucket
    state: BucketState<N, CAP, C>,
}

impl<'a, 'b, const N: usize, const CAP: usize, C: Count, A: Copy, B: Copy>
    BucketArrayPair<'a, 'b, N, CAP, C, A, B>
{
    /// A new [`BucketArray`] wraps a new [`BucketState`] and two [`BucketArrayMemory`]
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    pub(crate) fn new(
        mem_a: &'a mut BucketArrayMemory<N, CAP, A>,
        mem_b: &'b mut BucketArrayMemory<N, CAP, B>,
    ) -> Self {
        Self {
            mem_a,
            mem_b,
            state: BucketState::new(),
        }
    }

    /// Look up the valid item range for a particular bucket.
    ///
    /// Panics if the bucket index is out of range.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    #[inline(always)]
    pub(crate) fn item_range(&self, bucket: usize) -> Range<usize> {
        self.state.item_range(bucket)
    }

    /// Look up the first value for one item in one bucket.
    ///
    /// Panics if the indices are out of range.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    #[inline(always)]
    pub(crate) fn item_value_first(&self, bucket: usize, item: usize) -> A {
        assert!(self.state.item_range(bucket).contains(&item));
        // SAFETY: This requires that our [`BucketState`] instance accurately
        //         represents which fields in [`mem`] have been initialized.
        unsafe { self.mem_a.0[bucket][item].assume_init() }
    }

    /// Look up the second value for one item in one bucket.
    ///
    /// Panics if the indices are out of range.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    #[inline(always)]
    pub(crate) fn item_value_second(&self, bucket: usize, item: usize) -> B {
        assert!(self.state.item_range(bucket).contains(&item));
        // SAFETY: This requires that our [`BucketState`] instance accurately
        //         represents which fields in [`mem`] have been initialized.
        unsafe { self.mem_b.0[bucket][item].assume_init() }
    }

    /// Append a new item pair to a bucket.
    ///
    /// If the bucket is full, returns Err(()) and makes no changes.
    #[cfg_attr(
        feature = "bucket-array",
        visibility::make(pub),
        allow(clippy::result_unit_err)
    )]
    #[inline(always)]
    pub(crate) fn insert(&mut self, bucket: usize, first: A, second: B) -> Result<(), ()> {
        self.state.insert(bucket, |item| {
            self.mem_a.0[bucket][item].write(first);
            self.mem_b.0[bucket][item].write(second);
        })
    }

    /// Transfer the [`BucketState`] to a new single [`BucketArray`],
    /// keeping the second half and dropping the first.
    #[cfg_attr(feature = "bucket-array", visibility::make(pub))]
    pub(crate) fn drop_first(self) -> BucketArray<'b, N, CAP, C, B> {
        BucketArray {
            mem: self.mem_b,
            state: self.state,
        }
    }
}
