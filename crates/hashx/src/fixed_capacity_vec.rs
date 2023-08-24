//! Module for the `FixedCapacityVec` data type
//!
//! TODO should probably become a crate?  We could miri it etc.

use std::alloc::{self, Layout};
use std::{mem, ptr};

/// Like `Vec` with a capacity fixed at compile time
///
/// When full, can be converted without copying into `Box<[T; N]>`, using `TryFrom`.
///
/// ### Comparison with related data types
///
/// All of the following types store only the actual buffer on the heap,
/// and they are interconvertible without copying the data.
//
// TODO ^ not actually quite true; we should impl Into<Vec< >>
// TODO ^ not actually quite true; we should impl TryFrom<Vec< >>
///
/// | Type          | Size and representation (as eg on stack)  | Full? | Mutability           |
/// |---------------|-----------------------------------------|----------|---------------|
/// | `Vec`         | 3 words: pointer, length, capacity | maybe | indefinitely appendable |
/// | `Box<[T]>`    | 2 words: pointer, length = capacity | always | length fixed at runtime |
/// | `FixedCapacityVec<[T; N]>` | 2 words: pointer, length | maybe | appendable, but capacity fixed at compile time |
/// | `Box<[T; N]>` | 1 word: pointer                    | always | length fixed at compile time |
//
// TODO we should impl Default
// TODO we should impl Deref and DerefMut to [T]
// TODO there should be from_raw_parts and into_raw_parts
// TODO we should impl Clone, Debug, Hash, Eq, Serialize, ...
pub(crate) struct FixedCapacityVec<T, const N: usize> {
    /// Data
    ///
    /// ### SAFETY
    ///
    /// Every element of data in 0..len must always be initialised.
    ///
    /// Always a valid, properly aligned, heap pointer to a `[T; N]`;
    /// except, during deconstruction it may be null.
    /// (Deconstruction means methods that consume the `FixedCapacityVec`;
    /// these must typically hand ownership of the allocation to someone else,
    /// but our `Drop::drop` impl will of course still run after that.)
    data: *mut T,

    /// Initialised portion
    ///
    /// **SAFETY**: See `data`
    len: usize,
}

impl<T, const N: usize> FixedCapacityVec<T, N> {
    /// Create a new empty `FixedCapacityVec`, capable of holding up to `N` values of type `T`
    #[inline]
    pub(crate) fn new() -> Self {
        // We really want Box::new_uninit() but that's unstable
        let data = unsafe {
            // SAFETY: the Layout is good since we got it from Layout::new
            let data: *mut u8 = alloc::alloc(Self::layout());
            let data: *mut T = data as _;
            data
        };

        FixedCapacityVec { data, len: 0 }
    }

    // Return the `Layout` for our `data` pointer allocation
    fn layout() -> Layout {
        Layout::new::<[T; N]>()
    }

    /// Return the number of values stored so far
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` iff the `FixedCapacityVec` is empty
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` iff the `FixedCapacityVec` is full - ie, it has `N` elements
    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append an element
    ///
    /// # Panics
    ///
    /// Panics if the `FixedCapacityVec` is full, ie if it already contains `N` elements
    #[inline]
    // TODO there should be a panic-free try_push
    pub(crate) fn push(&mut self, item: T) {
        unsafe {
            assert!(self.len < N);
            // SAFETY now len is within bounds and the pointer is aligned
            // len can't be more than would imply isize, since N can't, so the conversion is fine
            self.data.offset(self.len as isize).write(item);
            // SAFETY now that the value is written, we can say it's there
            self.len += 1;
        }
    }

    // TODO there should be pop and try_pop
}

impl<T, const N: usize> Drop for FixedCapacityVec<T, N> {
    #[inline]
    fn drop(&mut self) {
        if !self.data.is_null() {
            unsafe {
                // SAFETY
                //
                // We are maybe in a deconstructor, but we have checked len and data,
                // so data is valid and aligned and elements up to len are initialised.
                //
                // We are about to break the invariants!  This is OK, because it cannot
                // be observed by anyone: we have &mut Self, so no-one else can see it,
                // and even if a panic unwinds from here, `self` will no longer be considered
                // valid by the language.
                if mem::needs_drop::<T>() {
                    let data: *mut [T] = ptr::slice_from_raw_parts_mut(self.data, self.len);
                    // This causes the supposedly-valid portion of data to become totally
                    // invalid, breaking the invariants.  See above.
                    ptr::drop_in_place(data);
                }
                // SAFETY: this causes self.data to become totally invalid, breaking
                // the invariants.  That's OK; see above.
                alloc::dealloc(self.data as _, Self::layout());
            }
        }
    }
}

/// Convert a full `FixedCapacityVec` into a boxed array.
///
/// If the `FixedCapacityVec` isn't full, it is returned as the `Err`
impl<T, const N: usize> TryFrom<FixedCapacityVec<T, N>> for Box<[T; N]> {
    type Error = FixedCapacityVec<T, N>;

    #[inline]
    fn try_from(mut fcvec: FixedCapacityVec<T, N>) -> Result<Box<[T; N]>, FixedCapacityVec<T, N>> {
        if fcvec.len == N {
            Ok(unsafe {
                // SAFETY
                // We are about to make ptr invalid so we must zero len
                fcvec.len = 0;
                let data: *mut T = mem::replace(&mut fcvec.data, ptr::null_mut());
                // It always was such a valid pointer
                let data: *mut [T; N] = data as _;
                // We have checked that every element is initialised
                // The pointer isn't null since *we* are the deconstructor
                let data: Box<[T; N]> = Box::from_raw(data);
                data
            })
        } else {
            Err(fcvec)
        }
    }
}

