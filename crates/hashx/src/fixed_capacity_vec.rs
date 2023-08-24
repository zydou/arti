//! Module for the `FixedCapacityVec` data type
//!
//! TODO should probably become a crate?  We could miri it etc.

use std::mem::{self, MaybeUninit};

/// Like `Vec` with a capacity fixed at compile time
///
/// When full, can be converted without copying into `Box<[T; N]>`, using `TryFrom`.
///
/// ### Comparison with related data types
///
/// All of the following types store only the actual buffer on the heap,
/// and they are interconvertible without copying the data.
///
/// | Type          | Size and representation (as eg on stack)  | Full? | Mutability           |
/// |---------------|-----------------------------------------|----------|---------------|
/// | `Vec`         | 3 words: pointer, length, capacity | maybe | indefinitely appendable |
/// | `Box<[T]>`    | 2 words: pointer, length = capacity | always | length fixed at runtime |
/// | `FixedCapacityVec<[T; N]>` | 2 words: pointer, length | maybe | appendable, but capacity fixed at compile time |
/// | `Box<[T; N]>` | 1 word: pointer                    | always | length fixed at compile time |
pub(crate) struct FixedCapacityVec<T, const N: usize> {
    /// Data
    ///
    /// **SAFETY**: see `len`.
    slice: Box<[MaybeUninit<T>; N]>,

    /// Initialised portion
    ///
    /// **SAFETY**:
    /// Every element of slice in 0..len must be initialised.
    len: usize,
}

impl<T, const N: usize> FixedCapacityVec<T, N> {
    /// Create a new empty `FixedCapacityVec`, capable of holding up to `N` values of type `T`
    #[inline]
    pub(crate) fn new() -> Self {
        // We really want Box::new_uninit() but that's unstable
        let slice = unsafe {
            use std::alloc::Layout;

            type Array<T, const N: usize> = [MaybeUninit<T>; N];
            // SAFETY: the Layout is good since we got it from Layout::new
            let slice: *mut u8 = std::alloc::alloc(Layout::new::<Array<T, N>>());
            let slice: *mut Array<T, N> = slice as _;
            // SAFETY: the pointer is properly aligned and valid since we got it from alloc
            // SAFETY: value is valid Array despite not being initialised because MaybeUninit
            let slice: Box<Array<T, N>> = Box::from_raw(slice);
            slice
        };

        FixedCapacityVec { slice, len: 0 }
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
    pub(crate) fn push(&mut self, item: T) {
        let ent = &mut self.slice[self.len]; // panics if out of bounds
        *ent = MaybeUninit::new(item);
        self.len += 1;
    }
}

/// Convert a full `FixedCapacityVec` into a boxed array.
///
/// If the `FixedCapacityVec` isn't full, it is returned as the `Err`
impl<T, const N: usize> TryFrom<FixedCapacityVec<T, N>> for Box<[T; N]> {
    type Error = FixedCapacityVec<T, N>;

    #[inline]
    fn try_from(fcvec: FixedCapacityVec<T, N>) -> Result<Box<[T; N]>, FixedCapacityVec<T, N>> {
        if fcvec.len == N {
            Ok(unsafe {
                // SAFETY
                // We have checked that every element is initialised
                let slice: Box<[MaybeUninit<T>; N]> = fcvec.slice;
                let array: Box<[T; N]> = mem::transmute(slice);
                array
            })
        } else {
            Err(fcvec)
        }
    }
}

