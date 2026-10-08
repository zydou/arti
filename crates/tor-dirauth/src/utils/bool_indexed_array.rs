//! `BoolIndexedArray`

use super::*;

/// Array of two values, one for `false` and one for `true`
///
/// This is a wrapper around `[T; 2]`, which views the array as being indexed by `bool`.
///
/// Can be constructed from a `[T; 2]` using `From`.
/// Implements `Default` if `T` is `Default`.
///
/// Ordering compares first the `true` value, then the `false` one.
//
// We use tuple rather than array, because in Rust an array is always better than a tuple
// if the values are known to be of the same type.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash)] //
#[derive(derive_more::Into, derive_more::From)]
// TODO move this somewhere else maybe? flesh out this API?
pub(crate) struct BoolIndexedArray<T>([T; 2]);

impl<T> std::ops::Index<bool> for BoolIndexedArray<T> {
    type Output = T;
    fn index(&self, b: bool) -> &T {
        &self.0[usize::from(b)]
    }
}
impl<T> std::ops::IndexMut<bool> for BoolIndexedArray<T> {
    fn index_mut(&mut self, b: bool) -> &mut T {
        &mut self.0[usize::from(b)]
    }
}

impl<T> BoolIndexedArray<T> {
    /// Treating this as a vote tally, are there (strictly) more yeses than noes?
    pub(crate) fn more_yes_than_no(&self) -> bool
    where
        T: Ord,
    {
        self[true] > self[false]
    }
}
