//! Representation and validation of Equi-X puzzle solutions
//!
//! Equi-X uses its own tweaked version of the Equihash algorithm. Solutions
//! are arrays of [`SolutionItem`]s, each representing one item in a space of
//! hash outputs. The `SolutionItem`s form a binary tree with constraints
//! on the sorting order of the items and on the sums of their corresponding
//! hashes.

use crate::Error;
use arrayvec::ArrayVec;
use hashx::HashX;
use std::{cmp, mem};

/// Equihash N parameter for Equi-X, number of bits used from the hash output
pub(crate) const EQUIHASH_N: usize = 60;

/// Equihash K parameter for Equi-X, the number of tree layers
pub(crate) const EQUIHASH_K: usize = 3;

/// One item in the solution
///
/// The Equihash paper also calls these "indices", to reference the way they
/// index into a space of potential hash outputs. They form the leaf nodes in
/// a binary tree of hashes.
pub type SolutionItem = u16;

/// One hash value, computed from a [`SolutionItem`]
///
/// Must hold [`EQUIHASH_N`] bits.
pub(crate) type HashValue = u64;

/// Compute a [`HashValue`] from a [`SolutionItem`]
#[inline(always)]
pub(crate) fn item_hash(func: &HashX, item: SolutionItem) -> HashValue {
    func.hash_to_u64(item.into())
}

/// A bundle of solutions as returned by one invocation of the solver
///
/// The actual number of solutions found is random, depending on the number of
/// collisions that exist. This size is arbitrary, and in the rare case that
/// the solver finds more solutions they are discarded.
pub type SolutionArray = ArrayVec<Solution, 8>;

/// A raw Item array which may or may not be a well-formed [`Solution`]
pub type SolutionItemArray = [SolutionItem; Solution::NUM_ITEMS];

/// A byte array of the right length to convert to/from a [`Solution`]
pub type SolutionByteArray = [u8; Solution::NUM_BYTES];

/// Potential solution to an EquiX puzzle
///
/// The `Solution` type itself verifies the well-formedness of an Equi-X
/// solution, but not its suitability for a particular challenge string.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Solution {
    /// Inner fixed-sized array of SolutionItem
    items: SolutionItemArray,
}

impl Solution {
    /// Number of items (selected hash inputs) in each solution
    pub const NUM_ITEMS: usize = 1 << EQUIHASH_K;

    /// Number of bytes in the packed representation of a solution
    pub const NUM_BYTES: usize = Self::NUM_ITEMS * mem::size_of::<SolutionItem>();

    /// Size of each [`SolutionItem`], in bytes
    const ITEM_SIZE: usize = mem::size_of::<SolutionItem>();

    /// Build a [`Solution`] from an array of items, checking that
    /// the solution is well-formed.
    pub fn try_from_array(items: &SolutionItemArray) -> Result<Self, Error> {
        if check_tree_order(items) {
            Ok(Self { items: *items })
        } else {
            Err(Error::Order)
        }
    }

    /// Build a [`Solution`] by sorting a [`SolutionItemArray`] as necessary,
    /// without the possibility of failure.
    ///    
    /// Used by the solver.
    pub(crate) fn sort_from_array(mut items: SolutionItemArray) -> Self {
        sort_into_tree_order(&mut items);
        Self { items }
    }

    /// Build a [`Solution`] from a fixed size byte array, checking
    /// that the solution is well-formed.
    pub fn try_from_bytes(bytes: &SolutionByteArray) -> Result<Self, Error> {
        let mut array: SolutionItemArray = Default::default();
        for i in 0..Self::NUM_ITEMS {
            array[i] = SolutionItem::from_le_bytes(
                bytes[i * Self::ITEM_SIZE..(i + 1) * Self::ITEM_SIZE]
                    .try_into()
                    .expect("slice length matches"),
            );
        }
        Self::try_from_array(&array)
    }

    /// Return the packed byte representation of this Solution.
    pub fn to_bytes(&self) -> SolutionByteArray {
        let mut result: SolutionByteArray = Default::default();
        for i in 0..Self::NUM_ITEMS {
            result[i * Self::ITEM_SIZE..(i + 1) * Self::ITEM_SIZE]
                .copy_from_slice(&self.items[i].to_le_bytes());
        }
        result
    }
}

impl AsRef<SolutionItemArray> for Solution {
    fn as_ref(&self) -> &SolutionItemArray {
        &self.items
    }
}

impl From<Solution> for SolutionItemArray {
    fn from(solution: Solution) -> SolutionItemArray {
        solution.items
    }
}

/// Ordering predicate for each node of the SolutionItem tree
#[inline(always)]
fn branches_are_sorted(left: &[SolutionItem], right: &[SolutionItem]) -> bool {
    matches!(
        left.iter().rev().cmp(right.iter().rev()),
        cmp::Ordering::Less | cmp::Ordering::Equal
    )
}

/// Check tree ordering recursively.
///
/// HashX uses a lexicographic ordering constraint applied at each tree level,
/// to resolve the ambiguity that would otherwise be present between each pair
/// of branches in the item tree.
///
/// When combined with the hash sum constraints, this fully constrains the order
/// of the items in a solution. On its own this constraint only partially defines
/// the order of the entire item array.
#[inline(always)]
fn check_tree_order(items: &[SolutionItem]) -> bool {
    let (left, right) = items.split_at(items.len() / 2);
    let sorted = branches_are_sorted(left, right);
    if items.len() == 2 {
        sorted
    } else {
        sorted && check_tree_order(left) && check_tree_order(right)
    }
}

/// Sort a solution in-place into tree order.
#[inline(always)]
fn sort_into_tree_order(items: &mut [SolutionItem]) {
    let len = items.len();
    let (left, right) = items.split_at_mut(items.len() / 2);
    if len > 2 {
        sort_into_tree_order(left);
        sort_into_tree_order(right);
    }
    if !branches_are_sorted(left, right) {
        left.swap_with_slice(right);
    }
}

/// Check hash sums recursively.
///
/// The main solution constraint in HashX is a partial sum at each tree level.
/// The overall match required is [`EQUIHASH_N`] bits, and each subsequent tree
/// level needs a match half this long.
///
/// Each recursive invocation returns the entire sum if its layer has the
/// indicated number of matching bits.
#[inline(always)]
fn check_tree_sums(func: &HashX, items: &[SolutionItem], n_bits: usize) -> Result<HashValue, ()> {
    let sum = if items.len() == 2 {
        item_hash(func, items[0]).wrapping_add(item_hash(func, items[1]))
    } else {
        let (left, right) = items.split_at(items.len() / 2);
        let left = check_tree_sums(func, left, n_bits / 2)?;
        let right = check_tree_sums(func, right, n_bits / 2)?;
        left.wrapping_add(right)
    };
    let mask = ((1 as HashValue) << n_bits) - 1;
    if (sum & mask) == 0 { Ok(sum) } else { Err(()) }
}

/// Check all tree sums, using the full size defined by [`EQUIHASH_N`].
///
/// This will recurse at compile-time into
/// layered tests for 60-, 30-, and 15-bit masks.
pub(crate) fn check_all_tree_sums(func: &HashX, solution: &Solution) -> Result<(), Error> {
    match check_tree_sums(func, solution.as_ref(), EQUIHASH_N) {
        Ok(_unused_bits) => Ok(()),
        Err(()) => Err(Error::HashSum),
    }
}
