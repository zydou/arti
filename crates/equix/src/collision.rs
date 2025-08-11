//! Utilities for representing and finding partial sum collisions in the solver

use crate::bucket_array::hash::{
    Count, Insert, Key, KeyLookup, KeyStorage, Shape, ValueBucketArray, ValueLookup,
};
use crate::bucket_array::mem::BucketArrayMemory;
use std::fmt::Debug;
use std::ops::{BitAnd, BitOr, Shl, Shr};

/// Look for partial sum collisions between items in one bucket array.
///
/// The items in each bucket are not sorted. This uses an additional small
/// hash table, with the supplied backing memory, to collect matches.
///
/// The temporary memory can have an arbitrary shape. Capacity of the
/// buffer will affect how may potential collisions we have to discard,
/// and bucket count will affect how much of the key we are operating on.
/// Its value type must match the [`Count`] type of the input table, since
/// it will store item-in-bucket indices.
///
/// For each collision, calls the supplied predicate with the remaining portion
/// of the hash sum and a [`CollisionLocation`] describing the two items.
#[inline(always)]
pub(crate) fn search<const TEMP_N: usize, const TEMP_CAP: usize, A, F, C, K, KS>(
    array: &A,
    scratchpad: &mut BucketArrayMemory<TEMP_N, TEMP_CAP, C>,
    num_bits: usize,
    mut predicate: F,
) where
    A: Shape<K> + KeyLookup<KS, K>,
    F: FnMut(K, CollisionLocation),
    C: Count,
    K: Key,
    KS: KeyStorage<K>,
{
    for first_bucket in 0..=(A::NUM_BUCKETS / 2) {
        let second_bucket = first_bucket.wrapping_neg() % A::NUM_BUCKETS;
        let mut paired_item_hash =
            ValueBucketArray::<'_, { TEMP_N }, { TEMP_CAP }, u8, K, C>::new(scratchpad);

        // Collect into paired_item_hash a mapping from the remainder portion
        // of the key, to the item index in the bucket where we found that key.
        for first_item in array.item_range(first_bucket) {
            let first_hash_remainder = array.item_stored_key(first_bucket, first_item);
            let _ = paired_item_hash.insert(
                first_hash_remainder.into_key(),
                C::from_item_index(first_item),
            );
        }

        // For each item in the second bucket, scan its (small) complementary
        // bucket in paired_item_hash to find partial sum collisions.
        for second_item in array.item_range(second_bucket) {
            let second_hash = array.item_full_key(second_bucket, second_item);
            let hash_complement = second_hash.wrapping_neg();

            let (_, hash_complement_remainder) = array.split_wide_key(hash_complement);
            let (bucket_in_paired_hash, _) =
                paired_item_hash.split_wide_key(hash_complement_remainder);

            for first_item in paired_item_hash
                .item_range(bucket_in_paired_hash)
                .map(|item| paired_item_hash.item_value(bucket_in_paired_hash, item))
            {
                let first_item: usize = first_item.into();
                let first_hash = array.item_full_key(first_bucket, first_item);
                let sum = first_hash.wrapping_add(&second_hash);

                // Compare two items that are in complementary buckets, to see
                // if they actually have a matching sum in all of num_bits.
                if sum.low_bits_are_zero(num_bits) {
                    predicate(
                        sum >> num_bits,
                        CollisionLocation {
                            first_bucket,
                            first_item,
                            second_item,
                        },
                    );
                }
            }
        }
    }
}

/// Locating information for one partial sum collision between items in
/// complementary buckets.
#[derive(Debug, Clone)]
pub(crate) struct CollisionLocation {
    /// Bucket index for the first colliding item, and the additive inverse of
    /// the bucket index for the second colliding item.
    pub(crate) first_bucket: usize,
    /// Index of the first colliding item within its bucket
    pub(crate) first_item: usize,
    /// Index of the second colliding item within its bucket
    pub(crate) second_item: usize,
}

impl CollisionLocation {
    /// Return values associated with both colliding items, as a 2-element array.
    #[inline(always)]
    pub(crate) fn pair<A: ValueLookup<T> + Shape<K>, K: Key, T: Copy>(&self, array: &A) -> [T; 2] {
        [
            array.item_value(self.first_bucket, self.first_item),
            array.item_value(
                self.first_bucket.wrapping_neg() % A::NUM_BUCKETS,
                self.second_item,
            ),
        ]
    }
}

/// Packed representation of a [`CollisionLocation`]
#[derive(Debug, Copy, Clone)]
pub(crate) struct PackedCollision<
    T: Copy
        + TryFrom<usize>
        + TryInto<usize>
        + Shl<usize, Output = T>
        + Shr<usize, Output = T>
        + BitAnd<T, Output = T>
        + BitOr<T, Output = T>,
    const BUCKET_BITS: usize,
    const ITEM_BITS: usize,
>(T);

impl<
    T: Copy
        + TryFrom<usize>
        + TryInto<usize>
        + Shl<usize, Output = T>
        + Shr<usize, Output = T>
        + BitAnd<T, Output = T>
        + BitOr<T, Output = T>,
    const BUCKET_BITS: usize,
    const ITEM_BITS: usize,
> PackedCollision<T, BUCKET_BITS, ITEM_BITS>
{
    /// Construct a new [`PackedCollision`] from its inner type.
    #[inline(always)]
    pub(crate) fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Unwrap this [`PackedCollision`] into its inner type.
    #[inline(always)]
    pub(crate) fn into_inner(self) -> T {
        self.0
    }

    /// Cast to the inner type from [`usize`], with panic on overflow.
    #[inline(always)]
    fn from_usize(i: usize) -> T {
        i.try_into()
            .map_err(|_| ())
            .expect("masked collision field always fits into bitfield type")
    }

    /// Cast the inner type to [`usize`], with panic on overflow.
    #[inline(always)]
    fn to_usize(i: T) -> usize {
        i.try_into()
            .map_err(|_| ())
            .expect("masked collision field always fits in usize")
    }

    /// Construct a new packed location from a [`CollisionLocation`].
    ///
    /// Packs all members into a bitfield. Panics if any of the indices
    /// are larger than the selected field widths can represent.
    #[inline(always)]
    pub(crate) fn pack(loc: &CollisionLocation) -> Self {
        assert!(loc.first_bucket < (1 << BUCKET_BITS));
        assert!(loc.first_item < (1 << ITEM_BITS));
        assert!(loc.second_item < (1 << ITEM_BITS));

        let first_bucket: T = Self::from_usize(loc.first_bucket) << (ITEM_BITS * 2);
        let first_item: T = Self::from_usize(loc.first_item) << ITEM_BITS;
        let second_item: T = Self::from_usize(loc.second_item);
        Self(first_bucket | first_item | second_item)
    }

    /// Unpack a bitfield into its [`CollisionLocation`].
    #[inline(always)]
    pub(crate) fn unpack(&self) -> CollisionLocation {
        let bucket_mask = Self::from_usize((1_usize << BUCKET_BITS) - 1);
        let item_mask = Self::from_usize((1_usize << ITEM_BITS) - 1);

        CollisionLocation {
            first_bucket: Self::to_usize((self.0 >> (ITEM_BITS * 2)) & bucket_mask),
            first_item: Self::to_usize((self.0 >> ITEM_BITS) & item_mask),
            second_item: Self::to_usize(self.0 & item_mask),
        }
    }
}
