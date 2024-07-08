//! Hash table layer
//!
//! This uses the minimal utilities in [`crate::bucket_array::mem`] to build
//! a slightly higher level data structure that's meant to be used as a hash
//! table for uniformly distributed keys. The single and paired bucket arrays
//! from [`crate::bucket_array::mem`] are wrapped into concrete value-only
//! and key-value hash table stores, and unified again via common traits.
//!
//! This introduces new data types and conversions that let us represent one
//! item key in multiple formats: the full size key, its implied bucket number,
//! the remaining unused key bits, and a packed version of that remainder.

use crate::bucket_array::mem::{self, BucketArrayMemory};
use num_traits::{One, WrappingAdd, WrappingNeg, Zero};
use std::marker::PhantomData;
use std::ops::{BitAnd, Div, Mul, Not, Range, Rem, Shl, Shr, Sub};

/// Trait for accessing the overall shape of a bucket array
pub(crate) trait Shape<K: Key> {
    /// The number of buckets in this array
    const NUM_BUCKETS: usize;

    /// Get the range of items within a single bucket.
    fn item_range(&self, bucket: usize) -> Range<usize>;

    /// Get the key divisor: the number of buckets but as a [`Key`] instance.
    #[inline(always)]
    fn divisor(&self) -> K {
        K::from_bucket_index(Self::NUM_BUCKETS)
    }

    /// Split a wide key into the bucket index and the remaining bits.
    #[inline(always)]
    fn split_wide_key(&self, key: K) -> (usize, K) {
        let divisor = self.divisor();
        ((key % divisor).into_bucket_index(), (key / divisor))
    }

    /// Rebuild a wide key from its split components.
    #[inline(always)]
    fn join_wide_key(&self, bucket: usize, remainder: K) -> K {
        let divisor = self.divisor();
        remainder * divisor + K::from_bucket_index(bucket)
    }
}

/// Trait for writing new key/value pairs to a bucket array
pub(crate) trait Insert<K: Key, V: Copy> {
    /// Append a new item to its sorting bucket, or return Err(()) if it's full
    fn insert(&mut self, key: K, value: V) -> Result<(), ()>;
}

/// Trait for bucket arrays that include storage for keys
///
/// Keys are always used to index into the bucket array, but an array may
/// also optionally include storage for the remaining portion.
pub(crate) trait KeyLookup<S: KeyStorage<K>, K: Key> {
    /// Retrieve the stored key remainder bits for this item
    fn item_stored_key(&self, bucket: usize, item: usize) -> S;

    /// Retrieve the key for a particular item, as a full width key
    fn item_full_key(&self, bucket: usize, item: usize) -> K;
}

/// Trait for bucket arrays that include storage for values
///
/// Values are opaque data, any [`Copy`] type may be used.
pub(crate) trait ValueLookup<V: Copy> {
    /// Retrieve the Value for a particular item
    fn item_value(&self, bucket: usize, item: usize) -> V;
}

/// Concrete bucket array with parallel [`BucketArrayMemory`] for key and value
/// storage
///
/// This is the basic data type used for one layer of sorting buckets.
///
/// Takes several type parameters so the narrowest possible types can be
/// chosen for counters, keys, and values. Keys take two types: the 'wide'
/// version that appears in the API and a 'storage' version that's been
/// stripped of the data redundant with its bucket position.
///
/// The validity of [`BucketArrayMemory`] entries is ensured by the combination
/// of our mutable ref to the `BucketArrayMemory` itself and our tracking of
/// bucket counts within the lifetime of that reference.
pub(crate) struct KeyValueBucketArray<
    // Lifetime for mutable reference to key storage memory
    'k,
    // Lifetime for mutable reference to value storage memory
    'v,
    // Number of buckets
    const N: usize,
    // Maximum number of items per bucket
    const CAP: usize,
    // Type for bucket item counts
    C: Count,
    // Full size key type, used in the API and for calculating bucket indices
    K: Key,
    // Storage type for keys, potentially smaller than `K`
    KS: KeyStorage<K>,
    // Value type
    V: Copy,
>(
    mem::BucketArrayPair<'k, 'v, N, CAP, C, KS, V>,
    PhantomData<K>,
);

impl<'k, 'v, const N: usize, const CAP: usize, C: Count, K: Key, KS: KeyStorage<K>, V: Copy>
    KeyValueBucketArray<'k, 'v, N, CAP, C, K, KS, V>
{
    /// A new [`KeyValueBucketArray`] wraps two mutable [`BucketArrayMemory`]
    /// references and adds state to track which items are valid.
    pub(crate) fn new(
        key_mem: &'k mut BucketArrayMemory<N, CAP, KS>,
        value_mem: &'v mut BucketArrayMemory<N, CAP, V>,
    ) -> Self {
        Self(mem::BucketArrayPair::new(key_mem, value_mem), PhantomData)
    }

    /// Keep the counts and the value memory but drop the key memory.
    ///
    /// Returns a new [`ValueBucketArray`].
    pub(crate) fn drop_key_storage(self) -> ValueBucketArray<'v, N, CAP, C, K, V> {
        ValueBucketArray(self.0.drop_first(), self.1)
    }
}

/// Concrete bucket array with a single [`BucketArrayMemory`] for value storage
///
/// Keys are used for bucket indexing but the remainder bits are not stored.
pub(crate) struct ValueBucketArray<
    // Lifetime for mutable reference to value storage memory
    'v,
    // Number of buckets
    const N: usize,
    // Maximum number of items per bucket
    const CAP: usize,
    // Type for bucket item counts
    C: Count,
    // Full size key type, used in the API and for calculating bucket indices
    K: Key,
    // Value type
    V: Copy,
>(mem::BucketArray<'v, N, CAP, C, V>, PhantomData<K>);

impl<'v, const N: usize, const CAP: usize, C: Count, K: Key, V: Copy>
    ValueBucketArray<'v, N, CAP, C, K, V>
{
    /// A new [`ValueBucketArray`] wraps one mutable [`BucketArrayMemory`]
    /// reference and adds a counts array to track which items are valid.
    pub(crate) fn new(value_mem: &'v mut BucketArrayMemory<N, CAP, V>) -> Self {
        Self(mem::BucketArray::new(value_mem), PhantomData)
    }
}

impl<'k, 'v, const N: usize, const CAP: usize, C: Count, K: Key, KS: KeyStorage<K>, V: Copy>
    Shape<K> for KeyValueBucketArray<'k, 'v, N, CAP, C, K, KS, V>
{
    /// Number of buckets in the array
    const NUM_BUCKETS: usize = N;

    #[inline(always)]
    fn item_range(&self, bucket: usize) -> Range<usize> {
        self.0.item_range(bucket)
    }
}

impl<'v, const N: usize, const CAP: usize, C: Count, K: Key, V: Copy> Shape<K>
    for ValueBucketArray<'v, N, CAP, C, K, V>
{
    /// Number of buckets in the array
    const NUM_BUCKETS: usize = N;

    #[inline(always)]
    fn item_range(&self, bucket: usize) -> Range<usize> {
        self.0.item_range(bucket)
    }
}

impl<'k, 'v, const N: usize, const CAP: usize, C: Count, K: Key, KS: KeyStorage<K>, V: Copy>
    Insert<K, V> for KeyValueBucketArray<'k, 'v, N, CAP, C, K, KS, V>
{
    #[inline(always)]
    fn insert(&mut self, key: K, value: V) -> Result<(), ()> {
        let (bucket, key_remainder) = self.split_wide_key(key);
        let key_storage = KS::from_key(key_remainder);
        self.0.insert(bucket, key_storage, value)
    }
}

impl<'v, const N: usize, const CAP: usize, C: Count, K: Key, V: Copy> Insert<K, V>
    for ValueBucketArray<'v, N, CAP, C, K, V>
{
    #[inline(always)]
    fn insert(&mut self, key: K, value: V) -> Result<(), ()> {
        let (bucket, _) = self.split_wide_key(key);
        self.0.insert(bucket, value)
    }
}

impl<'k, 'v, const N: usize, const CAP: usize, C: Count, K: Key, KS: KeyStorage<K>, V: Copy>
    KeyLookup<KS, K> for KeyValueBucketArray<'k, 'v, N, CAP, C, K, KS, V>
{
    #[inline(always)]
    fn item_stored_key(&self, bucket: usize, item: usize) -> KS {
        self.0.item_value_first(bucket, item)
    }

    #[inline(always)]
    fn item_full_key(&self, bucket: usize, item: usize) -> K {
        self.join_wide_key(bucket, self.item_stored_key(bucket, item).into_key())
    }
}

impl<'k, 'v, const N: usize, const CAP: usize, C: Count, K: Key, KS: KeyStorage<K>, V: Copy>
    ValueLookup<V> for KeyValueBucketArray<'k, 'v, N, CAP, C, K, KS, V>
{
    #[inline(always)]
    fn item_value(&self, bucket: usize, item: usize) -> V {
        self.0.item_value_second(bucket, item)
    }
}

impl<'v, const N: usize, const CAP: usize, C: Count, K: Key, V: Copy> ValueLookup<V>
    for ValueBucketArray<'v, N, CAP, C, K, V>
{
    #[inline(always)]
    fn item_value(&self, bucket: usize, item: usize) -> V {
        self.0.item_value(bucket, item)
    }
}

/// Trait for types that can be used as a count of items in a bucket
///
/// Whereas [`mem::Count`] is meant to be the minimum for that module's
/// purposes, this is an extended trait with features needed by the rest of
/// the crate.
pub(crate) trait Count: mem::Count + TryFrom<usize> {
    /// Convert from a usize item index, panic on overflow
    #[inline(always)]
    fn from_item_index(i: usize) -> Self {
        // Omit the original error type, to avoid propagating Debug bounds
        // for this trait. We might be able to stop doing this once the
        // associated_type_bounds Rust feature stabilizes.
        i.try_into()
            .map_err(|_| ())
            .expect("Bucket count type is always wide enough for item index")
    }
}

impl<T: mem::Count + TryFrom<usize>> Count for T {}

/// Types we can use as full width keys
pub(crate) trait Key:
    Copy
    + Zero
    + One
    + PartialEq<Self>
    + TryFrom<usize>
    + TryInto<usize>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Div<Self, Output = Self>
    + Rem<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Not
    + Sub<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + WrappingAdd
    + WrappingNeg
{
    /// Build a Key from a bucket index.
    ///
    /// Panics if the index is out of range.
    #[inline(always)]
    fn from_bucket_index(i: usize) -> Self {
        i.try_into()
            .map_err(|_| ())
            .expect("Key type is always wide enough for a bucket index")
    }

    /// Convert this Key back into a bucket index.
    ///
    /// Panics if the value would not fit in a `usize`. No other range
    /// checking on the bucket index is enforced here.
    #[inline(always)]
    fn into_bucket_index(self) -> usize {
        self.try_into()
            .map_err(|_| ())
            .expect("Key is a bucket index which always fits in a usize")
    }

    /// Check if the N low bits of the key are zero.
    #[inline(always)]
    fn low_bits_are_zero(self, num_bits: usize) -> bool {
        (self & ((Self::one() << num_bits) - Self::one())) == Self::zero()
    }
}

impl<
        T: Copy
            + Zero
            + One
            + PartialEq<Self>
            + TryFrom<usize>
            + TryInto<usize>
            + Shl<usize, Output = Self>
            + Shr<usize, Output = Self>
            + Div<Self, Output = Self>
            + Rem<Self, Output = Self>
            + Mul<Self, Output = Self>
            + Not
            + Sub<Self, Output = Self>
            + BitAnd<Self, Output = Self>
            + WrappingAdd
            + WrappingNeg,
    > Key for T
{
}

/// Backing storage for a specific key type
///
/// Intended to be smaller than or equal in size to the full Key type.
pub(crate) trait KeyStorage<K>:
    Copy + Zero + Not<Output = Self> + TryFrom<K> + TryInto<K>
where
    K: Key,
{
    /// Fit the indicated key into a [`KeyStorage`], wrapping if necessary.
    ///
    /// It is normal for keys to accumulate additional insignificant bits on
    /// the left side as we compute sums.
    #[inline(always)]
    fn from_key(k: K) -> Self {
        let key_mask = (!Self::zero()).into_key();
        <K as TryInto<Self>>::try_into(k & key_mask)
            .map_err(|_| ())
            .expect("masked Key type always fits in KeyStorage")
    }

    /// Unpack this [`KeyStorage`] back into a Key type, without
    /// changing its value.
    #[inline(always)]
    fn into_key(self) -> K {
        self.try_into()
            .map_err(|_| ())
            .expect("Key type is always wider than KeyStorage")
    }
}

impl<T: Copy + Zero + Not<Output = Self> + TryFrom<K> + TryInto<K>, K: Key> KeyStorage<K> for T {}
