//! Helper type: a frozen RangeMap where most ranges do not have gaps between them.
//!
//! Ordinary RangeMaps store a start and end for each range.  But if the
//! there are not gaps between a pair of ranges, then the range end is redundant.
//!
//! This trick lets us save about 40%-50% of the total database size, for
//! a savings of around 6 MiB.  (Data checked as of April 2026)

use std::ops::RangeInclusive;

/// An object that has a single next element.
pub(crate) trait Successor: Sized {
    /// Return the next element after this one.
    ///
    /// Returns None if this is the maximum value
    fn next(&self) -> Option<Self>;
}

impl Successor for u32 {
    fn next(&self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl Successor for u128 {
    fn next(&self) -> Option<Self> {
        self.checked_add(1)
    }
}

/// An immutable map from ranges to values.
///
/// This type is optimized for reasonable O(lg N) performance,
/// and for space efficiency in the case where:
/// - `Option<V>` is the same size as V, or at least not much larger.
/// - most or all ranges have no gaps between them.
///
/// That is to say, we get our space efficiency wins in the case where,
/// if some range (K..=V) in the map,
/// (V+1..=K2) is also likely to be in the map.
///
/// (This is true for around like 99% of our IPv4 ranges and around 91% of our
/// IPv6 ranges.)
///
/// This type is crate-internal because its functionality is limited,
/// and because we may want to switch to some other approach to geoip in the future.
///
/// ## Overview
///
/// We consider a map of disjoint ranges `(S..=E) => V`
/// as a _dense_ map from `(S'..=E') => Option<V>`,
/// such that there is is exactly one `(S'..E')` range covering every value from
/// `min(S)` through `K::MAX` inclusive.
///
/// Because this map is dense, we can encode these ranges as a sorted list of S',
/// and then use a binary search to find which `Option<V>` corresponds
/// to any given value.
///
/// ## Invariants
///
/// - `starts` is sorted and contains no duplicates.
/// - `values.len() == starts.len()``
///
/// ## Semantics:
///
/// This table maps keys to value as follows:
///
/// If `starts` is empty, then every key maps to None.
///
/// Otherwise:
///    - Every key such that `K::min <= key < starts[0]` maps to None.
///    - Every key such that `starts[idx] <= key < starts[idx+1]` maps to
///      `values[idx]`, which may be Some or None.
///    - Every key such that `key >= starts.last()` maps to values.last(),
///      which may be Some or None.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DenseRangeMap<K, V> {
    /// A list of the starting points of each range or gap.
    starts: Box<[K]>,
    /// A list of values.
    ///
    /// If `starts[i]` is the start of a range, then `values[i]` is Some(v)
    /// where v is the value of that range for every
    values: Box<[Option<V>]>,
}

impl<K, V> Default for DenseRangeMap<K, V> {
    fn default() -> Self {
        Self {
            starts: Default::default(),
            values: Default::default(),
        }
    }
}

/// A helper type to create a [`DenseRangeMap`] from a sorted list of disjoint ranges.
///
/// ## Invariants
///
/// - `starts.len() == values.len()`
/// - `starts` is sorted and contains no duplicates.
/// - `starts` is empty if and only if `prev_end` is None.
///
/// ## Semantics
///
/// If `starts` is empty, nothing has been added to this Builder.
///
/// Otherwise:
///    - Every key such that `K::min <= key < starts[0]` maps to None.
///    - Every key such that `starts[idx] <= key < starts[idx+1]` maps to
///      `values[idx]`, which may be Some or None.
///    - Every key such that `key <= starts.last() <= prev_end` maps to
///      `values.last()`.
///    - No mappings have been added for any range S..=E such that
///      'S > prev_end`.
struct DenseRangeMapBuilder<K, V> {
    /// A list of range starts so far.
    starts: Vec<K>,
    /// A list of values so far.
    values: Vec<Option<V>>,
    /// The last element of the most recently added range.
    prev_end: Option<K>,
}

/// An error that occurred while building a [`DenseRangeMap`]
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum Error {
    /// Some range was invalid
    #[error("Found an entry with an invalid range")]
    BadEntry,

    /// The entries in the database were not sorted.
    #[error("Entries were not sorted")]
    Unsorted,
}

impl<K: Eq + Ord + Successor, V> DenseRangeMapBuilder<K, V> {
    /// Construct a new empty builder.
    fn new() -> Self {
        Self {
            starts: Vec::new(),
            values: Vec::new(),
            prev_end: None,
        }
    }

    /// Consume this builder and return a DenseRangeMap with the same values.
    fn build(mut self) -> DenseRangeMap<K, V> {
        if let Some(prev_end) = self.prev_end.take()
            && let Some(next_range_start) = prev_end.next()
        {
            // There is empty space after the last range, so we need to
            // represent that with a gap entry.
            self.starts.push(next_range_start);
            self.values.push(None);
        }
        // See if we can reclaim any space.
        self.starts.shrink_to_fit();
        self.values.shrink_to_fit();

        let map = DenseRangeMap {
            starts: self.starts.into(),
            values: self.values.into(),
        };

        #[cfg(test)]
        map.assert_valid();

        map
    }

    /// Add an entry to this [`DenseRangeMapBuilder`].
    ///
    /// Returns an error if `range` is not in strictly ascending order with respect
    /// to all previous ranges.
    fn push(&mut self, range: RangeInclusive<K>, value: V) -> Result<(), Error> {
        // NOTE: We _could_ coalesce our ranges if two abutting ranges have the
        // same value.  But our geoip data processing tools already do that.
        use std::cmp::Ordering::*;

        let (start, end) = range.into_inner();
        if start > end {
            return Err(Error::BadEntry);
        }

        // Set "next_range_start" to the place that this range would start if
        // there is no gap after the last range.
        if let Some(prev_end) = self.prev_end.take() {
            // This is not the first entry, so we might need to add a gap entry.

            // Find the start of a possible gap entry.
            // (If there is not a successor to the end of the last range, then
            // any entry we are trying to push is unsorted!)
            let gap_start = prev_end.next().ok_or(Error::Unsorted)?;

            // Compare the start of the possible gap to the start of this range.
            match gap_start.cmp(&start) {
                Less => {
                    // There is a gap between the end of the last entry and the
                    // start of this one.  Add a representation of that gap.
                    self.starts.push(gap_start);
                    self.values.push(None);
                }
                Equal => {
                    // There is no gap, so we don't have to represent it. Cool!
                }
                Greater => {
                    // We aren't sorted; give up.
                    return Err(Error::Unsorted);
                }
            }
        }
        // Add this entry.
        self.starts.push(start);
        self.values.push(Some(value));
        self.prev_end = Some(end);

        Ok(())
    }
}

impl<K: Eq + Ord + Successor, V> DenseRangeMap<K, V> {
    /// Construct a [`DenseRangeMap`] from an iterator of `(range,value)` pairs.
    ///
    /// The ranges must be disjoint and sorted in ascending order by their start.
    #[cfg(test)]
    pub(crate) fn from_sorted_inclusive_ranges<S>(iter: S) -> Result<Self, Error>
    where
        S: Iterator<Item = (RangeInclusive<K>, V)>,
    {
        Self::try_from_sorted_inclusive_ranges(iter.map(Ok))
    }

    /// Construct a [`DenseRangeMap`] from an iterator of `Result<(range,value>`` pairs.
    ///
    /// The ranges must be disjoint and sorted in ascending order by their start.
    pub(crate) fn try_from_sorted_inclusive_ranges<S, E>(iter: S) -> Result<Self, E>
    where
        S: Iterator<Item = Result<(RangeInclusive<K>, V), E>>,
        E: From<Error>,
    {
        let mut b = DenseRangeMapBuilder::new();
        for entry in iter {
            let (range, value) = entry?;
            b.push(range, value)?;
        }

        Ok(b.build())
    }

    /// Return the value, if any, associated with the given `key`.
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        let index = match self.starts.binary_search(key) {
            Ok(v) => v,
            Err(0) => return None,
            Err(v) => v - 1,
        };

        self.values[index].as_ref()
    }

    /// Testing only: Assert that this object obeys its invariants.
    #[cfg(test)]
    fn assert_valid(&self) {
        // We don't use `is_sorted` here since it allows duplicates.
        for pair in self.starts.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        assert_eq!(self.values.len(), self.starts.len());
    }

    /// Testing only: return a `Vec` of `(start, Option<V>)` to represent
    /// this entries table.
    ///
    /// This is more convenient to inspect than looking at `starts` and `values`
    /// manually.
    ///
    /// (We store `starts` and `values` in separate lists to avoid padding issues.)
    #[cfg(test)]
    fn rep(&self) -> Vec<(K, Option<V>)>
    where
        K: Clone,
        V: Clone,
    {
        self.starts
            .iter()
            .cloned()
            .zip(self.values.iter().cloned())
            .collect()
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use proptest::prelude::*;

    type M = DenseRangeMap<u32, &'static str>;

    #[test]
    fn empty() {
        let map = M::from_sorted_inclusive_ranges(std::iter::empty()).unwrap();
        assert_eq!(map.get(&0), None);
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&50), None);
        assert_eq!(map.get(&(u32::MAX - 1)), None);
        assert_eq!(map.get(&(u32::MAX)), None);
    }

    #[test]
    fn both_ends_open() {
        // construct a map that has gaps at both ends.
        let map = M::from_sorted_inclusive_ranges(
            [
                //
                (5..=10, "small"),
                (11..=90, "medium"),
                (100..=1000, "big"),
            ]
            .into_iter(),
        )
        .unwrap();
        map.assert_valid();

        assert_eq!(
            map.rep()[..],
            [
                (5, Some("small")),
                (11, Some("medium")),
                (91, None),
                (100, Some("big")),
                (1001, None),
            ]
        );

        assert_eq!(map.get(&0), None);
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&5), Some(&"small"));
        assert_eq!(map.get(&10), Some(&"small"));
        assert_eq!(map.get(&11), Some(&"medium"));
        assert_eq!(map.get(&85), Some(&"medium"));
        assert_eq!(map.get(&90), Some(&"medium"));
        assert_eq!(map.get(&91), None);
        assert_eq!(map.get(&99), None);
        assert_eq!(map.get(&100), Some(&"big"));
        assert_eq!(map.get(&500), Some(&"big"));
        assert_eq!(map.get(&1000), Some(&"big"));
        assert_eq!(map.get(&1001), None);
        assert_eq!(map.get(&(u32::MAX - 1)), None);
        assert_eq!(map.get(&u32::MAX), None);
    }

    #[test]
    fn both_ends_filled_map() {
        // construct a map that has no gap at either end.
        let map = M::from_sorted_inclusive_ranges(
            [
                //
                (0..=10, "small"),
                (11..=90, "medium"),
                (100..=u32::MAX, "big"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            map.rep()[..],
            [
                (0, Some("small")),
                (11, Some("medium")),
                (91, None),
                (100, Some("big")),
            ]
        );

        assert_eq!(map.get(&0), Some(&"small"));
        assert_eq!(map.get(&1), Some(&"small"));
        assert_eq!(map.get(&5), Some(&"small"));
        assert_eq!(map.get(&10), Some(&"small"));
        assert_eq!(map.get(&11), Some(&"medium"));
        assert_eq!(map.get(&85), Some(&"medium"));
        assert_eq!(map.get(&90), Some(&"medium"));
        assert_eq!(map.get(&91), None);
        assert_eq!(map.get(&99), None);
        assert_eq!(map.get(&100), Some(&"big"));
        assert_eq!(map.get(&500), Some(&"big"));
        assert_eq!(map.get(&1000), Some(&"big"));
        assert_eq!(map.get(&1001), Some(&"big"));
        assert_eq!(map.get(&(u32::MAX - 1)), Some(&"big"));
        assert_eq!(map.get(&u32::MAX), Some(&"big"));
    }

    proptest! {
        // Property test: build a RangeIncluseiveMap at random, then construct a new
        // DenseRangeMap from that map, and make sure they give the same outputs.
        #[test]
        fn matches_rangemap(ranges: Vec<RangeInclusive<u32>>, probes: Vec<u32>) {
            let mut rangemap: rangemap::RangeInclusiveMap<u32, usize> = Default::default();
            for (n, range) in ranges.into_iter().enumerate() {
                rangemap.insert(range, n);
            }
            let dense_map = DenseRangeMap::<u32, usize>::from_sorted_inclusive_ranges(
                rangemap.iter().map(|(k,v)| (k.clone(), *v))
            ).unwrap();

            for probe in probes.iter() {
                assert_eq!(rangemap.get(probe), dense_map.get(probe));
            }
        }

        // Property test: construct a disjoint list of ranges in ascending
        // order, use that list to construct a RangeInclusiveMap and a
        // DenseRangeMap and make sure they give the same outputs.
        #[test]
        fn matches_rangemap2(r: Vec<(u32,u32)>, probes: Vec<u32>) {
            let mut ranges = vec![];
            let mut next = 0_u32;
            for (gap,len) in r {
                let Some(start) = next.checked_add(gap) else {break;};
                let end = start.saturating_add(len);
                ranges.push(start..=end);
                if let Some(n) = end.checked_add(1) {
                    next = n;
                } else {
                    break;
                }
            }

            let mut rangemap: rangemap::RangeInclusiveMap<u32, usize> = Default::default();
            for (n, range) in ranges.iter().enumerate() {
                rangemap.insert(range.clone(), n);
            }

            let dense_map = DenseRangeMap::<u32, usize>::from_sorted_inclusive_ranges(
                ranges.into_iter().enumerate().map(|(n, r)| (r, n))
            ).unwrap();

            for probe in probes.iter() {
                assert_eq!(rangemap.get(probe), dense_map.get(probe));
            }
        }
    }
}
