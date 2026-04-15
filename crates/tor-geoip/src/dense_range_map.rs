//! Helper type: a frozen RangeMap where most ranges do not have gaps between them.
//!
//! Ordinary RangeMaps store a start and end for each range.  But if the
//! there are not gaps between a pair of ranges, then the range end is redundant.
//!
//! This trick lets us save about 40%-50% of the total database size, for
//! a savings of around 6 MiB.  (Data checked as of April 2026)

use std::borrow::Cow;
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

/// An immutable map from ranges to `Option<V1>`, `Option<V2>`-pairs.
///
/// This type is optimized for reasonable O(lg N) performance,
/// and for space efficiency in the case where:
/// - `Option<V>` is the same size as V, or at least not much larger.
/// - most or all ranges have no gaps between them.
/// - we might not want to record any values for V2 at all.
/// - we are willing to treat "no entry" and "maps to None" as equivalent.
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
/// as a _dense_ map from `(S'..=E') => Option<V1, V2>`,
/// such that there is is exactly one `(S'..E')` range covering every value from
/// `min(S)` through `K::MAX` inclusive.
///
/// Because this map is dense, we can encode these ranges as a sorted list of S',
/// and then use a binary search to find which `Option<V1, V2>` corresponds
/// to any given value.
///
/// ## Invariants
///
/// - `starts` is sorted and contains no duplicates.
/// - `values1.len() == starts.len()`
/// - If `values2` is present, `values2.len() == starts.len()`
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
///
/// If `values2` is present, then keys map to the same indices in `values2`
/// as they do in `values1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DenseRangeMap<K, V1, V2>
where
    K: Clone + 'static,
    V1: Clone + 'static,
    V2: Clone + 'static,
{
    /// A list of the starting points of each range or gap.
    starts: Cow<'static, [K]>,
    /// A list of values.
    ///
    /// If `starts[i]` is the start of a range, then `values[i]` is Some(v)
    /// where v is the value of that range for every
    values1: Cow<'static, [Option<V1>]>,

    /// An optional list of secondary values.
    ///
    values2: Option<Cow<'static, [Option<V2>]>>,
}

impl<K, V1, V2> Default for DenseRangeMap<K, V1, V2>
where
    K: Clone + 'static,
    V1: Clone + 'static,
    V2: Clone + 'static,
{
    fn default() -> Self {
        Self {
            starts: Default::default(),
            values1: Default::default(),
            values2: None,
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
struct DenseRangeMapBuilder<K, V1, V2> {
    /// A list of range starts so far.
    starts: Vec<K>,
    /// A list of values so far.
    values1: Vec<Option<V1>>,

    /// A list of secondary values so far.
    ///
    /// None if we're ignoring secondary values.
    values2: Option<Vec<Option<V2>>>,

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

impl<K: Eq + Ord + Successor, V1, V2> DenseRangeMapBuilder<K, V1, V2>
where
    K: Clone + 'static,
    V1: Clone + 'static,
    V2: Clone + 'static,
{
    /// Construct a new empty builder.
    fn new() -> Self {
        Self {
            starts: Vec::new(),
            values1: Vec::new(),
            values2: Some(Vec::new()),
            prev_end: None,
        }
    }

    /// Add a single entry to this builder.
    fn push(&mut self, start: K, v1: Option<V1>, v2: Option<V2>) {
        self.starts.push(start);
        self.values1.push(v1);
        if let Some(values2) = self.values2.as_mut() {
            values2.push(v2);
        }
    }

    /// Consume this builder and return a DenseRangeMap with the same values.
    fn build(mut self) -> DenseRangeMap<K, V1, V2> {
        if let Some(prev_end) = self.prev_end.take()
            && let Some(next_range_start) = prev_end.next()
        {
            // There is empty space after the last range, so we need to
            // represent that with a gap entry.
            self.push(next_range_start, None, None);
        }
        // See if we can reclaim any space.
        self.starts.shrink_to_fit();
        self.values1.shrink_to_fit();
        if let Some(values2) = self.values2.as_mut() {
            values2.shrink_to_fit();
        }

        let map = DenseRangeMap {
            starts: self.starts.into(),
            values1: self.values1.into(),
            values2: self.values2.map(Into::into),
        };

        #[cfg(test)]
        map.assert_valid();

        map
    }

    /// Add an entry to this [`DenseRangeMapBuilder`].
    ///
    /// Returns an error if `range` is not in strictly ascending order with respect
    /// to all previous ranges.
    fn add_entry(
        &mut self,
        range: RangeInclusive<K>,
        value1: Option<V1>,
        value2: Option<V2>,
    ) -> Result<(), Error> {
        if value1.is_none() && value2.is_none() {
            return Ok(());
        }

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
                    self.push(gap_start, None, None);
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
        self.push(start, value1, value2);
        self.prev_end = Some(end);

        Ok(())
    }
}

impl<K: Eq + Ord + Successor, V1, V2> DenseRangeMap<K, V1, V2>
where
    K: Clone + 'static,
    V1: Clone + 'static,
    V2: Clone + 'static,
{
    /// Construct a [`DenseRangeMap`] from an iterator of `(range,v1)` tuples.
    ///
    /// The ranges must be disjoint and sorted in ascending order by their start.
    #[cfg(test)]
    pub(crate) fn from_sorted_inclusive_ranges<S>(iter: S) -> Result<Self, Error>
    where
        S: Iterator<Item = (RangeInclusive<K>, V1)>,
    {
        let discard_v2 = true;
        Self::try_from_sorted_inclusive_ranges(
            iter.map(|(r, v1)| Ok((r, Some(v1), None))),
            discard_v2,
        )
    }

    /// Construct a [`DenseRangeMap`] from an iterator of
    /// `Result<(range,optvalue1,optvalue2)>` tuples.
    ///
    /// The ranges must be disjoint and sorted in ascending order by their
    /// start.
    pub(crate) fn try_from_sorted_inclusive_ranges<S, E>(
        iter: S,
        discard_v2: bool,
    ) -> Result<Self, E>
    where
        S: Iterator<Item = Result<(RangeInclusive<K>, Option<V1>, Option<V2>), E>>,
        E: From<Error>,
    {
        let mut b = DenseRangeMapBuilder::new();
        if discard_v2 {
            b.values2 = None;
        }
        for entry in iter {
            let (range, value1, mut value2) = entry?;
            if discard_v2 {
                value2 = None;
            }
            b.add_entry(range, value1, value2)?;
        }

        Ok(b.build())
    }

    /// Return the index for the values corresponding to `key`.
    pub(crate) fn index_for_key(&self, key: &K) -> Option<usize> {
        match self.starts.binary_search(key) {
            Ok(v) => Some(v),
            Err(0) => None,
            Err(v) => Some(v - 1),
        }
    }

    /// Return the value, if any, associated with the given `key`.
    pub(crate) fn get1(&self, key: &K) -> Option<&V1> {
        self.index_for_key(key)
            .and_then(|index| self.values1[index].as_ref())
    }

    /// Return the secondary value, if any, associated with the given `key`.
    pub(crate) fn get2(&self, key: &K) -> Option<&V2> {
        if let Some(values2) = self.values2.as_ref() {
            self.index_for_key(key)
                .and_then(|index| values2[index].as_ref())
        } else {
            None
        }
    }

    /// Testing only: Assert that this object obeys its invariants.
    #[cfg(test)]
    fn assert_valid(&self) {
        // We don't use `is_sorted` here since it allows duplicates.
        for pair in self.starts.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        assert_eq!(self.values1.len(), self.starts.len());
        if let Some(values2) = &self.values2 {
            assert_eq!(values2.len(), self.starts.len());
        }
    }

    /// Testing only: return a `Vec` of `(start, Option<V1, V2>)` to represent
    /// this entries table.
    ///
    /// This is more convenient to inspect than looking at `starts` and `values`
    /// manually.
    ///
    /// (We store `starts` and `values` in separate lists to avoid padding issues.)
    #[cfg(test)]
    fn rep(&self) -> Vec<(K, Option<V1>)>
    where
        K: Clone + 'static,
        V1: Clone + 'static,
    {
        self.starts
            .iter()
            .cloned()
            .zip(self.values1.iter().cloned())
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

    type M = DenseRangeMap<u32, &'static str, ()>;

    #[test]
    fn empty() {
        let map = M::from_sorted_inclusive_ranges(std::iter::empty()).unwrap();
        assert_eq!(map.get1(&0), None);
        assert_eq!(map.get1(&1), None);
        assert_eq!(map.get1(&50), None);
        assert_eq!(map.get1(&(u32::MAX - 1)), None);
        assert_eq!(map.get1(&(u32::MAX)), None);
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

        assert_eq!(map.get1(&0), None);
        assert_eq!(map.get1(&1), None);
        assert_eq!(map.get1(&5), Some(&"small"));
        assert_eq!(map.get1(&10), Some(&"small"));
        assert_eq!(map.get1(&11), Some(&"medium"));
        assert_eq!(map.get1(&85), Some(&"medium"));
        assert_eq!(map.get1(&90), Some(&"medium"));
        assert_eq!(map.get1(&91), None);
        assert_eq!(map.get1(&99), None);
        assert_eq!(map.get1(&100), Some(&"big"));
        assert_eq!(map.get1(&500), Some(&"big"));
        assert_eq!(map.get1(&1000), Some(&"big"));
        assert_eq!(map.get1(&1001), None);
        assert_eq!(map.get1(&(u32::MAX - 1)), None);
        assert_eq!(map.get1(&u32::MAX), None);
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

        assert_eq!(map.get1(&0), Some(&"small"));
        assert_eq!(map.get1(&1), Some(&"small"));
        assert_eq!(map.get1(&5), Some(&"small"));
        assert_eq!(map.get1(&10), Some(&"small"));
        assert_eq!(map.get1(&11), Some(&"medium"));
        assert_eq!(map.get1(&85), Some(&"medium"));
        assert_eq!(map.get1(&90), Some(&"medium"));
        assert_eq!(map.get1(&91), None);
        assert_eq!(map.get1(&99), None);
        assert_eq!(map.get1(&100), Some(&"big"));
        assert_eq!(map.get1(&500), Some(&"big"));
        assert_eq!(map.get1(&1000), Some(&"big"));
        assert_eq!(map.get1(&1001), Some(&"big"));
        assert_eq!(map.get1(&(u32::MAX - 1)), Some(&"big"));
        assert_eq!(map.get1(&u32::MAX), Some(&"big"));
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
            let dense_map = DenseRangeMap::<u32, usize, ()>::from_sorted_inclusive_ranges(
                rangemap.iter().map(|(k,v)| (k.clone(), *v))
            ).unwrap();

            for probe in probes.iter() {
                assert_eq!(rangemap.get(probe), dense_map.get1(probe));
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

            let dense_map = DenseRangeMap::<u32, usize, ()>::from_sorted_inclusive_ranges(
                ranges.into_iter().enumerate().map(|(n, r)| (r, n))
            ).unwrap();

            for probe in probes.iter() {
                assert_eq!(rangemap.get(probe), dense_map.get1(probe));
            }
        }
    }
}
