//! This module exposes helpers for working with types that implement
//! [`RangeBounds`].

use std::cmp::{self, Ord};
use std::ops::{Bound, RangeBounds};

/// An extension trait for [`RangeBounds`].
pub trait RangeBoundsExt<T>: RangeBounds<T> {
    /// Compute the intersection of two `RangeBound`s.
    ///
    /// In essence, this computes the intersection of the intervals described by bounds of the
    /// two objects.
    ///
    /// Returns `None` if the intersection of the two ranges is the empty set.
    fn intersect<'a, U: RangeBounds<T>>(
        &'a self,
        other: &'a U,
    ) -> Option<(Bound<&'a T>, Bound<&'a T>)>;
}

impl<T, R> RangeBoundsExt<T> for R
where
    R: RangeBounds<T>,
    T: Ord,
{
    fn intersect<'a, U: RangeBounds<T>>(
        &'a self,
        other: &'a U,
    ) -> Option<(Bound<&'a T>, Bound<&'a T>)> {
        use Bound::*;

        let this_start = self.start_bound();
        let other_start = other.start_bound();
        let this_end = self.end_bound();
        let other_end = other.end_bound();

        let start = bounds_max(this_start, other_start);
        let end = bounds_min(this_end, other_end);

        match (start, end) {
            (Excluded(start), Excluded(end)) | (Included(start), Excluded(end)) if start == end => {
                // The interval (n, n) = [n, n) = {} (empty set).
                None
            }
            (Included(start), Included(end))
            | (Included(start), Excluded(end))
            | (Excluded(start), Included(end))
            | (Excluded(start), Excluded(end))
                if start > end =>
            {
                // For any a > b, the intervals [a, b], [a, b), (a, b], (a, b) are empty.
                None
            }
            _ => Some((start, end)),
        }
    }
}

/// Return the largest of `b1` and `b2`.
///
/// If one of the bounds is [Unbounded](Bound::Unbounded), the other will be returned.
fn bounds_max<'a, T: Ord>(b1: Bound<&'a T>, b2: Bound<&'a T>) -> Bound<&'a T> {
    use Bound::*;

    match (b1, b2) {
        (Included(b1), Included(b2)) => Included(cmp::max(b1, b2)),
        (Excluded(b1), Excluded(b2)) => Excluded(cmp::max(b1, b2)),

        (Excluded(b1), Included(b2)) if b1 >= b2 => Excluded(b1),
        (Excluded(_), Included(b2)) => Included(b2),

        (Included(b1), Excluded(b2)) if b2 >= b1 => Excluded(b2),
        (Included(b1), Excluded(_)) => Included(b1),

        (b, Unbounded) | (Unbounded, b) => b,
    }
}

/// Return the smallest of `b1` and `b2`.
///
/// If one of the bounds is [Unbounded](Bound::Unbounded), the other will be returned.
fn bounds_min<'a, T: Ord>(b1: Bound<&'a T>, b2: Bound<&'a T>) -> Bound<&'a T> {
    use Bound::*;

    match (b1, b2) {
        (Included(b1), Included(b2)) => Included(cmp::min(b1, b2)),
        (Excluded(b1), Excluded(b2)) => Excluded(cmp::min(b1, b2)),

        (Excluded(b1), Included(b2)) if b1 <= b2 => Excluded(b1),
        (Excluded(_), Included(b2)) => Included(b2),

        (Included(b1), Excluded(b2)) if b2 <= b1 => Excluded(b2),
        (Included(b1), Excluded(_)) => Included(b1),

        (b, Unbounded) | (Unbounded, b) => b,
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
    use super::*;
    use std::fmt::Debug;
    use std::time::{Duration, SystemTime};
    use Bound::{Excluded as Excl, Included as Incl, Unbounded};

    /// A helper that computes the intersection of `range1` and `range2`.
    ///
    /// This function also asserts that the intersection operation is commutative.
    fn intersect<'a, T, R: RangeBounds<T>>(
        range1: &'a R,
        range2: &'a R,
    ) -> Option<(Bound<&'a T>, Bound<&'a T>)>
    where
        T: PartialEq + Ord + Debug,
    {
        let intersection1 = range1.intersect(range2);
        let intersection2 = range2.intersect(range1);

        assert_eq!(intersection1, intersection2);

        intersection1
    }

    /// A helper for randomly generating either an inclusive or an exclusive bound with a
    /// particular value.
    fn random_bound<T>(value: T) -> Bound<T> {
        if rand::random() {
            Bound::Included(value)
        } else {
            Bound::Excluded(value)
        }
    }

    #[test]
    fn no_overlap() {
        #[allow(clippy::type_complexity)]
        const NON_OVERLAPPING_RANGES: &[(
            (Bound<usize>, Bound<usize>),
            (Bound<usize>, Bound<usize>),
        )] = &[
            // (1, 2) and (3, 4)
            ((Excl(1), Excl(2)), (Excl(3), Excl(4))),
            // (1, 2) and (2, 3)
            ((Excl(1), Excl(2)), (Excl(2), Excl(3))),
            // (1, 2) and [2, 3)
            ((Excl(1), Excl(2)), (Incl(2), Excl(3))),
            // (1, 2) and [2, 3]
            ((Excl(1), Excl(2)), (Incl(3), Incl(4))),
            // (-inf, 2) and [2, 3]
            ((Unbounded, Excl(2)), (Incl(2), Incl(3))),
            // (-inf, 2) and (2, inf)
            ((Unbounded, Excl(2)), (Excl(2), Unbounded)),
            // (-inf, 2) and [2, inf)
            ((Unbounded, Excl(2)), (Incl(2), Unbounded)),
        ];

        for (range1, range2) in NON_OVERLAPPING_RANGES {
            let intersection = intersect(range1, range2);
            assert!(
                intersection.is_none(),
                "{:?} and {:?} => {:?}",
                range1,
                range2,
                intersection
            );
        }
    }

    #[test]
    fn intersect_unbounded_start() {
        // (-inf, 3)
        let range1 = (Unbounded, Excl(3));
        // [2, 5]
        let range2 = (Incl(2), Incl(5));

        let intersection = intersect(&range1, &range2).unwrap();

        // intersection = [2 3]
        assert_eq!(intersection.start_bound(), Bound::Included(&2));
        assert_eq!(intersection.end_bound(), Bound::Excluded(&3));
    }

    #[test]
    fn intersect_unbounded_end() {
        // (8, inf)
        let range1 = (Excl(8), Unbounded);
        // [8, 20]
        let range2 = (Incl(8), Incl(20));

        let intersection = intersect(&range1, &range2).unwrap();

        // intersection = (8, 20]
        assert_eq!(intersection.start_bound(), Bound::Excluded(&8));
        assert_eq!(intersection.end_bound(), Bound::Included(&20));
    }

    #[test]
    fn intersect_unbounded_range() {
        #[allow(clippy::type_complexity)]
        const RANGES: &[(Bound<usize>, Bound<usize>)] = &[
            // (1, 2)
            (Excl(1), Excl(2)),
            // (1, 2]
            (Excl(1), Incl(2)),
            // [1, 2]
            (Incl(1), Incl(2)),
            // [1, 2)
            (Incl(1), Excl(2)),
            // (1, inf)
            (Excl(1), Unbounded),
            // [1, inf)
            (Incl(1), Unbounded),
            // (-inf, 2)
            (Unbounded, Excl(2)),
            // (-inf, 2]
            (Unbounded, Incl(2)),
        ];

        // The intersection of any interval I with (Unbounded, Unbounded) will be I.
        let range1 = (Unbounded, Unbounded);

        for range2 in RANGES {
            let range2 = (range2.0.as_ref(), range2.1.as_ref());
            assert_eq!(intersect(&range1, &range2).unwrap(), range2);
        }
    }

    #[test]
    fn intersect_time_bounds() {
        const MIN: Duration = Duration::from_secs(60);

        // time (relative to now):  0   1   2   3
        //                          |   |   |   |
        // [t1, t2]:                [.......]
        // [t3, t4]:                    [.......]
        // intersection:                [...]
        let now = SystemTime::now();
        let t1 = now;
        let t2 = now + 2 * MIN;

        let t3 = now + 1 * MIN;
        let t4 = now + 3 * MIN;

        let b1 = (Bound::Included(t1), Bound::Included(t2));
        let b2 = (Bound::Included(t3), Bound::Included(t4));
        let expected = (Bound::Included(&t3), Bound::Included(&t2));
        assert_eq!(intersect(&b1, &b2).unwrap(), expected);

        //  t1  -  -  t2  -  -
        //                   t3  -  -  t4
        //
        // time (relative to now):  0   1   2   3   4   5   6   7
        //                          |   |   |   |   |   |   |   |
        // [t1, t2]:                [.......]
        // [t3, t4]:                                [............]
        let t3 = now + 4 * MIN;
        let t4 = now + 7 * MIN;
        let b2 = (Bound::Included(t3), Bound::Included(t4));
        assert!(intersect(&b1, &b2).is_none());
    }

    #[test]
    fn combinatorial() {
        for i in 0..10 {
            for j in 0..10 {
                for k in 0..10 {
                    for l in 0..10 {
                        let range1 = (random_bound(i), random_bound(j));
                        let range2 = (random_bound(k), random_bound(l));

                        let intersection = intersect(&range1, &range2);

                        for witness in 0..10 {
                            let c1 = range1.contains(&witness);
                            let c2 = range2.contains(&witness);
                            let both_contain_witness = c1 && c2;

                            if both_contain_witness {
                                // If both ranges contain `witness` they definitely intersect.
                                assert!(intersection.unwrap().contains(&witness));
                            } else if let Some(intersection) = intersection {
                                // If one of them doesn't contain `witness`, `witness` is
                                // definitely not part of the intersection.
                                assert!(!intersection.contains(&witness));
                            }
                        }
                    }
                }
            }
        }
    }
}
