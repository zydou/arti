//! Iterator helpers for Arti.

/// Iterator extension trait to implement a counting filter.
pub trait IteratorExt: Iterator {
    /// Return an iterator that contains every member of this iterator, and
    /// which records its progress in `count`.
    ///
    /// The values in `count` are initially set to zero.  Then, every time the
    /// filter considers an item, it will either increment `count.n_accepted` or
    /// `count.n_rejected`.
    ///
    /// Note that if the iterator is dropped before it is exhausted, the count will not
    /// be complete.
    ///
    /// # Examples
    ///
    /// ```
    /// use tor_basic_utils::iter::{IteratorExt, FilterCount};
    ///
    /// let mut count = FilterCount::default();
    /// let emoji : String = "Hello 🙂 World 🌏!"
    ///     .chars()
    ///     .filter_cnt(&mut count, |ch| !ch.is_ascii())
    ///     .collect();
    /// assert_eq!(emoji, "🙂🌏");
    /// assert_eq!(count, FilterCount { n_accepted: 2, n_rejected: 14});
    /// ```
    //
    // In Arti, we mostly use this iterator for reporting issues when we're
    // unable to find a suitable relay for some purpose: it makes it easy to
    // tabulate which filters in a chain of filters rejected how many of the
    // potential candidates.
    fn filter_cnt<P>(self, count: &mut FilterCount, pred: P) -> CountingFilter<'_, P, Self>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        *count = FilterCount::default();
        CountingFilter {
            inner: self,
            pred,
            count,
        }
    }
}

impl<I> IteratorExt for I where I: Iterator {}

/// A record of how many items a [`CountingFilter`] returned by
/// [`IteratorExt::filter_cnt`] accepted and rejected.
///
/// In `tor-guardmgr` we use this type to keep track of which filters reject which guards.
//
// SEMVER NOTE: This type has public members, is exhaustive, and is re-exposed
// from various error types elsewhere in arti.  Probably you should not change
// its members.  If you do, you will need to mark it as a breaking change
// everywhere that it is re-exported.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_structs)]
pub struct FilterCount {
    /// The number of items that the filter considered and accepted.
    pub n_accepted: usize,
    /// The number of items that the filter considered and accepted.
    pub n_rejected: usize,
}

/// An iterator to implement [`IteratorExt::filter_cnt`].
pub struct CountingFilter<'a, P, I> {
    /// The inner iterator that we're taking items from.
    inner: I,
    /// The predicate we're using to decide which items are accepted.
    pred: P,
    /// The count of the number of items accepted and rejected so far.
    count: &'a mut FilterCount,
}

impl<'a, P, I> Iterator for CountingFilter<'a, P, I>
where
    P: FnMut(&I::Item) -> bool,
    I: Iterator,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        for item in &mut self.inner {
            if (self.pred)(&item) {
                self.count.n_accepted += 1;
                return Some(item);
            } else {
                self.count.n_rejected += 1;
            }
        }
        None
    }
}

impl FilterCount {
    /// Return a wrapper that can be displayed as the fraction of rejected items.
    ///
    /// # Example
    ///
    /// ```
    /// # use tor_basic_utils::iter::{IteratorExt, FilterCount};
    /// let mut count = FilterCount::default();
    /// let sum_of_evens : u32 = (1..=10)
    ///     .filter_cnt(&mut count, |x| *x % 2 == 0)
    ///     .sum();
    /// assert_eq!(format!("Rejected {} as odd", count.display_frac_rejected()),
    ///     "Rejected 5/10 as odd".to_string());
    /// ```
    pub fn display_frac_rejected(&self) -> DisplayFracRejected<'_> {
        DisplayFracRejected(self)
    }

    /// Count and return the provided boolean value.
    ///
    /// This is an alternative way to use `FilterCount` when you have to provide
    /// a function that takes a predicate rather than a member of an iterator
    /// chain.
    ///
    /// # Example
    ///
    /// ```
    /// # use tor_basic_utils::iter::FilterCount;
    /// let mut count = FilterCount::default();
    /// let mut emoji = "Hello 🙂 World 🌏!".to_string();
    /// emoji.retain(|ch| count.count(!ch.is_ascii()));
    /// assert_eq!(emoji, "🙂🌏");
    /// assert_eq!(count, FilterCount { n_accepted: 2, n_rejected: 14});
    /// ```
    pub fn count(&mut self, accept: bool) -> bool {
        if accept {
            self.n_accepted += 1;
        } else {
            self.n_rejected += 1;
        }
        accept
    }
}

/// Return value from [`FilterCount::display_frac_rejected`].
#[derive(Debug, Clone)]
pub struct DisplayFracRejected<'a>(&'a FilterCount);

impl<'a> std::fmt::Display for DisplayFracRejected<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.0.n_rejected,
            self.0.n_accepted + self.0.n_rejected
        )
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

    #[test]
    fn counting_filter() {
        let mut count = FilterCount::default();
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let first_even = v
            .iter()
            .filter_cnt(&mut count, |val| **val % 2 == 0)
            .next()
            .unwrap();
        assert_eq!(*first_even, 2);
        assert_eq!(count.n_accepted, 1);
        assert_eq!(count.n_rejected, 1);

        let sum_even: usize = v.iter().filter_cnt(&mut count, |val| **val % 2 == 0).sum();
        assert_eq!(sum_even, 20);
        assert_eq!(count.n_accepted, 4);
        assert_eq!(count.n_rejected, 5);
    }

    #[test]
    fn counting_with_predicates() {
        let mut count = FilterCount::default();
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let first_even = v.iter().find(|val| count.count(**val % 2 == 0)).unwrap();
        assert_eq!(*first_even, 2);
        assert_eq!(count.n_accepted, 1);
        assert_eq!(count.n_rejected, 1);

        let mut count = FilterCount::default();
        let sum_even: usize = v.iter().filter(|val| count.count(**val % 2 == 0)).sum();
        assert_eq!(sum_even, 20);
        assert_eq!(count.n_accepted, 4);
        assert_eq!(count.n_rejected, 5);
    }

    #[test]
    fn fooz() {}
}
