//! Misc helper functions and types for use in parsing network documents

pub(crate) mod intern;
pub(crate) mod str;

use std::iter::Peekable;

/// An iterator adaptor that pauses when a given predicate is true.
///
/// Unlike std::iter::TakeWhile, it doesn't consume the first non-returned
/// element.
///
/// We guarantee that the predicate is called no more than once for
/// each item.
pub(crate) struct PauseAt<'a, I: Iterator, F: FnMut(&I::Item) -> bool> {
    /// An underlying iterator that we should take items from
    peek: &'a mut Peekable<I>,
    /// A predicate telling us which items mean that we should pause
    pred: F,
    /// Memoized value of self.pred(self.peek()), so we never
    /// calculate it more than once.
    paused: Option<bool>,
}

impl<'a, I: Iterator, F: FnMut(&I::Item) -> bool> PauseAt<'a, I, F> {
    /// Construct a PauseAt that will pause the iterator `peek` when the
    /// predicate `pred` is about to be true.
    pub(crate) fn from_peekable(peek: &'a mut Peekable<I>, pred: F) -> Self
    where
        F: FnMut(&I::Item) -> bool,
    {
        PauseAt {
            peek,
            pred,
            paused: None,
        }
    }
    /// Replace the predicate on a PauseAt, returning a new PauseAt.
    #[cfg(any(test, feature = "routerdesc"))]
    pub(crate) fn new_pred<F2>(self, pred: F2) -> PauseAt<'a, I, F2>
    where
        F2: FnMut(&I::Item) -> bool,
    {
        PauseAt::from_peekable(self.peek, pred)
    }
    /// Unwrap this PauseAt, returning its underlying Peekable.
    #[allow(unused)]
    pub(crate) fn remaining(self) -> &'a mut Peekable<I> {
        self.peek
    }
    /// Return the next item that will be yielded from this iterator, or
    /// None if this iterator is about to yield None.
    #[allow(unused)]
    pub(crate) fn peek(&mut self) -> Option<&I::Item> {
        // TODO: I wish it weren't necessary for this function to take
        // a mutable reference.
        if self.check_paused() {
            None
        } else {
            self.peek.peek()
        }
    }
    /// Helper: Return true if we will pause before the next element,
    /// and false otherwise.  Store the value in self.paused, so that
    /// we don't invoke self.pred more than once.
    fn check_paused(&mut self) -> bool {
        if let Some(p) = self.paused {
            return p;
        }
        if let Some(nextval) = self.peek.peek() {
            let p = (self.pred)(nextval);
            self.paused = Some(p);
            p
        } else {
            self.paused = Some(false);
            false
        }
    }
}

impl<'a, I: Iterator, F: FnMut(&I::Item) -> bool> Iterator for PauseAt<'a, I, F> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        if self.check_paused() {
            None
        } else {
            self.paused = None;
            self.peek.next()
        }
    }
}

/// A Private module for declaring a "sealed" trait.
pub(crate) mod private {
    /// A non-exported trait, used to prevent others from implementing a trait.
    ///
    /// For more information on this pattern, see [the Rust API
    /// guidelines](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed).
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn test_pause_at() {
        let mut iter = (1..10).into_iter().peekable();
        let mut iter = PauseAt::from_peekable(&mut iter, |x| *x == 3);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), None);

        let mut iter = iter.new_pred(|x| *x > 5);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);

        let iter = iter.remaining();
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.peek(), Some(&7));
        assert_eq!(iter.next(), Some(7));
        assert_eq!(iter.next(), Some(8));
        assert_eq!(iter.next(), Some(9));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_parse_at_mutable() {
        let mut count = 0;
        let mut iter = (1..10).into_iter().peekable();
        // pause at the third item, using mutable state in the closure.
        let mut iter = PauseAt::from_peekable(&mut iter, |_| {
            count += 1;
            count == 4
        });
        assert_eq!(iter.peek(), Some(&1)); // we can do this multiple times,
        assert_eq!(iter.peek(), Some(&1)); // but count isn't advanced.
        assert_eq!(iter.next(), Some(1));

        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.peek(), Some(&3));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
    }
}
