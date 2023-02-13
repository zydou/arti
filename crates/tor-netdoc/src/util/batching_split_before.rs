//! Iterator extension for splitting into batches, each introduced by a batch-starting item
//!
//! See
//! [`IteratorExt::batching_split_before_loose`] and
//! [`IteratorExt::batching_split_before_prefixed`].

use std::iter::{self, Peekable};
use std::marker::PhantomData;

/// An iterator with a `.peek()` method
///
/// We make this a trait to avoid entangling all the types with `Peekable`.
/// Ideally we would do this with `Itertools::PeekingNext`
/// but that's not implemented for `&mut PeekingNext`,
/// and we need that because we use a lot of `&mut NetdocReader`.
/// <https://github.com/rust-itertools/itertools/issues/678>
pub trait PeekableIterator: Iterator {
    /// Inspect the next item, if there is one
    fn peek(&mut self) -> Option<&Self::Item>;
}

impl<I: Iterator> PeekableIterator for Peekable<I> {
    fn peek(&mut self) -> Option<&Self::Item> {
        self.peek()
    }
}

impl<I: PeekableIterator> PeekableIterator for &mut I {
    fn peek(&mut self) -> Option<&Self::Item> {
        <I as PeekableIterator>::peek(*self)
    }
}

/// Iterator for the prefix, transformable into a [`Batches`] yielding subsequent batches
pub struct BatchesWithPrefix<II, I, F> {
    /// Input
    input: Input<II, I, F>,
}

/// Input, shared by our public structs
struct Input<II, I, F> {
    /// The input iterator
    unfiltered: I,
    /// Callback to test if this is batch-starting
    batch_starting: F,
    /// We're like a function that yields II
    marker: PhantomData<fn() -> II>,
}

/// An iterator-like object yielding an iterator for each batch.
///
/// Each call to [`.next_batch()`](Batches::next_batch)
/// yields an iterator for one subsequent batch,
/// which in turn will yield the individual items.
///
/// `Batches` is not an [`Iterator`] because
/// its returned item type (the sub-iterator)
/// borrows it mutably.
pub struct Batches<II, I, F> {
    /// Input
    input: Input<II, I, F>,
    /// Should we avoid draining the end of the previous batch
    no_drain: Option<()>,
    /// Should we yield even (one) batch-starting item
    yield_one: Option<()>,
}

/// Iterator to yield the members of a batch. 
///
/// This is the iterator returned by
/// [`.next_batch()`](Batches::next_batch).
pub struct Batch<'p, II, I, F> {
    /// The parent, with all the actual state etc.
    ///
    /// It is less confusing to keep all the state in the parent iterator.
    parent: &'p mut Batches<II, I, F>,
}

impl<II, I, F> Input<II, I, F>
where
    I: Iterator<Item = II> + PeekableIterator,
    F: FnMut(&II) -> bool,
{
    /// Yield the next item - unless it is batch-starting.
    fn next_non_starting(&mut self) -> Option<II> {
        let item = self.unfiltered.peek()?;
        if (self.batch_starting)(item) {
            return None;
        };
        self.unfiltered.next()
    }
}

impl<II, I, F> Iterator for BatchesWithPrefix<II, I, F>
where
    I: Iterator<Item = II> + PeekableIterator,
    F: FnMut(&II) -> bool,
{
    type Item = II;

    fn next(&mut self) -> Option<II> {
        self.input.next_non_starting()
    }
}

impl<II, I, F> BatchesWithPrefix<II, I, F>
where
    I: Iterator<Item = II> + PeekableIterator,
    F: FnMut(&II) -> bool,
{
    /// Proceed from the prefix to the subsequent batches
    ///
    /// Any un-yielded items remaining in the prefix will be discarded.
    pub fn subsequent(mut self) -> Batches<II, I, F> {
        // Discard any un-yielded contents of the prefix
        let _ = self.by_ref().count();

        Batches {
            input: self.input,
            yield_one: None,
            no_drain: None,
        }
    }
}

impl<II, I, F> Iterator for Batch<'_, II, I, F>
where
    I: Iterator<Item = II> + PeekableIterator,
    F: FnMut(&II) -> bool,
{
    type Item = II;

    fn next(&mut self) -> Option<II> {
        if self.parent.yield_one.take().is_some() {
            self.parent.input.unfiltered.next()
        } else {
            self.parent.input.next_non_starting()
        }
    }
}

impl<II, I: Iterator<Item = II> + PeekableIterator, F: FnMut(&II) -> bool> Batches<II, I, F> {
    /// Proceed to the next batch
    ///
    /// If the input is exhausted (ie, there is no next batch), returns `None`.
    ///
    /// Any un-yielded items remaining in the previous batch will be discarded.
    //
    // SubsquentBatches is a LendingIterator, so can't be Iterator.
    pub fn next_batch(&mut self) -> Option<Batch<'_, II, I, F>> {
        // Drain to the end of the batch
        if self.no_drain.take().is_none() {
            let _ = Batch { parent: self }.count();
        }
        let _: &II = self.input.unfiltered.peek()?;
        self.yield_one = Some(());
        Some(Batch { parent: self })
    }

    /// Map each batch
    pub fn map<T>(
        mut self,
        mut f: impl FnMut(Batch<'_, II, I, F>) -> T,
    ) -> impl Iterator<Item = T> {
        iter::from_fn(move || {
            let batch = self.next_batch()?;
            Some(f(batch))
        })
    }
}

/// **Extension trait providing `batching_split_before`**
pub trait IteratorExt: Iterator + Sized {
    /// Splits the input into a prefix followed by batches started according to a predicate
    ///
    /// The input is divided into:
    ///  * A prefix, containing no batch-starting items
    ///  * Zero or more subsequent batches, each with precisely one batch-starting item
    ///
    /// The returned value from `batching_split_before` is an iterator,
    /// which yields the elements in the prefix - before the first batch-starting item.
    ///
    /// After processing the prefix, call
    /// [`.subsequent()`](BatchesWithPrefix)
    /// which will return a meta-iterator for the subsequent batches.
    ///
    /// Each subsequent batch is then returned by calling
    /// [`.next_batch()`](Batches::next_batch)
    /// which yields a separate sub-iterator.
    ///
    /// A new batch is recognised for each input item for which `batch_starting` returns true.
    ///
    /// This method is named **prefixed** because it separates out the prefix,
    /// using a typestate pattern, which is convenient for processing the prefix
    /// separately.
    ///
    /// (You will want to iterate the first batch by reference,
    /// so that the iteration doesn't consume the [`BatchesWithPrefix`],
    /// which is what you will need to call `.subsequent()`.
    /// You must process the batches sequentially;
    /// so can only be processing one batch at a time.)
    ///
    /// # **UNSTABLE**
    ///
    /// This method is UNSTABLE and not part of the semver guarantees.
    /// You'll only see it if you ran rustdoc with `--document-private-items`.
    ///
    /// # Example
    ///
    /// ```
    /// use itertools::Itertools as _;
    /// use tor_netdoc::batching_split_before::IteratorExt as _;
    ///
    /// let mut batches = (1..10).peekable().batching_split_before_prefixed(|v| v % 3 == 0);
    /// assert_eq!(batches.by_ref().collect_vec(), [ 1, 2 ]);
    ///
    /// let mut batches = batches.subsequent();
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 3, 4, 5 ]);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 6, 7, 8 ]);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 9 ]);
    /// assert!(batches.next_batch().is_none());
    /// ```
    fn batching_split_before_prefixed<F>(
        self,
        batch_starting: F,
    ) -> BatchesWithPrefix<Self::Item, Self, F>
    where
        F: FnMut(&Self::Item) -> bool,
    {
        let input = Input {
            unfiltered: self,
            batch_starting,
            marker: PhantomData,
        };
        BatchesWithPrefix { input }
    }

    /// Splits the input into batches, with new batches started according to a predicate
    ///
    /// The input is divided into batches, just before each batch-starting item.
    /// The batch-starting item is included as the first item of every batch,
    /// except the first batch if the input starts with a non-batch-starting-item.
    ///
    /// If the input iterator is empty, there are no batches.
    ///
    /// This method is named **loose** because it neither
    /// insists that the iterator start with a batch-starting item,
    /// nor returns batches which always start with a batch-starting item.
    /// It is up to the caller to handle a possible first batch with no batch-starting item.
    ///
    /// Each batch is returned by calling
    /// [`.next_batch()`](Batches::next_batch)
    /// which yields a separate sub-iterator.
    ///
    /// A new batch is recognised for each input item for which `batch_start` returns true.
    ///
    /// (You must process the batches sequentially;
    /// so can only be processing one batch at a time.)
    ///
    /// # **UNSTABLE**
    ///
    /// This method is UNSTABLE and not part of the semver guarantees.
    /// You'll only see it if you ran rustdoc with `--document-private-items`.
    ///
    /// # Example
    ///
    /// ```
    /// use itertools::Itertools as _;
    /// use tor_netdoc::batching_split_before::IteratorExt as _;
    ///
    /// let mut batches = (1..10).peekable().batching_split_before_loose(|v| v % 3 == 0);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 1, 2 ]);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 3, 4, 5 ]);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 6, 7, 8 ]);
    /// assert_eq!(batches.next_batch().unwrap().collect_vec(), [ 9 ]);
    /// assert!(batches.next_batch().is_none());
    /// ```
    fn batching_split_before_loose<F>(self, batch_starting: F) -> Batches<Self::Item, Self, F>
    where
        F: FnMut(&Self::Item) -> bool,
    {
        let input = Input {
            unfiltered: self,
            batch_starting,
            marker: PhantomData,
        };
        Batches {
            input,
            no_drain: Some(()),
            yield_one: None,
        }
    }
}
impl<I: Iterator> IteratorExt for I {}

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
    use itertools::chain;
    use std::fmt::Debug;
    use std::iter;

    struct TrackingPeekable<I: Iterator>(Peekable<I>);
    impl<I: Iterator> Iterator for TrackingPeekable<I>
    where
        I::Item: Debug,
    {
        type Item = I::Item;
        fn next(&mut self) -> Option<I::Item> {
            let v = self.0.next();
            eprintln!("        iter yielded {v:?}");
            v
        }
    }
    impl<I: Iterator> PeekableIterator for TrackingPeekable<I>
    where
        I::Item: Debug,
    {
        fn peek(&mut self) -> Option<&I::Item> {
            let v = self.0.peek();
            eprintln!("        iter peeked {v:?}");
            v
        }
    }

    #[test]
    fn test_batching_split_before() {
        fn chk_exp(mut iter: impl Iterator<Item = u32>, exp: &[u32]) {
            eprintln!("    exp {exp:?}");
            for exp in exp.iter().cloned() {
                assert_eq!(iter.next(), Some(exp));
            }
            assert_eq!(iter.next(), None);
            assert_eq!(iter.next(), None);
            assert_eq!(iter.next(), None);
        }

        let chk_breakdown = |input: &[u32], iexp: &[u32], sexp: &[&[u32]]| {
            let chk_batches = |mut subseq: Batches<_, _, _>, sexp: &mut dyn Iterator<Item = _>| {
                loop {
                    match (subseq.next_batch(), sexp.next()) {
                        (Some(batch), Some(sexp)) => chk_exp(batch, sexp),
                        (None, None) => break,
                        (b, e) => panic!("({:?}, {e:?}", b.map(|_| ())),
                    }
                }
                assert!(subseq.next_batch().is_none());
                assert!(subseq.next_batch().is_none());
            };

            eprintln!("input {input:?}");
            let input = || TrackingPeekable(input.iter().cloned().peekable());
            let is_starting = |v: &u32| *v >= 10;

            {
                let mut prefix = input().batching_split_before_prefixed(is_starting);

                chk_exp(&mut prefix, iexp);
                eprintln!("    subsequent...");
                let subseq = prefix.subsequent();
                let mut sexp = sexp.iter().cloned();
                chk_batches(subseq, &mut sexp);
            }

            {
                let batches = input().batching_split_before_loose(is_starting);

                let mut sexp =
                    chain!(iter::once(iexp), sexp.iter().cloned(),).filter(|s| !s.is_empty());

                chk_batches(batches, &mut sexp);
            }
        };

        chk_breakdown(&[], &[], &[]);

        chk_breakdown(&[10], &[], &[&[10]]);

        chk_breakdown(
            &[1, 2, 30, 4, 5, 60, 7, 8],
            &[1, 2],
            &[&[30, 4, 5], &[60, 7, 8]],
        );
    }
}
