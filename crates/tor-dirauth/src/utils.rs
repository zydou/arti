//! Miscellaneous utilities

use crate::internal_prelude::*;

pub mod bool_indexed_array;
pub(crate) use bool_indexed_array::*;

/// What `RangeInclusive::map` ought to be
///
/// Open-coding this at the call site would risk accidental change of the range type,
/// changing inclusiveness, etc.  This function has the same range type as argument and return.
pub(crate) fn map_range<T, U>(
    r: &RangeInclusive<T>,
    mut f: impl FnMut(&T) -> U,
) -> RangeInclusive<U> {
    f(r.start())..=f(r.end())
}

#[ext(name = IteratorExtUnzip)]
pub(crate) impl<AI, BI, I> I
where
    I: Iterator<Item = (Option<AI>, Option<BI>)>,
{
    /// Collect and filter an iterator yielding tuples of options into two collections.
    ///
    /// Takes an iterator yielding `(Option<AI>, Option<AB>)` and collects the
    /// `Some`s into a tuple of the two collections, of `AI` and `BI` respectively.
    //
    // TODO DIRAUTH consider moving this to tor-basic-utils or itertools or something.
    fn filter_collect_unzip<AC, BC>(self) -> (AC, BC)
    where
        AC: Default + Extend<AI>,
        BC: Default + Extend<BI>,
    {
        let mut ac = AC::default();
        let mut bc = BC::default();
        for (ao, bo) in self {
            ac.extend(ao);
            bc.extend(bo);
        }
        (ac, bc)
    }
}

#[ext(name = IteratorExt)]
pub(crate) impl<I> I
where
    I: Iterator,
{
    /// Filter items using a fallible predicate
    ///
    /// Returns an iterator of `Result`.
    //
    // TODO DIRAUTH consider moving this to tor-basic-utils or itertools or something.
    fn try_filter<'r, F, E>(self, mut f: F) -> impl Iterator<Item = Result<I::Item, E>> + 'r
    where
        I: 'r,
        F: FnMut(&I::Item) -> Result<bool, E> + 'r,
    {
        self.filter_map(move |item| match f(&item) {
            Ok(false) => None,
            Ok(true) => Some(Ok(item)),
            Err(e) => Some(Err(e)),
        })
    }
}

#[ext(name = TryAddAssign)]
pub(crate) impl<T: num_traits::CheckedAdd> T {
    /// `+=` but throws bug on overflow.
    //
    // `try` rather than `checked` because `checked_add_assign` ought to return `Option<()>`
    // by analogy with `.checked_add`.
    fn try_add_assign(&mut self, v: Self) -> Result<(), Bug> {
        *self = self
            .checked_add(&v)
            .ok_or_else(|| internal!("addition overflow"))?;
        Ok(())
    }
}

/// Helper for deferring handling of `None`, temporarily substituting dummy values
///
/// Our macros like things to be uniform.  For exaempl, when calculating a pair of
/// routerstatuses, they want us to generate both in parallel.
///
/// But sometimes we want to be able to "early exit" from calculating an md rs,
/// for example if we discover that voters don't agree enough on the md hash.
///
/// This utility type allows us to "defer the early exit":
/// instead of returning early, we make a note in the
/// `NoneDefer` that we ought to be returning early.
///
/// And then we can safely fill in dummy values, knowing that they won't leak.
///
/// # Correctness - manual checks needed!
///
///  * You must ensure to call `.finish()` in your return path.
///    There is no engineered safeguard against forgetting to do so.
///
///  * The return from every call to `handle` must *only*
///    go into the output value that will be fed to `.finish()`.
///    Again, there is no engineered safeguard against getting this wrong.
///
///  * Do not attempt to have multiple `NoneDefer` in the same function.
///    There is nothing stopping you using the wrong one.
//
// Still, this is better than something more ad-hoc, such as "just a local boolean".
// And given that there's only one call site atm, this is probably a reasonable compromise.
pub(crate) struct NoneDefer<O> {
    /// Are we live?
    ///
    /// `Some` means we can still return `Some` from `finish`,
    /// and no dummy values have been substituted.
    ///
    /// `None` means we've `handle`d a `Noen`.
    ok: Option<()>,

    /// Bind this to the output type.
    ///
    /// This is not strictly necessary to uphold the promised assurances,
    /// but it seems like a good idea.
    marker: PhantomData<fn(O) -> O>,
}

impl<O> NoneDefer<O> {
    /// Create a new `NoneDefer`, which is initialised as "all is good, we'll return `Some`"
    pub(crate) fn new() -> Self {
        NoneDefer {
            ok: Some(()),
            marker: PhantomData,
        }
    }

    /// Handle a value that might be `None`, deferring and substituting if necessary
    ///
    /// If `v` is `Ok(Some(_))` or `Err()`, it is passed through.
    ///
    /// If `v` is `Ok(None`, remembers in `self` that we should be returning `None`.
    /// and then calls `fallback` to generate a dummy value.
    ///
    /// # Correctness
    ///
    /// The returned `Ok` value must only flow into the input to `finish`.
    /// See the [type-level docs](NoneDefer).
    pub(crate) fn handle<V, E, F>(&mut self, v: Result<Option<V>, E>, fallback: F) -> Result<V, E>
    where
        F: FnOnce() -> V,
    {
        Ok(match v? {
            Some(v) => v,
            None => {
                self.ok = None;
                fallback()
            }
        })
    }

    /// End the deferral of `Noen`s
    ///
    /// If we substituted any dummy value in a `handle` call, returns `None`.
    ///
    /// Otherwise returns `Some(o)`.
    pub(crate) fn finish(self, o: O) -> Option<O> {
        self.ok.map(|()| o)
    }
}
