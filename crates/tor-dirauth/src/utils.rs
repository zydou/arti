//! Miscellaneous utilities

use crate::internal_prelude::*;

/// Wrapper for `todo!` which avoids daft warnings everywhere
///
/// TOOD DIRAUTH abolish `todo` wrapper, getting rid of panics.
pub(super) fn todo<T>() -> T {
    todo!()
}

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

#[ext(name = IteratorExt)]
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
