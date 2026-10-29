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

/// Is `n_y` strictly more than half of `n_total` ?
///
/// Use this instead of open-coding, to avoid rounding and off-by-one bugs.
///
/// # Correctness - take care with argument order!
///
/// Prefer [`is_true_for_more_than_half_of`] or
/// `ConsensusesCommonContext::is_more_than_half_all_auths`
/// because those functions eliminate that possible error.
pub(super) fn is_more_than_half_of(n_y: usize, n_total: usize) -> bool {
    // This way of writing it avoids any possibility of over/under-flow
    //
    // Tested via ConsensusCommonContext.is_more_than_half_all_auths.
    //
    n_y > n_total / 2
}

/// Is `predicate` true for more than half the values in `iterator`?
//
// The signature of this function is complicated, compared to the alternative
//   fn is_for_more_than_half_of(some: usize, all: usize)
// but makes it impossible to accidentally swap the arguments, or get the wrong
// total value, or some such.
pub(super) fn is_true_for_more_than_half_of<I, E>(
    iterator: impl IntoIterator<Item = I>,
    predicate: impl Fn(I) -> Result<bool, E>,
) -> Result<bool, E>
where
    E: From<Bug>,
{
    let mut all = 0;
    let mut yes = 0;
    for i in iterator {
        all.try_add_assign(1)?;
        if predicate(i)? {
            yes.try_add_assign(1)?;
        }
    }
    Ok(is_more_than_half_of(yes, all))
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn is_true_for_more_than_half_of_t() -> Result<(), Bug> {
        // This test case is quite like is_more_than_half_all_auths in framework.rs

        let check = |n_all: usize, minimum_that_is_more_than_half| {
            for t in 0..=n_all {
                let cheat = Cell::new(t);
                // returns true t times, and then returns false
                let predicate = |_| {
                    Ok::<_, Bug>(match cheat.get().checked_sub(1) {
                        None => false,
                        Some(less) => {
                            cheat.set(less);
                            true
                        }
                    })
                };
                assert_eq! {
                    is_true_for_more_than_half_of(0..n_all, predicate)?,
                    t >= minimum_that_is_more_than_half,
                }
            }
            Ok::<_, Bug>(())
        };

        check(0, 1)?;
        check(1, 1)?;
        check(2, 2)?;
        check(3, 2)?;
        check(4, 3)?;
        check(5, 3)?;

        Ok(())
    }
}
