//! Handling thresholds like "at least two thirds"
//!
//! TODO maybe this should be promoted somewhere?

use crate::internal_prelude::*;

/// `>1/2`: `n_y` is strictly more than half of `n_total` - i.e., a majority
///
/// Threshold rule token, implementing [`ThresholdRule`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MoreThanHalf;

/// `>=2/3`: `n_y` is at least two thirds of `n_total`
///
/// Threshold rule token, implementing [`ThresholdRule`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct AtLeastTwoThirds;

/// `>2/3`: `n_y` is strictly more than two thirds of `n_total`
///
/// Threshold rule token, implementing [`ThresholdRule`].
///
/// Used only for selecting the best consensus method,
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#consensus-method-list>
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct StrictlyMoreThanTwoThirds;

/// Threshold rule, such as "at least two thirds"
///
/// Implemented for unit token types [`MoreThanHalf`] [`AtLeastTwoThirds`].
///
/// Use these token types, instead of open-coding,
/// to avoid rounding and off-by-one bugs.
///
/// The rule types can be used with methods from this trait
/// and also with `ConsensusesCommonContext::is_enough_of_all_auths`.
///
// The trait allows sharing code for checking an iterator,
// or checking against a number of authorities:
// there are going to be three rules, and at least three possible testing contexts,
// of which we may use only a subset.  This way it can all be regular.
//
/// The token types do not ever need to be constructed -
/// they are always used as generic parameters.
// This facilitates use with, eg, the consensus `calc!` macro.)
pub(crate) trait ThresholdRule {
    /// Is `n_y` enough of `n_total`, according to a threshold rule ?
    ///
    /// # Correctness - take care with argument order!
    ///
    /// Prefer
    /// [`is_true_for_enough_of`](ThresholdRule::is_true_for_enough_of)
    /// or
    /// `ConsensusesCommonContext::is_enough_of_all_auths`
    /// because those functions eliminate that possible error.
    fn is_enough_of(n_y: usize, n_total: usize) -> bool;

    /// Is `predicate` true for enough of the values in `iterator`?
    //
    // The signature of this function is complicated, compared to the alternative
    //   fn is_for_more_than_half_of(some: usize, all: usize)
    // but makes it impossible to accidentally swap the arguments, or get the wrong
    // total value, or some such.
    //
    // We can't have an infallible version of this, because it needs to throw `Bug`
    // on arithmetic overflow.
    fn is_true_for_enough_of<I, E>(
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
        Ok(Self::is_enough_of(yes, all))
    }
}

impl ThresholdRule for MoreThanHalf {
    fn is_enough_of(n_y: usize, n_total: usize) -> bool {
        // This way of writing it avoids any possibility of over/under-flow
        //
        n_y > n_total / 2
    }
}

impl ThresholdRule for AtLeastTwoThirds {
    fn is_enough_of(n_y: usize, n_total: usize) -> bool {
        // Overflow ought to be impossible since it would involve an unreasonable number
        // of authorities, but in that case return `fale`.
        //
        // The alternative would be to suppress the rule against possibly-panicking arithmetic,
        // which would impose an additional review burden.
        let thresh = match n_total.checked_mul(2) {
            Some(y) => y,
            None => return false,
        }
        .div_ceil(3);

        n_y >= thresh
    }
}

impl ThresholdRule for StrictlyMoreThanTwoThirds {
    fn is_enough_of(n_y: usize, n_total: usize) -> bool {
        // Very similar to `AtLeastTwoThirds::is_enough_of`, but needs different rounding.
        let thresh = match n_total.checked_mul(2) {
            Some(y) => y,
            None => return false,
        } / 3;

        n_y > thresh
    }
}

#[cfg(test)]
pub(crate) mod test {
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
    #![allow(clippy::arithmetic_side_effects)]
    use super::*;

    /// Checks that `Rule` gives the same answers as `reference`
    ///
    /// Unlike `Rule`'s impl, `reference` doesn't need to use panic-free arithmetic,
    /// so it can be simple and obvious.
    fn check_against_reference<Rule: ThresholdRule>(reference: impl Fn(usize, usize) -> bool) {
        for total in 0..20 {
            for y in 0..=total {
                assert_eq!(
                    Rule::is_enough_of(y, total),
                    reference(y, total),
                    "{y}/{total}",
                );
            }
        }
    }

    /// Check that `Rule` is `true` for `total` iff `y` >= `minimum`
    fn check_minimum<Rule: ThresholdRule>(total: usize, minimum: usize) {
        for y in 0..=(total + 1) {
            assert_eq!(
                Rule::is_enough_of(y, total),
                y >= minimum,
                "{y}/{total} {minimum}",
            );
        }
    }

    #[test]
    fn more_than_half() {
        check_against_reference::<MoreThanHalf>(|y, total| y * 2 > total);

        let minimum = check_minimum::<MoreThanHalf>;
        minimum(0, 1);
        minimum(1, 1);
        minimum(2, 2);
        minimum(3, 2);
        minimum(4, 3);
        minimum(5, 3);
    }

    #[test]
    fn at_least_two_thirds() {
        check_against_reference::<AtLeastTwoThirds>(|y, total| 3 * y >= 2 * total);

        let minimum = check_minimum::<AtLeastTwoThirds>;
        minimum(0, 0);
        minimum(1, 1);
        minimum(2, 2);
        minimum(3, 2);
        minimum(4, 3);
        minimum(5, 4);
        minimum(6, 4);
        minimum(7, 5);
        minimum(8, 6);
        minimum(9, 6);
    }

    #[test]
    fn strictly_more_than_two_thirds() {
        check_against_reference::<StrictlyMoreThanTwoThirds>(|y, total| 3 * y > 2 * total);

        let minimum = check_minimum::<StrictlyMoreThanTwoThirds>;
        minimum(0, 1);
        minimum(1, 1);
        minimum(2, 2);
        minimum(3, 3);
        minimum(4, 3);
        minimum(5, 4);
        minimum(6, 5);
        minimum(7, 5);
        minimum(8, 6);
        minimum(9, 7);
    }

    /// Threshold rule for testing, with exciting behaviour
    ///
    /// Asserts that we were asked "is 1 out of 2 enough?".
    ///
    /// The return value is not interesting.
    pub(crate) struct ExpectOneOutOfTwo;

    impl ThresholdRule for ExpectOneOutOfTwo {
        fn is_enough_of(y: usize, total: usize) -> bool {
            assert_eq!(y, 1);
            assert_eq!(total, 2);
            true
        }
    }

    #[test]
    fn enough_of_iter() {
        ExpectOneOutOfTwo::is_true_for_enough_of(0..2, |i| Ok::<_, Bug>(i < 1)).unwrap();
    }
}
