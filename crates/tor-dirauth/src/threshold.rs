//! Handling thresholds like "at least two thirds"
//!
//! TODO maybe this should be promoted somewhere?

use crate::internal_prelude::*;

/// `>1/2`: `n_y` is strictly more than half of `n_total` - i.e., a majority
///
/// Threshold rule token, implementing [`ThresholdRule`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MoreThanHalf;

/// Threshold rule, such as "at least two thirds"
///
/// Implemented for unit token types [`MoreThanHalf`] [`AtLeastTwoThirds`].
// ^ XXXX AtLeastTwoThirds doesn't exist yet
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

    /// Is `predicate` true for more than half the values in `iterator`?
    //
    // The signature of this function is complicated, compared to the alternative
    //   fn is_for_more_than_half_of(some: usize, all: usize)
    // but makes it impossible to accidentally swap the arguments, or get the wrong
    // total value, or some such.
    fn is_true_for_enough_of<I, E>(
        iterator: impl IntoIterator<Item = I>,
        predicate: impl Fn(I) -> Result<bool, E>,
    ) -> Result<bool, E>
    where
        Self: Sized,
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
        let minimum = check_minimum::<MoreThanHalf>;
        minimum(0, 1);
        minimum(1, 1);
        minimum(2, 2);
        minimum(3, 2);
        minimum(4, 3);
        minimum(5, 3);
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
