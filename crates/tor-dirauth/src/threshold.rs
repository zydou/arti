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
    // ^ XXXX these functions don't exist yet
    fn is_enough_of(n_y: usize, n_total: usize) -> bool;
}

impl ThresholdRule for MoreThanHalf {
    fn is_enough_of(n_y: usize, n_total: usize) -> bool {
        // This way of writing it avoids any possibility of over/under-flow
        //
        // Tested via ConsensusCommonContext.is_more_than_half_all_auths.
        //
        n_y > n_total / 2
    }
}
