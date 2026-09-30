//! General functions for use in consensus calculations
//!
//! Eg with signatures like [`Aggregate::aggregate`]

use super::*;

/// Return the low median of the inputs
pub(super) fn low_median<'i, T: Ord + Clone + 'i, AC>(
    _context: ConsensusContextRefs<AC>,
    inputs: impl ComponentInVotes<&'i T>,
) -> Result<T, ConsensusError> {
    low_median_raw(inputs.map(|(_vnum, v)| v.clone())).ok_or(ConsensusError::NoVotes)
}

/// Return the low median of the inputs, without cloning, and without context
pub(super) fn low_median_raw<'i, T: Ord + 'i>(inputs: impl Iterator<Item = T>) -> Option<T> {
    let mut all = inputs.collect_vec();
    all.sort();
    let i = all.len().checked_sub(1)? / 2;
    all.into_iter().nth(i)
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
    fn low_medians() {
        let check = |exp: i32, inp: &[i32]| {
            assert_eq!(low_median_raw(inp.iter().cloned()), Some(exp), "{inp:?}");
        };

        assert_eq!(low_median_raw::<i32>([].into_iter()), None);
        check(1, &[1]);
        check(1, &[1, 2]);
        check(2, &[1, 2, 3]);
        check(2, &[1, 2, 3, 4]);
        check(3, &[1, 2, 3, 4, 5]);
    }
}
