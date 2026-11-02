//! General functions for use in consensus calculations
//!
//! Eg with signatures like [`Aggregate::aggregate`]

use super::*;

/// Return the low median of the inputs
#[allow(clippy::needless_pass_by_value)]
pub(super) fn low_median<'i, T: Ord + Clone + 'i, AC>(
    _context: ConsensusContextRefs<AC>,
    inputs: impl ComponentInVotes<&'i T>,
) -> Result<T, ConsensusError> {
    low_median_raw(inputs.votes().cloned()).ok_or(ConsensusError::NoVotes)
}

/// Return the low median of the inputs, without cloning, and without context
pub(super) fn low_median_raw<'i, T: Ord + 'i>(inputs: impl Iterator<Item = T>) -> Option<T> {
    let mut all = inputs.collect_vec();
    all.sort();
    let i = all.len().checked_sub(1)? / 2;
    all.into_iter().nth(i)
}

/// Return the value which is most popular
///
/// If there are several values which are equally most popular,
/// ties are broken in favour of the earliest according to `ord`.
/// (We avoid calling `ord` unless it is necessary.)
///
/// This is used for `v` and `pr` items in routerstatuses:
///  * <https://spec.torproject.org/dir-spec/computing-consensus.html>
///  * <https://spec.torproject.org/dir-spec/consensus-formats.html#item:pr>
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
pub(super) fn choose_most_popular_amongst_votes<'i, T, K, AC>(
    _context: ConsensusContextRefs<AC>,
    inputs: impl ComponentInVotes<&'i T>,
    ord_key: impl Fn(&'i T) -> K,
) -> Result<Option<T>, ConsensusError>
where
    T: Eq + Hash + Clone + 'i,
    K: Ord,
{
    let counts = inputs.votes().counts();

    let Some(best) = counts.values().copied().max() else {
        return Ok(None);
    };

    Ok(counts
        .into_iter()
        .filter(|&(_v, count)| count == best)
        .map(|(v, _count)| v)
        .at_most_one()
        .unwrap_or_else(|several| several.min_by_key(|v| ord_key(*v)))
        .cloned())
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
