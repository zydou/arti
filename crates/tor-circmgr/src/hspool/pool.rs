//! An internal pool object that we use to implement HsCircPool.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use rand::Rng;
use tor_basic_utils::RngExt as _;
use tor_proto::circuit::ClientCirc;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::{VanguardConfig, VanguardMode};

/// A collection of circuits used to fulfil onion-service-related requests.
pub(super) struct Pool {
    /// The collection of circuits themselves, in no particular order.
    circuits: Vec<Arc<ClientCirc>>,

    /// The number of elements that we would like to have in our pool.
    ///
    /// We do not discard when we are _above_ this threshold, but we do
    /// try to build when we are low.
    target: usize,

    /// True if we have exhausted our pool since the last time we decided
    /// whether to change our target level.
    have_been_exhausted: bool,

    /// True if we have been under 4/5 of our target since the last time we
    /// decided whether to change it.
    have_been_under_highwater: bool,

    /// Last time when we changed our target size.
    last_changed_target: Option<Instant>,

    /// The kind of vanguards that are in use.
    ///
    /// All the circuits from `circuits` use the type of vanguards specified here.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    mode: VanguardMode,
}

/// Our default (and minimum) target pool size.
const DEFAULT_TARGET: usize = 4;

/// Our maximum target pool size.  We will never let our target grow above this
/// value.
const MAX_TARGET: usize = 512;

impl Default for Pool {
    fn default() -> Self {
        Self {
            circuits: Vec::new(),
            target: DEFAULT_TARGET,
            have_been_exhausted: false,
            have_been_under_highwater: false,
            last_changed_target: None,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            mode: VanguardMode::default(),
        }
    }
}

impl Pool {
    /// Add `circ` to this pool
    pub(super) fn insert(&mut self, circ: Arc<ClientCirc>) {
        self.circuits.push(circ);
    }

    /// Remove every circuit from this pool for which `f` returns false.
    pub(super) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Arc<ClientCirc>) -> bool,
    {
        self.circuits.retain(f);
    }

    /// Return true if we are very low on circuits and should build more immediately.
    pub(super) fn very_low(&self) -> bool {
        self.circuits.len() <= self.target / 3
    }

    /// Return the number of circuits we would currently like to launch.
    pub(super) fn n_to_launch(&self) -> usize {
        self.target.saturating_sub(self.circuits.len())
    }

    /// If there is any circuit in this pool for which `f`  returns true, return one such circuit at random, and remove it from the pool.
    pub(super) fn take_one_where<R, F>(&mut self, rng: &mut R, f: F) -> Option<Arc<ClientCirc>>
    where
        R: Rng,
        F: Fn(&Arc<ClientCirc>) -> bool,
    {
        // Select a circuit satisfying `f` at random.
        let rv = match random_idx_where(rng, &mut self.circuits[..], f) {
            Some(idx) => Some(self.circuits.swap_remove(idx)),
            None => None,
        };

        if self.circuits.is_empty() {
            self.have_been_exhausted = true;
            self.have_been_under_highwater = true;
        } else if self.circuits.len() < self.target * 4 / 5 {
            self.have_been_under_highwater = true;
        }

        rv
    }

    /// Update the target size for our pool.
    pub(super) fn update_target_size(&mut self, now: Instant) {
        /// Minimum amount of time that must elapse between a change and a
        /// decision to grow our pool.  We use this to control the rate of
        /// growth and make sure that we are allowing enough time for circuits
        /// to complete.
        const MIN_TIME_TO_GROW: Duration = Duration::from_secs(120);
        /// Minimum amount of time that must elapse between a target change and
        /// a decisions to shrink our target.  We use this to make sure that we
        /// aren't shrinking too rapidly, and that we are allowing enough time
        /// for the pool to actually get used.
        const MIN_TIME_TO_SHRINK: Duration = Duration::from_secs(600);

        let last_changed = self.last_changed_target.get_or_insert(now);
        let time_since_last_change = now.saturating_duration_since(*last_changed);

        if self.have_been_exhausted {
            if time_since_last_change < MIN_TIME_TO_GROW {
                return;
            }
            self.target *= 2;
        } else if !self.have_been_under_highwater {
            if time_since_last_change < MIN_TIME_TO_SHRINK {
                return;
            }

            self.target /= 2;
        }
        self.last_changed_target = Some(now);
        self.target = self.target.clamp(DEFAULT_TARGET, MAX_TARGET);
        self.have_been_exhausted = false;
        self.have_been_under_highwater = false;
    }

    /// Handle vanguard configuration changes.
    ///
    /// If new config has a different [`VanguardMode`] enabled,
    /// this empties the circuit pool.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    #[allow(clippy::unnecessary_wraps)] // for consistency and future-proofing
    pub(super) fn reconfigure_vanguards(
        &mut self,
        config: &VanguardConfig,
    ) -> Result<(), tor_config::ReconfigureError> {
        let mode = config.mode();

        if self.mode != mode {
            self.mode = mode;
            self.have_been_exhausted = true;

            // Purge all circuits from this pool
            self.circuits.clear();
        }

        Ok(())
    }
}

/// Helper: find a random item `elt` in `slice` such that `predicate(elt)` is
/// true. Return the index of that item.
///
/// Can arbitrarily reorder `slice`. This allows us to visit the indices in uniform-at-random
/// order, without having to do any O(N) operations or allocations.
fn random_idx_where<R, T, P>(rng: &mut R, mut slice: &mut [T], predicate: P) -> Option<usize>
where
    R: Rng,
    P: Fn(&T) -> bool,
{
    while !slice.is_empty() {
        let idx = rng
            .gen_range_checked(0..slice.len())
            .expect("slice was not empty but is now empty");
        if predicate(&slice[idx]) {
            return Some(idx);
        }
        let last_idx = slice.len() - 1;
        // Move the one we just tried to the end,
        // and eliminate it from consideration.
        slice.swap(idx, last_idx);
        slice = &mut slice[..last_idx];
    }
    // We didn't find any.
    None
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn random_idx() {
        let mut rng = testing_rng();
        let mut orig_numbers: Vec<i32> = vec![1, 3, 4, 8, 11, 19, 12, 6, 27];
        let mut numbers = orig_numbers.clone();

        let mut found: std::collections::HashMap<i32, bool> =
            numbers.iter().map(|n| (*n, false)).collect();

        for _ in 0..1000 {
            let idx = random_idx_where(&mut rng, &mut numbers[..], |n| n & 1 == 1).unwrap();
            assert!(numbers[idx] & 1 == 1);
            found.insert(numbers[idx], true);
        }

        for num in numbers.iter() {
            assert!(found[num] == (num & 1 == 1));
        }

        // Number may be reordered, but should still have the same elements.
        numbers.sort();
        orig_numbers.sort();
        assert_eq!(numbers, orig_numbers);
    }

    #[test]
    fn random_idx_empty() {
        let mut rng = testing_rng();
        let idx = random_idx_where(&mut rng, &mut [], |_: &i32| panic!());
        assert_eq!(idx, None);
    }

    #[test]
    fn random_idx_none() {
        let mut rng = testing_rng();
        let mut numbers: Vec<i32> = vec![1, 3, 4, 8, 11, 19, 12, 6, 27];
        assert_eq!(
            random_idx_where(&mut rng, &mut numbers[..], |_: &i32| false),
            None
        );
    }
}
