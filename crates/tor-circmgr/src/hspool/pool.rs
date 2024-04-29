//! An internal pool object that we use to implement HsCircPool.

use std::time::{Duration, Instant};

use crate::hspool::{HsCircStub, HsCircStubKind};
use rand::Rng;
use tor_basic_utils::RngExt as _;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::VanguardConfig;

use tor_guardmgr::VanguardMode;

/// A collection of circuits used to fulfil onion-service-related requests.
pub(super) struct Pool {
    /// The collection of circuits themselves, in no particular order.
    circuits: Vec<HsCircStub>,

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
    mode: VanguardMode,
}

/// Our default (and minimum) target pool size.
const DEFAULT_TARGET: usize = 4;

/// Our maximum target pool size.  We will never let our target grow above this
/// value.
const MAX_TARGET: usize = 512;

/// The fraction of circuits that should be STUB.
///
/// We will launch (1 - STUB_CIRC_RATIO) STUB+ circuits.
//
// TODO: the ideal STUB/STUB+ ratio will depend on whether arti is running as a client or as a
// hidden service. In general, launching more STUB circuits than STUB+ ones is a safe bet, because
// STUB circuits can become STUB+, but not vice-versa
//
// That being said, this value is arbitrary and might need to be tweaked.
const STUB_CIRC_RATIO: f32 = 0.7;

/// A type of circuit we would like to launch.
///
/// [`ForLaunch::note_circ_launched`] should be called whenever a circuit
/// of this [`HsCircStubKind`] is launched, to decrement the internal target `count`.
pub(super) struct ForLaunch<'a> {
    /// The kind of circuit we want to launch.
    kind: HsCircStubKind,
    /// How many circuits of this kind do we need?
    ///
    /// This is a mutable reference to one of the target values from [`CircsToLaunch`];
    /// we decrement it when we have launched a circuit of this type.
    count: &'a mut usize,
}

impl<'a> ForLaunch<'a> {
    /// A circuit was launched, decrement the current target for its kind.
    pub(super) fn note_circ_launched(self) {
        *self.count -= 1;
    }

    /// The kind of circuit we want to launch.
    pub(super) fn kind(&self) -> HsCircStubKind {
        self.kind
    }
}

/// The circuits we need to launch.
///
/// See also the [`STUB_CIRC_RATIO`] docs.
pub(super) struct CircsToLaunch {
    /// The number of STUB circuits we want to launch.
    stub_target: usize,
    /// The number of STUB+ circuits we want to launch.
    ext_stub_target: usize,
}

impl CircsToLaunch {
    /// Return a [`ForLaunch`] representing a circuit we would like to launch.
    pub(super) fn for_launch(&mut self) -> ForLaunch {
        // We start by launching STUB circuits.
        if self.stub_target > 0 {
            ForLaunch {
                kind: HsCircStubKind::Stub,
                count: &mut self.stub_target,
            }
        } else {
            // If we have enough STUB circuits, we can start launching STUB+ ones too.
            ForLaunch {
                kind: HsCircStubKind::Extended,
                count: &mut self.ext_stub_target,
            }
        }
    }

    /// Return the number of STUB circuits we would like to launch.
    pub(super) fn stub(&self) -> usize {
        self.stub_target
    }

    /// Return the number of STUB+ circuits we would like to launch.
    pub(super) fn ext_stub(&self) -> usize {
        self.ext_stub_target
    }

    /// Return the total number of circuits we would currently like to launch.
    pub(super) fn n_to_launch(&self) -> usize {
        self.stub_target + self.ext_stub_target
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            circuits: Vec::new(),
            target: DEFAULT_TARGET,
            have_been_exhausted: false,
            have_been_under_highwater: false,
            last_changed_target: None,
            mode: VanguardMode::default(),
        }
    }
}

impl Pool {
    /// Add `circ` to this pool
    pub(super) fn insert(&mut self, circ: HsCircStub) {
        self.circuits.push(circ);
    }

    /// Remove every circuit from this pool for which `f` returns false.
    pub(super) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&HsCircStub) -> bool,
    {
        self.circuits.retain(f);
    }

    /// Return true if we are very low on circuits and should build more immediately.
    pub(super) fn very_low(&self) -> bool {
        self.circuits.len() <= self.target / 3
    }

    /// Return a [`CircsToLaunch`] describing the circuits we would currently like to launch.
    pub(super) fn circs_to_launch(&self) -> CircsToLaunch {
        CircsToLaunch {
            stub_target: self.stubs_to_launch(),
            ext_stub_target: self.ext_stubs_to_launch(),
        }
    }

    /// Return the number of STUB circuits we would currently like to launch.
    fn stubs_to_launch(&self) -> usize {
        let target = ((self.target as f32) * STUB_CIRC_RATIO) as usize;
        let circ_count = self
            .circuits
            .iter()
            .filter(|c| c.kind == HsCircStubKind::Stub)
            .count();

        target.saturating_sub(circ_count)
    }

    /// Return the number of STUB+ circuits we would currently like to launch.
    fn ext_stubs_to_launch(&self) -> usize {
        let target = self.target - self.stubs_to_launch();
        let circ_count = self
            .circuits
            .iter()
            .filter(|c| c.kind == HsCircStubKind::Extended)
            .count();

        // TODO: if the number of STUB circuits >= self.target,
        // we don't launch any STUB+ circuits
        target.saturating_sub(circ_count)
    }

    /// If there is any circuit in this pool for which `f`  returns true, return one such circuit at random, and remove it from the pool.
    pub(super) fn take_one_where<R, F>(&mut self, rng: &mut R, f: F) -> Option<HsCircStub>
    where
        R: Rng,
        F: Fn(&HsCircStub) -> bool,
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

    /// Returns `true` if vanguards are enabled.
    pub(super) fn vanguards_enabled(&self) -> bool {
        self.mode != VanguardMode::Disabled
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
    #![allow(clippy::mixed_attributes_style)]
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
