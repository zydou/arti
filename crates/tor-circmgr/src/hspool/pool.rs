//! An internal pool object that we use to implement HsCircPool.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use rand::{seq::IteratorRandom, Rng};
use tor_proto::circuit::ClientCirc;

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

    /// Return true if we ar very low on circuits and should build more immediately.
    pub(super) fn very_low(&self) -> bool {
        self.circuits.len() <= self.target / 3
    }

    /// Return the number of sircuits we would currently like to launch.
    pub(super) fn n_to_launch(&self) -> usize {
        self.target.saturating_sub(self.circuits.len())
    }

    /// If there is any circuit in this pool for which `f`  returns true, return one such circuit at random, and remove it from the pool.
    pub(super) fn take_one_where<R, F>(&mut self, rng: &mut R, f: F) -> Option<Arc<ClientCirc>>
    where
        R: Rng,
        F: Fn(&Arc<ClientCirc>) -> bool,
    {
        // TODO HS: This ensures that we take a circuit at random, but at the
        // expense of searching every circuit.  That could certainly be costly
        // if `circuits` is large!  Perhaps we should instead stop at the first
        // matching circuit we find.
        let rv = match self
            .circuits
            .iter()
            .enumerate()
            .filter(|(_, c)| f(c))
            .choose(rng)
        {
            Some((idx, _)) => Some(self.circuits.remove(idx)),
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
}
