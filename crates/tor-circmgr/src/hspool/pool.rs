//! An internal pool object that we use to implement HsCircPool.

use std::sync::Arc;

use rand::{seq::IteratorRandom, Rng};
use tor_proto::circuit::ClientCirc;

/// A collection of circuits used to fulfil onion-service-related requests.
#[derive(Default)]
pub(super) struct Pool {
    /// The collection of circuits themselves, in no particular order.
    circuits: Vec<Arc<ClientCirc>>,
}

impl Pool {
    /// Return the number of circuits in this pool.
    pub(super) fn len(&self) -> usize {
        self.circuits.len()
    }

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
        let (idx, _) = self
            .circuits
            .iter()
            .enumerate()
            .filter(|(_, c)| f(c))
            .choose(rng)?;
        Some(self.circuits.remove(idx))
    }
}
