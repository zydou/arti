//! Tracking for the path of a client circuit.

use std::sync::Mutex;
use tor_linkspec::OwnedChanTarget;

/// Helper struct that shares information
#[derive(Debug, Default)]
pub(super) struct Path {
    /// Information about the relays on this circuit.
    ///
    /// We only store ChanTarget information here, because it doesn't matter
    /// which ntor key we actually used with each hop.
    hops: Mutex<Vec<OwnedChanTarget>>,
}

impl Path {
    /// Return the number of hops in this path
    pub(super) fn n_hops(&self) -> usize {
        self.hops.lock().expect("poisoned lock").len()
    }

    /// Add a hop to this  this path.
    pub(super) fn push_hop(&self, target: OwnedChanTarget) {
        self.hops.lock().expect("poisoned lock").push(target);
    }
}
