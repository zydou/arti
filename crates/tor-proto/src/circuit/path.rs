//! Tracking for the path of a client circuit.

use std::sync::Mutex;
use tor_linkspec::OwnedChanTarget;

use crate::crypto::cell::HopNum;

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

    /// Return an OwnedChanTarget representing the first hop of this path.
    pub(super) fn first_hop(&self) -> Option<OwnedChanTarget> {
        self.hops
            .lock()
            .expect("poisoned lock")
            .get(0)
            .map(Clone::clone)
    }

    /// Return a copy of all the hops in this path.
    pub(super) fn all_hops(&self) -> Vec<OwnedChanTarget> {
        self.hops.lock().expect("poisoned lock").clone()
    }

    /// Return the index of the last hop on this path, or `None` if the path is
    /// empty (or impossibly long).
    pub(super) fn last_hop_num(&self) -> Option<HopNum> {
        let n = self.n_hops();
        let idx: u8 = n.checked_sub(1)?.try_into().ok()?;
        Some(idx.into())
    }
}
