//! Tracking for the path of a client circuit.

use std::sync::Mutex;
use tor_linkspec::OwnedChanTarget;

use crate::crypto::cell::HopNum;

/// A descriptor of a single hop in a circuit path.
//
// TODO HS: I think this will want to be a public type once we change the
// return type of Circuit::path().
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) enum PathEntry {
    /// A hop built through a known relay or a set of externally provided
    /// linkspecs.
    ///
    /// TODO hs: distinguish the two cases here?
    Relay(OwnedChanTarget),
    /// A hop built using
    /// [`extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
    ///
    /// TODO hs: remember anything about what the virtual hop represents?
    #[cfg(feature = "hs-common")]
    Virtual,
}

/// Helper struct that shares information
#[derive(Debug, Default)]
pub(super) struct Path {
    /// Information about the relays on this circuit.
    ///
    /// We only store ChanTarget information here, because it doesn't matter
    /// which ntor key we actually used with each hop.
    hops: Mutex<Vec<PathEntry>>,
}

impl Path {
    /// Return the number of hops in this path
    pub(super) fn n_hops(&self) -> usize {
        self.hops.lock().expect("poisoned lock").len()
    }

    /// Add a hop to this  this path.
    pub(super) fn push_hop(&self, target: PathEntry) {
        self.hops.lock().expect("poisoned lock").push(target);
    }

    /// Return an OwnedChanTarget representing the first hop of this path.
    pub(super) fn first_hop(&self) -> Option<PathEntry> {
        self.hops
            .lock()
            .expect("poisoned lock")
            .get(0)
            .map(Clone::clone)
    }

    /// Return a copy of all the hops in this path.
    pub(super) fn all_hops(&self) -> Vec<PathEntry> {
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
