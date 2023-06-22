//! Tracking for the path of a client circuit.

use tor_linkspec::OwnedChanTarget;

use crate::crypto::cell::HopNum;

/// A descriptor of a single hop in a circuit path.
///
/// This enum is not public; we want the freedom to change it as we see fit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) enum HopDetail {
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

/// A description of a single hop in a [`Path`].
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// The actual information about this hop.  We use an inner structure here
    /// to keep the information private.
    inner: HopDetail,
}

/// A circuit's path through the network.
///
/// Every path is composed of some number of hops; each hop is typically a
/// bridge or relay on the Tor network.
#[derive(Debug, Default, Clone)]
pub struct Path {
    /// Information about the relays on this circuit.
    ///
    /// We only store ChanTarget information here, because it doesn't matter
    /// which ntor key we actually used with each hop.
    hops: Vec<PathEntry>,
}

impl Path {
    /// Return the number of hops in this path
    pub fn n_hops(&self) -> usize {
        self.hops.len()
    }

    /// Add a hop to this path.
    pub(super) fn push_hop(&mut self, target: HopDetail) {
        self.hops.push(PathEntry { inner: target });
    }

    /// Return an OwnedChanTarget representing the first hop of this path.
    pub(super) fn first_hop(&self) -> Option<HopDetail> {
        self.hops.get(0).map(|ent| ent.inner.clone())
    }

    /// Return a copy of all the hops in this path.
    pub(super) fn all_hops(&self) -> Vec<HopDetail> {
        self.hops.iter().map(|ent| ent.inner.clone()).collect()
    }

    /// Return the index of the last hop on this path, or `None` if the path is
    /// empty (or impossibly long).
    pub(super) fn last_hop_num(&self) -> Option<HopNum> {
        let n = self.n_hops();
        let idx: u8 = n.checked_sub(1)?.try_into().ok()?;
        Some(idx.into())
    }
}
