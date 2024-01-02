//! Tracking for the path of a client circuit.

use std::fmt::{self, Display};

use safelog::Redactable;
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
    /// TODO: Someday we might ant to distinguish the two cases (known relay,
    /// externally provided linkspecs).  We might want to also record more
    /// information about the hop... but we can do all of  this in a
    /// backward-compatible way, so it doesn't need to happen right now.
    Relay(OwnedChanTarget),
    /// A hop built using
    /// [`extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
    ///
    /// TODO: Perhaps we'd like to remember something about what the virtual hop
    /// represents?
    #[cfg(feature = "hs-common")]
    Virtual,
}

/// A description of a single hop in a [`Path`].
///
/// Each hop can be to a relay or bridge on the Tor network, or a "virtual" hop
/// representing the cryptographic connection between a client and an onion
/// service.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// The actual information about this hop.  We use an inner structure here
    /// to keep the information private.
    inner: HopDetail,
}

impl Display for PathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            HopDetail::Relay(ct) => write!(f, "{}", ct),
            #[cfg(feature = "hs-common")]
            HopDetail::Virtual => write!(f, "<virtual hop>"),
        }
    }
}

impl Redactable for PathEntry {
    fn display_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            HopDetail::Relay(ct) => Redactable::display_redacted(ct, f),
            #[cfg(feature = "hs-common")]
            HopDetail::Virtual => write!(f, "<virtual hop>"),
        }
    }
}

impl PathEntry {
    /// If this hop was built to a known Tor relay or bridge instance, return
    /// a reference to a ChanTarget representing that instance.
    ///
    /// Otherwise, return None.
    pub fn as_chan_target(&self) -> Option<&impl tor_linkspec::ChanTarget> {
        match &self.inner {
            HopDetail::Relay(chan_target) => Some(chan_target),
            #[cfg(feature = "hs-common")]
            HopDetail::Virtual => None,
        }
    }
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

    /// Return a list of all the hops in this path.
    pub fn hops(&self) -> &[PathEntry] {
        &self.hops[..]
    }

    /// Return an iterator over all the hops in this path.
    pub fn iter(&self) -> impl Iterator<Item = &PathEntry> + '_ {
        self.hops.iter()
    }

    /// Add a hop to this path.
    pub(super) fn push_hop(&mut self, target: HopDetail) {
        self.hops.push(PathEntry { inner: target });
    }

    /// Return an OwnedChanTarget representing the first hop of this path.
    pub(super) fn first_hop(&self) -> Option<HopDetail> {
        self.hops.first().map(|ent| ent.inner.clone())
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
