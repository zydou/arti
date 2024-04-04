//! Vanguard sets

use std::cmp::Ordering;
use std::sync::Weak;
use std::time::SystemTime;

use rand::{seq::SliceRandom as _, RngCore};
use serde::{Deserialize, Serialize};

use tor_linkspec::{HasRelayIds as _, RelayIdSet, RelayIds};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{LowLevelRelayPredicate as _, RelayExclusion};

/// A vanguard relay.
//
// TODO HS-VANGUARDS: this is currently just a Relay newtype (if it doesn't grow any additional
// fields, we might want to consider removing it and using Relay instead).
#[derive(Clone, amplify::Getters)]
pub struct Vanguard<'a> {
    /// The relay.
    relay: Relay<'a>,
}

/// An identifier for a time-bound vanguard.
///
/// Each vanguard [`Layer`](crate::vanguards::Layer) consists of a [`VanguardSet`],
/// which contains multiple `TimeBoundVanguard`s.
///
/// A [`VanguardSet`]'s `TimeBoundVanguard`s are rotated
/// by [`VanguardMgr`](crate::vanguards::VanguardMgr) as soon as they expire.
/// If [Full](crate::vanguards::VanguardMode) vanguards are in use,
/// the `TimeBoundVanguard`s from all layers are persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)] //
pub(crate) struct TimeBoundVanguard {
    /// The ID of this relay.
    pub(super) id: RelayIds,
    /// When to stop using this relay as a vanguard.
    pub(super) when: SystemTime,
}

// TODO(#1342): derive all of these?
impl Ord for TimeBoundVanguard {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed, because we want the earlier
        // `TimeBoundVanguard` to be "greater".
        self.when.cmp(&other.when).reverse()
    }
}

impl PartialOrd for TimeBoundVanguard {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TimeBoundVanguard {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when
    }
}

impl Eq for TimeBoundVanguard {}

/// A set of vanguards, for use in a particular [`Layer`](crate::vanguards::Layer).
///
/// This structure is just a view over the vanguards owned by VanguardMgr.
/// It does **not** own the vanguards.
#[derive(Debug, Clone)] //
#[allow(unused)] // TODO HS-VANGUARDS
pub(super) struct VanguardSet {
    /// The time-bound vanguards of a given [`Layer`](crate::vanguards::Layer).
    vanguards: Vec<Weak<TimeBoundVanguard>>,
    /// The number of vanguards we would like to have in this set.
    target: usize,
}

impl VanguardSet {
    /// Create a new vanguard set with the specified target size.
    pub(super) fn new(target: usize) -> Self {
        Self {
            vanguards: Default::default(),
            target,
        }
    }

    /// Pick a relay from this set.
    ///
    /// See [`VanguardMgr::select_vanguard`](crate::vanguards::VanguardMgr::select_vanguard)
    /// for more information.
    pub(super) fn pick_relay<'a, R: RngCore>(
        &mut self,
        rng: &mut R,
        netdir: &'a NetDir,
        neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Option<Vanguard<'a>> {
        self.discard_expired();

        let good_relays = self
            .vanguards
            .iter()
            .filter_map(|vanguard| {
                // Skip over the vanguards that have been dropped
                // (there shouldn't be any, because we called discard_expired earlier).
                let vanguard = vanguard.upgrade()?;
                // Skip over any unusable relays
                let relay = netdir.by_ids(&vanguard.id)?;
                neighbor_exclusion
                    .low_level_predicate_permits_relay(&relay)
                    .then_some(relay)
            })
            .collect::<Vec<_>>();

        good_relays.choose(rng).map(|relay| Vanguard {
            relay: relay.clone(),
        })
    }

    /// The number of vanguards we're missing.
    pub(super) fn deficit(&self) -> usize {
        let good_vanguards = self
            .vanguards
            .iter()
            .filter(|v| v.upgrade().is_some())
            .count();
        self.target.saturating_sub(good_vanguards)
    }

    /// Add a vanguard to this set.
    pub(super) fn add_vanguard(&mut self, weak: Weak<TimeBoundVanguard>) {
        self.vanguards.push(weak);
    }

    /// Update the target size of this set, discarding or requesting additional vanguards if needed.
    pub(super) fn update_target(&mut self, target: usize) {
        self.discard_expired();
        self.target = target;
    }

    /// Discard any expired vanguards.
    fn discard_expired(&mut self) {
        self.vanguards.retain(|v| v.upgrade().is_some());
    }
}

impl From<&VanguardSet> for RelayIdSet {
    fn from(vanguard_set: &VanguardSet) -> Self {
        vanguard_set
            .vanguards
            .iter()
            .filter_map(|vanguard| {
                // Skip over any dangling references
                Some(vanguard.upgrade()?.id.clone())
            })
            .flat_map(|relay: RelayIds| {
                relay
                    .identities()
                    .map(|id| id.to_owned())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

// Amplify can't generate pub(super) getters, so we need to write them by hand.
#[cfg(test)]
impl VanguardSet {
    /// Return the target size of this set.
    #[cfg(test)]
    pub(super) fn target(&self) -> usize {
        self.target
    }

    /// Return the vanguards in this set
    #[cfg(test)]
    pub(super) fn vanguards(&self) -> &Vec<Weak<TimeBoundVanguard>> {
        &self.vanguards
    }
}
