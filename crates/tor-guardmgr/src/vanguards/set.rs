//! Vanguard sets

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

/// A set of vanguards, for use in a particular [`Layer`](crate::vanguards::Layer).
///
/// `VanguardSet`s start out with a target size of `0`.
///
/// Upon obtaining a `NetDir`, users of this type should update the target
/// based on the the current [`NetParameters`](tor_netdir::params::NetParameters).
#[derive(Default, Debug, Clone)] //
#[derive(Serialize, Deserialize)] //
#[serde(transparent)]
#[allow(unused)] // TODO HS-VANGUARDS
pub(super) struct VanguardSet {
    /// The time-bound vanguards of a given [`Layer`](crate::vanguards::Layer).
    vanguards: Vec<TimeBoundVanguard>,
    /// The number of vanguards we would like to have in this set.
    ///
    /// We do not serialize this value, as it should be derived from, and kept up to date with,
    /// the current [`NetParameters`](tor_netdir::params::NetParameters).
    #[serde(skip)]
    target: usize,
}

/// The L2 and L3 vanguard sets,
/// stored in the same struct to simplify serialization.
#[derive(Default, Debug, Clone)] //
#[derive(Serialize, Deserialize)] //
pub(super) struct VanguardSets {
    /// The L2 vanguard sets.
    pub(super) l2_vanguards: VanguardSet,
    /// The L3 vanguard sets.
    ///
    /// Only used if full vanguards are enabled.
    pub(super) l3_vanguards: VanguardSet,
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
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Option<Vanguard<'a>> {
        let good_relays = self
            .vanguards
            .iter()
            .filter_map(|vanguard| {
                // Skip over any unusable relays
                let relay = netdir.by_ids(&vanguard.id)?;
                neighbor_exclusion
                    .low_level_predicate_permits_relay(&relay)
                    .then_some(relay)
            })
            .collect::<Vec<_>>();

        // Note: We make a uniform choice instead of a weighted one,
        // because we already made a bandwidth-weighted choice when we added
        // the vanguards to this set in the first place.
        good_relays.choose(rng).map(|relay| Vanguard {
            relay: relay.clone(),
        })
    }

    /// The number of vanguards we're missing.
    pub(super) fn deficit(&self) -> usize {
        self.target.saturating_sub(self.vanguards.len())
    }

    /// Add a vanguard to this set.
    pub(super) fn add_vanguard(&mut self, v: TimeBoundVanguard) {
        self.vanguards.push(v);
    }

    /// Remove the vanguards that are no longer listed in `netdir`
    pub(super) fn remove_unlisted(&mut self, netdir: &NetDir) {
        self.vanguards
            .retain(|v| netdir.ids_listed(&v.id) != Some(false));
    }

    /// Remove the vanguards that are expired at the specified timestamp.
    pub(super) fn remove_expired(&mut self, now: SystemTime) {
        self.vanguards.retain(|v| v.when > now);
    }

    /// Find the timestamp of the vanguard that is due to expire next.
    pub(super) fn next_expiry(&self) -> Option<SystemTime> {
        self.vanguards.iter().map(|v| v.when).min()
    }

    /// Update the target size of this set, discarding or requesting additional vanguards if needed.
    pub(super) fn update_target(&mut self, target: usize) {
        self.target = target;
    }
}

impl From<&VanguardSet> for RelayIdSet {
    fn from(vanguard_set: &VanguardSet) -> Self {
        vanguard_set
            .vanguards
            .iter()
            .flat_map(|vanguard| {
                vanguard
                    .id
                    .clone()
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
    pub(super) fn vanguards(&self) -> &Vec<TimeBoundVanguard> {
        &self.vanguards
    }
}
