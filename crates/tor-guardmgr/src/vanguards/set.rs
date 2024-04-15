//! Vanguard sets

use std::cmp;
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

impl VanguardSets {
    /// Return a [`VanguardSetsTrackedMut`] for mutating the vanguard sets.
    pub(super) fn as_mut(&mut self) -> VanguardSetsTrackedMut {
        VanguardSetsTrackedMut {
            inner: self,
            changed: false,
        }
    }

    /// Find the timestamp of the vanguard that is due to expire next.
    pub(super) fn next_expiry(&self) -> Option<SystemTime> {
        let l2_expiry = self.l2_vanguards.next_expiry();
        let l3_expiry = self.l3_vanguards.next_expiry();
        match (l2_expiry, l3_expiry) {
            (Some(e), None) | (None, Some(e)) => Some(e),
            (Some(e1), Some(e2)) => Some(cmp::min(e1, e2)),
            (None, None) => {
                // Both vanguard sets are empty
                None
            }
        }
    }

    /// Pick a relay from the L2 set.
    ///
    /// See [`VanguardSet::pick_relay`].
    pub(super) fn pick_l2_relay<'a, R: RngCore>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Option<Vanguard<'a>> {
        self.l2_vanguards
            .pick_relay(rng, netdir, neighbor_exclusion)
    }

    /// Pick a relay from the L3 set.
    ///
    /// See [`VanguardSet::pick_relay`].
    pub(super) fn pick_l3_relay<'a, R: RngCore>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Option<Vanguard<'a>> {
        self.l3_vanguards
            .pick_relay(rng, netdir, neighbor_exclusion)
    }
}

/// A handle that can be used to mutate a [`VanguardSets`] instance.
///
/// It keeps track of whether the `VanguardSets` was modified or not.
///
/// When running in full vanguards mode, [`VanguardMgr`](super::VanguardMgr)
/// uses this to decide whether the vanguard sets are "dirty"
/// and need to be flushed to disk.
pub(super) struct VanguardSetsTrackedMut<'a> {
    /// The underlying `VanguardSets`.
    inner: &'a mut VanguardSets,
    /// Whether the [`VanguardSets`] was mutated.
    changed: bool,
}

impl<'a> VanguardSetsTrackedMut<'a> {
    /// Whether the underlying [`VanguardSets`] has changed.
    pub(super) fn has_changes(&self) -> bool {
        self.changed
    }

    /// Remove the vanguards that are expired at the specified timestamp.
    pub(super) fn remove_expired(&mut self, now: SystemTime) {
        let l2_changed = self.inner.l2_vanguards.remove_expired(now);
        let l3_changed = self.inner.l3_vanguards.remove_expired(now);

        self.update_changed(l2_changed || l3_changed);
    }

    /// Remove the vanguards that are no longer listed in `netdir`.
    ///
    /// Returns whether either of the two sets have changed.
    pub(super) fn remove_unlisted(&mut self, netdir: &NetDir) {
        let l2_changed = self.inner.l2_vanguards.remove_unlisted(netdir);
        let l3_changed = self.inner.l3_vanguards.remove_unlisted(netdir);

        self.update_changed(l2_changed || l3_changed);
    }

    /// Set the `changed` flag if `new_changed` is `true`.
    ///
    /// If `changed` is already `true`, it won't be set back to `false`.
    fn update_changed(&mut self, new_changed: bool) {
        self.changed = self.changed || new_changed;
    }
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
    pub(super) fn remove_unlisted(&mut self, netdir: &NetDir) -> bool {
        self.retain(|v| netdir.ids_listed(&v.id) != Some(false))
    }

    /// Remove the vanguards that are expired at the specified timestamp.
    pub(super) fn remove_expired(&mut self, now: SystemTime) -> bool {
        self.retain(|v| v.when > now)
    }

    /// Find the timestamp of the vanguard that is due to expire next.
    pub(super) fn next_expiry(&self) -> Option<SystemTime> {
        self.vanguards.iter().map(|v| v.when).min()
    }

    /// Update the target size of this set, discarding or requesting additional vanguards if needed.
    pub(super) fn update_target(&mut self, target: usize) {
        self.target = target;
    }

    /// A wrapper around [`Vec::retain`] that returns whether any values were discarded.
    fn retain<F>(&mut self, f: F) -> bool
    where
        F: FnMut(&TimeBoundVanguard) -> bool,
    {
        let old_len = self.vanguards.len();
        self.vanguards.retain(f);
        self.vanguards.len() < old_len
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
