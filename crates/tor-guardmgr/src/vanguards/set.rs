//! Vanguard sets

use std::cmp;
use std::time::{Duration, SystemTime};

use derive_deftly::{derive_deftly_adhoc, Deftly};
use rand::{seq::IndexedRandom as _, RngCore};
use serde::{Deserialize, Serialize};

use tor_basic_utils::RngExt as _;
use tor_error::internal;
use tor_linkspec::{HasRelayIds as _, RelayIdSet, RelayIds};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{LowLevelRelayPredicate as _, RelayExclusion, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;
use tracing::{debug, trace};

use crate::{VanguardMgrError, VanguardMode};

use super::VanguardParams;

/// A vanguard relay.
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] //
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
#[derive(Default, Debug, Clone, PartialEq)] //
#[derive(Serialize, Deserialize)] //
#[serde(transparent)]
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
#[derive(Default, Debug, Clone, PartialEq)] //
#[derive(Deftly, Serialize, Deserialize)] //
#[derive_deftly_adhoc]
pub(super) struct VanguardSets {
    /// The L2 vanguard sets.
    l2_vanguards: VanguardSet,
    /// The L3 vanguard sets.
    ///
    /// Only used if full vanguards are enabled.
    l3_vanguards: VanguardSet,
}

impl VanguardSets {
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

    /// Return a reference to the L2 [`VanguardSet`].
    pub(super) fn l2(&self) -> &VanguardSet {
        &self.l2_vanguards
    }

    /// Return a reference to the L3 [`VanguardSet`].
    pub(super) fn l3(&self) -> &VanguardSet {
        &self.l3_vanguards
    }

    /// Remove the vanguards that are expired at the specified timestamp.
    ///
    /// Returns the number of vanguards that were removed.
    pub(super) fn remove_expired(&mut self, now: SystemTime) -> usize {
        let l2_expired = self.l2_vanguards.remove_expired(now);
        let l3_expired = self.l3_vanguards.remove_expired(now);

        l2_expired + l3_expired
    }

    /// Remove the vanguards that are no longer listed in `netdir`.
    ///
    /// Returns whether either of the two sets have changed.
    pub(super) fn remove_unlisted(&mut self, netdir: &NetDir) {
        self.l2_vanguards.remove_unlisted(netdir);
        self.l3_vanguards.remove_unlisted(netdir);
    }

    /// Replenish the vanguard sets if necessary, using the directory information
    /// from the specified [`NetDir`].
    ///
    /// Note: the L3 set is only replenished if [`Full`](VanguardMode::Full) vanguards are enabled.
    pub(super) fn replenish_vanguards<R: Runtime>(
        &mut self,
        runtime: &R,
        netdir: &NetDir,
        params: &VanguardParams,
        mode: VanguardMode,
    ) -> Result<(), VanguardMgrError> {
        trace!("Replenishing vanguard sets");

        // Resize the vanguard sets if necessary.
        self.l2_vanguards.update_target(params.l2_pool_size());

        let mut rng = rand::rng();
        Self::replenish_set(
            runtime,
            &mut rng,
            netdir,
            &mut self.l2_vanguards,
            params.l2_lifetime_min(),
            params.l2_lifetime_max(),
        )?;

        if mode == VanguardMode::Full {
            self.l3_vanguards.update_target(params.l3_pool_size());
            Self::replenish_set(
                runtime,
                &mut rng,
                netdir,
                &mut self.l3_vanguards,
                params.l3_lifetime_min(),
                params.l3_lifetime_max(),
            )?;
        }

        Ok(())
    }

    /// Replenish a single `VanguardSet` with however many vanguards it is short of.
    fn replenish_set<R: Runtime, Rng: RngCore>(
        runtime: &R,
        rng: &mut Rng,
        netdir: &NetDir,
        vanguard_set: &mut VanguardSet,
        min_lifetime: Duration,
        max_lifetime: Duration,
    ) -> Result<bool, VanguardMgrError> {
        let mut set_changed = false;
        let deficit = vanguard_set.deficit();
        if deficit > 0 {
            // Exclude the relays that are already in this vanguard set.
            let exclude_ids = RelayIdSet::from(&*vanguard_set);
            let exclude = RelayExclusion::exclude_identities(exclude_ids);
            // Pick some vanguards to add to the vanguard_set.
            let new_vanguards = Self::add_n_vanguards(
                runtime,
                rng,
                netdir,
                deficit,
                exclude,
                min_lifetime,
                max_lifetime,
            )?;

            if !new_vanguards.is_empty() {
                set_changed = true;
            }

            for v in new_vanguards {
                vanguard_set.add_vanguard(v);
            }
        }

        Ok(set_changed)
    }

    /// Select `n` relays to use as vanguards.
    ///
    /// Each selected vanguard will have a random lifetime
    /// between `min_lifetime` and `max_lifetime`.
    fn add_n_vanguards<R: Runtime, Rng: RngCore>(
        runtime: &R,
        rng: &mut Rng,
        netdir: &NetDir,
        n: usize,
        exclude: RelayExclusion,
        min_lifetime: Duration,
        max_lifetime: Duration,
    ) -> Result<Vec<TimeBoundVanguard>, VanguardMgrError> {
        trace!(relay_count = n, "selecting relays to use as vanguards");

        let vanguard_sel = RelaySelector::new(RelayUsage::vanguard(), exclude);

        let (relays, _outcome) = vanguard_sel.select_n_relays(rng, n, netdir);

        relays
            .into_iter()
            .map(|relay| {
                // Pick an expiration for this vanguard.
                let duration = select_lifetime(rng, min_lifetime, max_lifetime)?;
                let when = runtime.wallclock() + duration;

                Ok(TimeBoundVanguard {
                    id: RelayIds::from_relay_ids(&relay),
                    when,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Randomly select the lifetime of a vanguard from the `max(X,X)` distribution,
/// where `X` is a uniform random value between `min_lifetime` and `max_lifetime`.
///
/// This ensures we are biased towards longer lifetimes.
///
/// See
/// <https://spec.torproject.org/vanguards-spec/vanguards-stats.html>
//
// Note: the lifetimes of the vanguards (both L2 and L3) are selected
// from the max(X,X) distribution.
fn select_lifetime<Rng: RngCore>(
    rng: &mut Rng,
    min_lifetime: Duration,
    max_lifetime: Duration,
) -> Result<Duration, VanguardMgrError> {
    let err = || internal!("invalid consensus: vanguard min_lifetime > max_lifetime");

    let l1 = rng
        .gen_range_checked(min_lifetime..=max_lifetime)
        .ok_or_else(err)?;

    let l2 = rng
        .gen_range_checked(min_lifetime..=max_lifetime)
        .ok_or_else(err)?;

    Ok(std::cmp::max(l1, l2))
}

impl VanguardSet {
    /// Pick a relay from this set.
    ///
    /// See [`VanguardMgr::select_vanguard`](crate::vanguards::VanguardMgr::select_vanguard)
    /// for more information.
    pub(super) fn pick_relay<'a, R: RngCore>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        relay_selector: &RelaySelector<'a>,
    ) -> Option<Vanguard<'a>> {
        let good_relays = self
            .vanguards
            .iter()
            .filter_map(|vanguard| {
                // Skip over any unusable relays
                let relay = netdir.by_ids(&vanguard.id)?;
                relay_selector
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

    /// Whether this vanguard set is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.vanguards.is_empty()
    }

    /// The number of vanguards we're missing.
    fn deficit(&self) -> usize {
        self.target.saturating_sub(self.vanguards.len())
    }

    /// Add a vanguard to this set.
    fn add_vanguard(&mut self, v: TimeBoundVanguard) {
        self.vanguards.push(v);
    }

    /// Remove the vanguards that are no longer listed in `netdir`
    ///
    /// Returns the number of vanguards that were unlisted.
    fn remove_unlisted(&mut self, netdir: &NetDir) -> usize {
        self.retain(|v| {
            let cond = netdir.ids_listed(&v.id) != Some(false);

            if !cond {
                debug!(id=?v.id, "Removing newly-unlisted vanguard");
            }

            cond
        })
    }

    /// Remove the vanguards that are expired at the specified timestamp.
    ///
    /// Returns the number of vanguards that expired.
    fn remove_expired(&mut self, now: SystemTime) -> usize {
        self.retain(|v| {
            let cond = v.when > now;

            if !cond {
                debug!(id=?v.id, "Removing expired vanguard");
            }

            cond
        })
    }

    /// A wrapper around [`Vec::retain`] that returns the number of discarded elements.
    fn retain<F>(&mut self, f: F) -> usize
    where
        F: FnMut(&TimeBoundVanguard) -> bool,
    {
        let old_len = self.vanguards.len();
        self.vanguards.retain(f);
        old_len - self.vanguards.len()
    }

    /// Find the timestamp of the vanguard that is due to expire next.
    fn next_expiry(&self) -> Option<SystemTime> {
        self.vanguards.iter().map(|v| v.when).min()
    }

    /// Update the target size of this set, discarding or requesting additional vanguards if needed.
    fn update_target(&mut self, target: usize) {
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

// Some accessors we need in the VanguardMgr tests.
#[cfg(test)]
derive_deftly_adhoc! {
    VanguardSets expect items:

    impl VanguardSets {
        $(
            #[doc = concat!("Return the ", stringify!($fname))]
            pub(super) fn $fname(&self) -> &Vec<TimeBoundVanguard> {
                &self.$fname.vanguards
            }

            #[doc = concat!("Return the target size of the ", stringify!($fname), " set")]
            pub(super) fn $<$fname _target>(&self) -> usize {
                self.$fname.target
            }

            #[doc = concat!("Return the deficit of the ", stringify!($fname), " set")]
            pub(super) fn $<$fname _deficit>(&self) -> usize {
                self.$fname.deficit()
            }

        )
    }
}
