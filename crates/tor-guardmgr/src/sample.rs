//! Logic for manipulating a sampled set of guards, along with various
//! orderings on that sample.

mod candidate;

use crate::filter::GuardFilter;
use crate::guard::{Guard, NewlyConfirmed, Reachable};
use crate::skew::SkewObservation;
use crate::{
    ids::GuardId, ExternalActivity, GuardParams, GuardUsage, GuardUsageKind, PickGuardError,
};
use crate::{FirstHop, GuardSetSelector};
use tor_basic_utils::iter::{FilterCount, IteratorExt as _};
use tor_linkspec::{ByRelayIds, HasRelayIds};

use itertools::Itertools;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime};
use tracing::{debug, info};

#[allow(unused_imports)]
pub(crate) use candidate::{Candidate, CandidateStatus, Universe, UniverseRef, WeightThreshold};

/// A set of sampled guards, along with various orderings on subsets
/// of the sample.
///
/// Every guard in a `GuardSet` is considered to be "sampled": that
/// is, selected from a network directory at some point in the past.
/// The guards in the sample are ordered (roughly) by the time at
/// which they were added.  This list is persistent.
///
/// Any guard which we've successfully used at least once is
/// considered "confirmed".  Confirmed guards are ordered (roughly) by
/// the time at which we first used them.  This list is persistent.
///
/// The guards which we would prefer to use are called "primary".
/// Primary guards are ordered from most- to least-preferred.
/// This list is not persistent, and is re-derived as needed.
///
/// These lists together define a "preference order".  All primary
/// guards come first in preference order.  Then come the non-primary
/// confirmed guards, in their confirmed order.  Finally come the
/// non-primary, non-confirmed guards, in their sampled order.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(from = "GuardSample")]
pub(crate) struct GuardSet {
    /// Map from identities to guards, for every guard in this sample.
    ///
    /// The key for each entry is a set of identities which we have
    /// good (trustworthy-enough) reason to link together.
    ///
    /// When we connect to a guard we require it to demonstrate
    /// that it has *all* of these identities;
    /// and we do pinning, so that we note down the other identities we discover it has,
    /// with the intent that we will require them in future.
    ///
    /// ### Sources of linkage:
    ///
    ///  * If we connect to a relay and it proves a set of identities,
    ///    that necessarily will include at least the ones we have already.
    ///    We can add any other identities we have discovered.
    ///    Justification: the owners of the old ids have made a statement
    ///    (via the connection protocols) that these other ids are also theirs,
    ///    and should be required in future.
    ///
    ///  * If we obtain a (full) descriptor for a relay, and check the
    ///    self-signatures by all the identities we have already,
    ///    we can add any other identities listed in the descriptor.
    ///    Justification: the owners of the old ids have made an explicit statement
    ///    that these other ids are also theirs,
    ///    and should be required in future.
    ///
    ///  * For a relay in the netdir, if the netdir links some ids together,
    ///    we can combine the entries.
    ///    Justification: the netdir is authoritative for netdir-based relays.
    ///
    ///  * For a configured bridge, if our configuration links some identities,
    ///    we must insist on all those identities.
    ///    So we combine them.
    ///
    /// ### Handling of conflicting entries:
    ///
    /// `ByRelayIds` will implicitly delete conflicting entries,
    /// simply forgetting about them.
    /// This is OK for netdir relays, since we do not expect this to occur in practice.
    ///
    /// For bridges, conflicts may in fact occur,
    /// since bridge lines are not issued by a single authority,
    /// and should be afforded limited trust.
    ///
    ///  * If the configuration contains bridge lines that mutually conflict,
    ///    affected bridge lines should be disregarded,
    ///    or the configuration rejected.
    ///
    ///  * If the configuration contains information which is inconsistent with
    ///    our past experience, we should discard the past experiences which
    ///    aren't reconcilable with the configuration.
    ///
    ///  * We may discover a linkage which demonstrates that the configuration
    ///    is wrong: for example, two bridge lines for identities X and Y,
    ///    but in fact there is only one bridge with both identities.
    ///    In this situation it is OK to effectively disregard some the configuration
    ///    entries which are at variance with reality, maybe with a warning,
    ///    but keeping at least one of every usable id set (actually existing bridge)
    ///    would be good.
    guards: ByRelayIds<Guard>,
    /// Identities of all the guards in the sample, in sample order.
    ///
    /// This contains the same elements as the keys of `guards`
    sample: Vec<GuardId>,
    /// Identities of all the confirmed guards in the sample, in
    /// confirmed order.
    ///
    /// This contains a subset of the values in `sample`.
    confirmed: Vec<GuardId>,
    /// Identities of all the primary guards, in preference order
    /// (from best to worst).
    ///
    /// This contains a subset of the values in `sample`.
    primary: Vec<GuardId>,
    /// Currently active filter that restricts which guards we can use.
    ///
    /// Note that all of the lists above (with the exception of `primary`)
    /// can hold guards that the filter doesn't permit.  This behavior
    /// is meant to give good security behavior in the presence of filters
    /// that change over time.
    active_filter: GuardFilter,

    /// If true, the active filter is "very restrictive".
    filter_is_restrictive: bool,

    /// Set to 'true' whenever something changes that would force us
    /// to call 'select_primary_guards()', and cleared whenever we call it.
    primary_guards_invalidated: bool,

    /// Fields from the state file that was used to make this `GuardSet` that
    /// this version of Arti doesn't understand.
    unknown_fields: HashMap<String, JsonValue>,
}

/// Which of our lists did a given guard come from?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ListKind {
    /// A guard that came from the primary guard list.
    Primary,
    /// A non-primary guard that came from the confirmed guard list.
    Confirmed,
    /// A non-primary, non-confirmed guard.
    Sample,
    /// Not a guard at all, but a fallback directory.
    Fallback,
}

impl ListKind {
    /// Return true if this is a primary guard.
    pub(crate) fn is_primary(&self) -> bool {
        self == &ListKind::Primary
    }

    /// Return true if this guard's origin indicates that you can use successful
    /// circuits built through it immediately without waiting for any other
    /// circuits to succeed or fail.
    pub(crate) fn usable_immediately(&self) -> bool {
        match self {
            ListKind::Primary | ListKind::Fallback => true,
            ListKind::Confirmed | ListKind::Sample => false,
        }
    }
}

impl GuardSet {
    /// Return the lengths of the different elements of the guard set.
    ///
    /// Used to report bugs or corruption in consistency.
    fn inner_lengths(&self) -> (usize, usize, usize, usize) {
        (
            self.guards.len(),
            self.sample.len(),
            self.confirmed.len(),
            self.primary.len(),
        )
    }

    /// Remove all elements from this `GuardSet` that ought to be referenced by
    /// another element, but which are not.
    ///
    /// This method only removes corrupted elements and updates IDs in the ID
    /// list (possibly adding new IDs); it doesn't add guards or other data.
    /// It won't do anything if the `GuardSet` is well-formed.
    fn fix_consistency(&mut self) {
        /// Remove every element of `id_list` that does not belong to some guard
        /// in `guards`, and update the others to have any extra identities
        /// listed in `guards`.
        fn fix_id_list(guards: &ByRelayIds<Guard>, id_list: &mut Vec<GuardId>) {
            id_list.retain_mut(|id| match guards.by_all_ids(id) {
                Some(guard) => {
                    *id = guard.guard_id().clone();
                    true
                }
                None => false,
            });
        }

        let sample_set: HashSet<_> = self.sample.iter().collect();
        self.guards.retain(|g| sample_set.contains(g.guard_id()));
        fix_id_list(&self.guards, &mut self.sample);
        fix_id_list(&self.guards, &mut self.confirmed);
        fix_id_list(&self.guards, &mut self.primary);
    }

    /// Assert that this `GuardSet` is internally consistent.
    ///
    /// Incidentally fixes the consistency of this `GuardSet` if needed.
    fn assert_consistency(&mut self) {
        let len_pre = self.inner_lengths();
        self.fix_consistency();
        let len_post = self.inner_lengths();
        assert_eq!(len_pre, len_post);
    }

    /// Return the guard that has every identity in `id`, if any.
    pub(crate) fn get(&self, id: &GuardId) -> Option<&Guard> {
        self.guards.by_all_ids(id)
    }

    /// Replace the filter used by this `GuardSet` with `filter`.
    ///
    /// Removes all primary guards that the filter doesn't permit.
    ///
    /// If `restrictive` is true, this filter is treated as "extremely restrictive".
    pub(crate) fn set_filter(&mut self, filter: GuardFilter, restrictive: bool) {
        self.active_filter = filter;
        self.filter_is_restrictive = restrictive;

        self.assert_consistency();

        let guards = &self.guards; // avoid borrow issues
        let filt = &self.active_filter;
        self.primary.retain(|id| {
            guards
                .by_all_ids(id)
                .map(|g| g.usable() && filt.permits(g))
                .unwrap_or(false)
        });

        self.primary_guards_invalidated = true;
    }

    /// Return the current filter for this `GuardSet`.
    pub(crate) fn filter(&self) -> &GuardFilter {
        &self.active_filter
    }

    /// Copy non-persistent status from every guard shared with `other`.
    ///
    /// This is used as part of our reload process when we don't own our state
    /// files, and we're reloading in order to find out what the other Arti
    /// instance thinks the guards are. At that point, `self` is the set of
    /// guards that we just loaded from state, and `other` is our old guards,
    /// which we are using only for their status information.
    pub(crate) fn copy_ephemeral_status_into_newly_loaded_state(&mut self, mut other: GuardSet) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|guard| {
                let id = guard.guard_id();

                if let Some(other_guard) = other.guards.remove_exact(id) {
                    guard.copy_ephemeral_status_into_newly_loaded_state(other_guard)
                } else {
                    guard
                }
            })
            .collect();
    }

    /// Return a serializable state object that can be stored to disk
    /// to capture the current state of this GuardSet.
    fn get_state(&self) -> GuardSample<'_> {
        let guards = self
            .sample
            .iter()
            .map(|id| Cow::Borrowed(self.guards.by_all_ids(id).expect("Inconsistent state")))
            .collect();

        GuardSample {
            guards,
            confirmed: Cow::Borrowed(&self.confirmed),
            remaining: self.unknown_fields.clone(),
        }
    }

    /// Reconstruct a guard state from its serialized representation.
    fn from_state(state: GuardSample<'_>) -> Self {
        let mut guards = ByRelayIds::new();
        let mut sample = Vec::new();
        for guard in state.guards {
            sample.push(guard.guard_id().clone());
            guards.insert(guard.into_owned());
        }
        let confirmed = state.confirmed.into_owned();
        let primary = Vec::new();
        let mut guard_set = GuardSet {
            guards,
            sample,
            confirmed,
            primary,
            active_filter: GuardFilter::default(),
            filter_is_restrictive: false,
            primary_guards_invalidated: true,
            unknown_fields: state.remaining,
        };

        // Fix any inconsistencies in the stored representation.
        let len_pre = guard_set.inner_lengths();
        guard_set.fix_consistency();
        let len_post = guard_set.inner_lengths();
        if len_pre != len_post {
            info!(
                "Resolved a consistency issue in stored guard state. Diagnostic codes: {:?}, {:?}",
                len_pre, len_post
            );
        }
        debug!(
            n_guards = len_post.0,
            n_confirmed = len_post.2,
            "Guard set loaded."
        );

        guard_set
    }

    /// Return `Ok(true)` if `id` is definitely a member of this set, and
    /// `Ok(false)` if it is definitely not a member.  
    ///
    /// If we cannot tell, it's because there is a guard in this sample that has
    /// a _subset_ of the IDs in `id`. In that case, we return
    /// `Err(guard_ident)`, where `guard_ident`  is the identity of that guard.
    pub(crate) fn contains(&self, id: &GuardId) -> Result<bool, &GuardId> {
        let overlapping = self.guards.all_overlapping(id);
        match &overlapping[..] {
            [singleton] => {
                if singleton.has_all_relay_ids_from(id) {
                    Ok(true)
                } else {
                    Err(singleton.guard_id())
                }
            }
            _ => Ok(false),
        }
    }

    /// If there are not enough filter-permitted usable guards in this
    /// sample (according to the current active filter), then add
    /// more, up to the limits allowed by the parameters.
    ///
    /// This is the only function that adds new guards to the sample.
    ///
    /// Guards always start out un-confirmed.
    ///
    /// Return true if any guards were added.
    pub(crate) fn extend_sample_as_needed<U: Universe>(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
        dir: &U,
    ) -> crate::ExtendedStatus {
        let mut any_added = crate::ExtendedStatus::No;
        while self.extend_sample_inner(now, params, dir) {
            any_added = crate::ExtendedStatus::Yes;
        }
        any_added
    }

    /// Implementation helper for extend_sample_as_needed.
    ///
    /// # Complications
    ///
    /// For spec conformance, we only consider our filter when selecting new
    /// guards if the filter is "very restrictive". That makes it possible that
    /// this function will add fewer filter-permitted guards than we had wanted.
    /// Because of that, this is a separate function, and
    /// extend_sample_as_needed runs it in a loop until it returns false.
    fn extend_sample_inner<U: Universe>(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
        dir: &U,
    ) -> bool {
        self.assert_consistency();
        let n_filtered_usable = self
            .guards
            .values()
            .filter(|g| {
                g.usable()
                    && self.active_filter.permits(*g)
                    && g.reachable() != Reachable::Unreachable
            })
            .count();
        if n_filtered_usable >= params.min_filtered_sample_size {
            return false; // We have enough usage guards in our sample.
        }
        if self.guards.len() >= params.max_sample_size {
            return false; // We can't add any more guards to our sample.
        }

        // What are the most guards we're willing to have in the sample?
        let max_to_add = params.max_sample_size - self.sample.len();
        let want_to_add = params.min_filtered_sample_size - n_filtered_usable;
        let n_to_add = std::cmp::min(max_to_add, want_to_add);

        let WeightThreshold {
            mut current_weight,
            maximum_weight,
        } = dir.weight_threshold(&self.guards, params);

        // Ask the netdir for a set of guards we could use.
        let no_filter = GuardFilter::unfiltered();
        let (n_candidates, pre_filter) =
            if self.filter_is_restrictive || self.active_filter.is_unfiltered() {
                (n_to_add, &self.active_filter)
            } else {
                // The filter will probably reject a bunch of guards, but we sample
                // before filtering, so we make this larger on an ad-hoc basis.
                (n_to_add * 3, &no_filter)
            };

        let candidates = dir.sample(&self.guards, pre_filter, n_candidates);

        // Add those candidates to the sample.
        let mut any_added = false;
        let mut n_filtered_usable = n_filtered_usable;
        for (candidate, weight) in candidates {
            // Don't add any more if we have met the minimal sample size, and we
            // have added too much weight.
            if current_weight >= maximum_weight
                && self.guards.len() >= params.min_filtered_sample_size
            {
                break;
            }
            if self.guards.len() >= params.max_sample_size {
                // Can't add any more.
                break;
            }
            if n_filtered_usable >= params.min_filtered_sample_size {
                // We've reached our target; no need to add more.
                break;
            }
            if self.active_filter.permits(&candidate.owned_target) {
                n_filtered_usable += 1;
            }
            current_weight += weight;
            self.add_guard(candidate, now, params);
            any_added = true;
        }
        self.assert_consistency();
        any_added
    }

    /// Add `relay` as a new guard.
    ///
    /// Does nothing if it is already a guard.
    fn add_guard(&mut self, relay: Candidate, now: SystemTime, params: &GuardParams) {
        let id = GuardId::from_relay_ids(&relay.owned_target);
        if self.guards.by_all_ids(&id).is_some() {
            return;
        }
        debug!(guard_id=?id, "Adding guard to sample.");
        let guard = Guard::from_candidate(relay, now, params);
        self.guards.insert(guard);
        self.sample.push(id);
        self.primary_guards_invalidated = true;
    }

    /// Return the number of our primary guards that are missing directory
    /// information in `universe`.
    ///
    /// Note that "missing directory information" is not the same as "absent":
    /// in this case, we  are counting the primary guards where we cannot tell
    /// whether they appear in the universe or not because we have not yet
    /// downloaded their descriptors.
    pub(crate) fn n_primary_without_id_info_in<U: Universe>(&mut self, universe: &U) -> usize {
        self.primary
            .iter()
            .filter(|id| {
                let g = self
                    .guards
                    .by_all_ids(*id)
                    .expect("Inconsistent guard state");
                g.listed_in(universe).is_none()
            })
            .count()
    }

    /// Update the status of every guard  in this sample from a given source.
    pub(crate) fn update_status_from_dir<U: Universe>(&mut self, dir: &U) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.update_from_universe(dir);
                guard
            })
            .collect();
        // Call "fix consistency", in case any guards got a new ID.
        self.fix_consistency();
    }

    /// Re-build the list of primary guards.
    ///
    /// Primary guards are chosen according to preference order over all
    /// the guards in the set, restricted by the current filter.
    ///
    /// TODO: Enumerate all the times when this function needs to be called.
    ///
    /// TODO: Make sure this is called enough.
    pub(crate) fn select_primary_guards(&mut self, params: &GuardParams) {
        // TODO-SPEC: This is not 100% what the spec says, but it does match what
        // Tor does.  We pick first from the confirmed guards,
        // then from any previous primary guards, and then from maybe-reachable
        // guards in the sample.

        // Only for logging.
        let old_primary = self.primary.clone();

        self.primary = self
            // First, we look at the confirmed guards.
            .confirmed
            .iter()
            // Then we consider existing primary guards.
            .chain(self.primary.iter())
            // Finally, we look at the rest of the sample for guards not marked
            // as "unreachable".
            .chain(self.reachable_sample_ids())
            // We only consider each guard the first time it appears.
            .unique()
            // We only consider usable guards that the filter allows.
            .filter_map(|id| {
                let g = self
                    .guards
                    .by_all_ids(id)
                    .expect("Inconsistent guard state");
                if g.usable() && self.active_filter.permits(g) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            // The first n_primary guards on that list are primary!
            .take(params.n_primary)
            .collect();

        if self.primary != old_primary {
            debug!(old=?old_primary, new=?self.primary, "Updated primary guards.");
        }

        // Clear exploratory_circ_pending for all primary guards.
        for id in &self.primary {
            self.guards.modify_by_all_ids(id, |guard| {
                guard.note_exploratory_circ(false);
            });
        }

        // TODO: Recalculate retry times, perhaps, since we may have changed
        // the timeouts?

        self.assert_consistency();
        self.primary_guards_invalidated = false;
    }

    /// Remove all guards which should expire `now`, according to the settings
    /// in `params`.
    pub(crate) fn expire_old_guards(&mut self, params: &GuardParams, now: SystemTime) {
        self.assert_consistency();
        let n_pre = self.guards.len();
        self.guards.retain(|g| !g.is_expired(params, now));
        let guards = &self.guards;
        self.sample.retain(|id| guards.by_all_ids(id).is_some());
        self.confirmed.retain(|id| guards.by_all_ids(id).is_some());
        self.primary.retain(|id| guards.by_all_ids(id).is_some());
        self.assert_consistency();

        if self.guards.len() < n_pre {
            let n_expired = n_pre - self.guards.len();
            debug!(n_expired, "Expired guards as too old.");
            self.primary_guards_invalidated = true;
        }
    }

    /// Return an iterator over the Id for every Guard in the sample that
    /// is not known to be Unreachable.
    fn reachable_sample_ids(&self) -> impl Iterator<Item = &GuardId> {
        self.sample.iter().filter(move |id| {
            let g = self
                .guards
                .by_all_ids(*id)
                .expect("Inconsistent guard state");
            g.reachable() != Reachable::Unreachable
        })
    }

    /// Return an iterator that yields an element for every guard in
    /// this set, in preference order.
    ///
    /// Each element contains a `ListKind` that describes which list the
    /// guard was in, and a `&GuardId` that identifies the guard.
    ///
    /// Note that this function will return guards that are not
    /// accepted by the current active filter: the caller must apply
    /// that filter if appropriate.
    fn preference_order_ids(&self) -> impl Iterator<Item = (ListKind, &GuardId)> {
        self.primary
            .iter()
            .map(|id| (ListKind::Primary, id))
            .chain(self.confirmed.iter().map(|id| (ListKind::Confirmed, id)))
            .chain(self.sample.iter().map(|id| (ListKind::Sample, id)))
            .unique_by(|(_, id)| *id)
    }

    /// Like `preference_order_ids`, but yields `&Guard` instead of `&GuardId`.
    fn preference_order(&self) -> impl Iterator<Item = (ListKind, &Guard)> + '_ {
        self.preference_order_ids()
            .filter_map(move |(p, id)| self.guards.by_all_ids(id).map(|g| (p, g)))
    }

    /// Return true if `guard_id` is an identity subset for any primary guard in this set.
    fn guard_is_primary(&self, guard_id: &GuardId) -> bool {
        // (This could be yes/no/maybe.)

        // This is O(n), but the list is short.
        self.primary
            .iter()
            .any(|p| p.has_all_relay_ids_from(guard_id))
    }

    /// For every guard that has been marked as `Unreachable` for too long,
    /// mark it as `Unknown`.
    pub(crate) fn consider_all_retries(&mut self, now: Instant) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.consider_retry(now);
                guard
            })
            .collect();
    }

    /// Return the earliest time at which any guard will be retriable.
    pub(crate) fn next_retry(&self, usage: &GuardUsage) -> Option<Instant> {
        self.guards
            .values()
            .filter_map(|g| g.next_retry(usage))
            .min()
    }

    /// Mark every `Unreachable` primary guard as `Unknown`.
    pub(crate) fn mark_primary_guards_retriable(&mut self) {
        for id in &self.primary {
            self.guards
                .modify_by_all_ids(id, |guard| guard.mark_retriable());
        }
    }

    /// Return true if all of our primary guards are currently marked
    /// unreachable.
    pub(crate) fn all_primary_guards_are_unreachable(&mut self) -> bool {
        self.primary
            .iter()
            .flat_map(|id| self.guards.by_all_ids(id))
            .all(|g| g.reachable() == Reachable::Unreachable)
    }

    /// Mark every `Unreachable` guard as `Unknown`.
    pub(crate) fn mark_all_guards_retriable(&mut self) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.mark_retriable();
                guard
            })
            .collect();
    }

    /// Record that an attempt has begun to use the guard with
    /// `guard_id`.
    pub(crate) fn record_attempt(&mut self, guard_id: &GuardId, now: Instant) {
        let is_primary = self.guard_is_primary(guard_id);
        self.guards.modify_by_all_ids(guard_id, |guard| {
            guard.record_attempt(now);

            if !is_primary {
                guard.note_exploratory_circ(true);
            }
        });
    }

    /// Record that an attempt to use the guard with `guard_id` has just
    /// succeeded.
    ///
    /// If `how` is provided, it's an operation from outside the crate that the
    /// guard succeeded at doing.
    pub(crate) fn record_success(
        &mut self,
        guard_id: &GuardId,
        params: &GuardParams,
        how: Option<ExternalActivity>,
        now: SystemTime,
    ) {
        self.assert_consistency();
        self.guards.modify_by_all_ids(guard_id, |guard| match how {
            Some(external) => guard.record_external_success(external),
            None => {
                let newly_confirmed = guard.record_success(now, params);

                if newly_confirmed == NewlyConfirmed::Yes {
                    self.confirmed.push(guard_id.clone());
                    self.primary_guards_invalidated = true;
                }
            }
        });
        self.assert_consistency();
    }

    /// Record that an attempt to use the guard with `guard_id` has just failed.
    ///
    pub(crate) fn record_failure(
        &mut self,
        guard_id: &GuardId,
        how: Option<ExternalActivity>,
        now: Instant,
    ) {
        // TODO use instant uniformly for in-process, and systemtime for storage?
        let is_primary = self.guard_is_primary(guard_id);
        self.guards.modify_by_all_ids(guard_id, |guard| match how {
            Some(external) => guard.record_external_failure(external, now),
            None => guard.record_failure(now, is_primary),
        });
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just been abandoned, without learning whether it succeeded or failed.
    pub(crate) fn record_attempt_abandoned(&mut self, guard_id: &GuardId) {
        self.guards
            .modify_by_all_ids(guard_id, |guard| guard.note_exploratory_circ(false));
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just failed in a way that we could not definitively attribute to
    /// the guard.
    pub(crate) fn record_indeterminate_result(&mut self, guard_id: &GuardId) {
        self.guards.modify_by_all_ids(guard_id, |guard| {
            guard.note_exploratory_circ(false);
            guard.record_indeterminate_result();
        });
    }

    /// Record that a given guard has told us about clock skew.
    pub(crate) fn record_skew(&mut self, guard_id: &GuardId, observation: SkewObservation) {
        self.guards
            .modify_by_all_ids(guard_id, |guard| guard.note_skew(observation));
    }

    /// Return an iterator over all stored clock skew observations.
    pub(crate) fn skew_observations(&self) -> impl Iterator<Item = &SkewObservation> {
        self.guards.values().filter_map(|g| g.skew())
    }

    /// Return whether the circuit manager can be allowed to use a
    /// circuit with the `guard_id`.
    ///
    /// Return `Some(bool)` if the circuit is usable, and `None` if we
    /// cannot yet be sure.
    pub(crate) fn circ_usability_status(
        &self,
        guard_id: &GuardId,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Option<bool> {
        // TODO-SPEC: This isn't what the spec says.  The spec is phrased
        // in terms of circuits blocking circuits, whereas this algorithm is
        // about guards blocking guards.
        //
        // Also notably, the spec also says:
        //
        // * Among guards that do not appear in {CONFIRMED_GUARDS},
        // {is_pending}==true guards have higher priority.
        // * Among those, the guard with earlier {last_tried_connect} time
        // has higher priority.
        // * Finally, among guards that do not appear in
        // {CONFIRMED_GUARDS} with {is_pending==false}, all have equal
        // priority.
        //
        // I believe this approach is fine too, but we ought to document it.

        if self.guard_is_primary(guard_id) {
            // Circuits built to primary guards are always usable immediately.
            //
            // This has to be a special case, since earlier primary guards
            // don't block later ones.
            return Some(true);
        }

        // Assuming that the guard is _not_ primary, then the rule is
        // fairly simple: we can use the guard if all the guards we'd
        // _rather_ use are either down, or have had their circuit
        // attempts pending for too long.

        let cutoff = now
            .checked_sub(params.np_connect_timeout)
            .expect("Can't subtract connect timeout from now.");

        for (src, guard) in self.preference_order() {
            if guard.guard_id() == guard_id {
                return Some(true);
            }
            if guard.usable() && self.active_filter.permits(guard) && guard.conforms_to_usage(usage)
            {
                match (src, guard.reachable()) {
                    (_, Reachable::Reachable) => return Some(false),
                    (_, Reachable::Unreachable) => (),
                    (ListKind::Primary, Reachable::Untried | Reachable::Retriable) => {
                        return Some(false)
                    }
                    (_, Reachable::Untried | Reachable::Retriable) => {
                        if guard.exploratory_attempt_after(cutoff) {
                            return None;
                        }
                    }
                }
            }
        }

        // This guard is not even listed.
        Some(false)
    }

    /// Try to select a guard for a given `usage`.
    ///
    /// On success, returns the kind of guard that we got, and its filtered
    /// representation in a form suitable for use as a first hop.
    ///
    /// Label the returned guard as having come from `sample_id`.
    //
    // NOTE (nickm): I wish that we didn't have to take sample_id as an input,
    // but the alternative would be storing it as a member of `GuardSet`, which
    // makes things very complicated.
    pub(crate) fn pick_guard(
        &self,
        sample_id: &GuardSetSelector,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Result<(ListKind, FirstHop), PickGuardError> {
        let (list_kind, id) = self.pick_guard_id(usage, params, now)?;
        let first_hop = self
            .get(&id)
            .expect("Somehow selected a guard we don't know!")
            .get_external_rep(sample_id.clone());
        let first_hop = self.active_filter.modify_hop(first_hop)?;

        Ok((list_kind, first_hop))
    }

    /// Try to select a guard for a given `usage`.
    ///
    /// On success, returns the kind of guard that we got, and its identity.
    fn pick_guard_id(
        &self,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Result<(ListKind, GuardId), PickGuardError> {
        debug_assert!(!self.primary_guards_invalidated);
        let n_options = match usage.kind {
            GuardUsageKind::OneHopDirectory => params.dir_parallelism,
            GuardUsageKind::Data => params.data_parallelism,
        };

        // Counts of how many elements were rejected by which of the filters
        // below.
        //
        // Note that since we use `Iterator::take`, these counts won't cover the
        // whole guard sample on the successful case: only in the failing case,
        // when we fail to find any candidates.
        let mut running = FilterCount::default();
        let mut pending = FilterCount::default();
        let mut suitable = FilterCount::default();
        let mut filtered = FilterCount::default();

        let mut options: Vec<_> = self
            .preference_order()
            // Discard the guards that are down or unusable, and see if any
            // are left.
            .filter_cnt(&mut running, |(_, g)| {
                g.usable()
                    && g.reachable() != Reachable::Unreachable
                    && g.ready_for_usage(usage, now)
            })
            // Now remove those that are excluded because we're already trying
            // them on an exploratory basis.
            .filter_cnt(&mut pending, |(_, g)| !g.exploratory_circ_pending())
            // ...or because they don't support the operation we're
            // attempting...
            .filter_cnt(&mut suitable, |(_, g)| g.conforms_to_usage(usage))
            // ... or because we specifically filtered them out.
            .filter_cnt(&mut filtered, |(_, g)| self.active_filter.permits(*g))
            // We only consider the first n_options such guards.
            .take(n_options)
            .collect();

        if options.iter().any(|(src, _)| src.is_primary()) {
            // If there are any primary guards, we only consider those.
            options.retain(|(src, _)| src.is_primary());
        } else {
            // If there are no primary guards, parallelism doesn't apply.
            options.truncate(1);
        }

        match options.choose(&mut rand::thread_rng()) {
            Some((src, g)) => Ok((*src, g.guard_id().clone())),
            None => {
                let retry_at = if running.n_accepted == 0 {
                    self.next_retry(usage)
                } else {
                    None
                };
                Err(PickGuardError::AllGuardsDown {
                    retry_at,
                    running,
                    pending,
                    suitable,
                    filtered,
                })
            }
        }
    }

    /// Return the guards whose bridge descriptors we should request, given our
    /// current configuration and status.
    ///
    /// (The output of this function is not reasonable unless this is a Bridge
    /// sample.)
    #[cfg(feature = "bridge-client")]
    pub(crate) fn descriptors_to_request(&self, now: Instant, params: &GuardParams) -> Vec<&Guard> {
        /// This constant is here to improve our odds that we can get a working
        /// bridge if we have any per-circuit filters that would prevent us from
        /// using our preferred bridge.
        const MINIMUM: usize = 2;

        let maximum = std::cmp::max(params.data_parallelism, MINIMUM);
        let data_usage = GuardUsage::default();

        // Here we duplicate some but not all of the restrictions above in
        // pick_guard_id.  We skip those restrictions that are specific to only
        // certain kinds of circuits, and those that are temporary restrictions
        // encouraging us to try more guards.
        //
        // TODO: we may want to refactor this code and the code in pick_guard_id
        // above to share a single function.  Before we do that, however, I want
        // to experiment with this logic a bit to make sure that it works and
        // doesn't give us surprising results.
        self.preference_order()
            .filter(|(_, g)| {
                g.usable()
                    && g.reachable() != Reachable::Unreachable
                    && g.ready_for_usage(&data_usage, now)
                    && self.active_filter.permits(*g)
            })
            .take(maximum)
            .map(|(_, g)| g)
            .collect()
    }
}

use serde::Serializer;
use tor_persist::JsonValue;

/// State object used to serialize and deserialize a [`GuardSet`].
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GuardSample<'a> {
    /// Equivalent to `GuardSet.guards.values()`, except in sample order.
    guards: Vec<Cow<'a, Guard>>,
    /// The identities for the confirmed members of `guards`, in confirmed order.
    confirmed: Cow<'a, Vec<GuardId>>,
    /// Other data from the state file that this version of Arti doesn't recognize.
    #[serde(flatten)]
    remaining: HashMap<String, JsonValue>,
}

impl Serialize for GuardSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        GuardSample::from(self).serialize(serializer)
    }
}

impl<'a> From<&'a GuardSet> for GuardSample<'a> {
    fn from(guards: &'a GuardSet) -> Self {
        guards.get_state()
    }
}

impl<'a> From<GuardSample<'a>> for GuardSet {
    fn from(sample: GuardSample) -> Self {
        GuardSet::from_state(sample)
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use tor_linkspec::{HasRelayIds, RelayIdType};
    use tor_netdir::{NetDir, Relay};
    use tor_netdoc::doc::netstatus::{RelayFlags, RelayWeight};

    use super::*;
    use crate::FirstHopId;
    use std::time::Duration;

    fn netdir() -> NetDir {
        use tor_netdir::testnet;
        testnet::construct_netdir().unwrap_if_sufficient().unwrap()
    }

    #[test]
    fn sample_test() {
        // Make a test network that gives every relay equal weight, and which
        // has 20 viable (Guard + V2Dir + DirCache=2) candidates.  Otherwise the
        // calculation of collision probability at the end of this function is
        // too tricky.
        let netdir = tor_netdir::testnet::construct_custom_netdir(|idx, builder| {
            // Give every node equal bandwidth.
            builder.rs.weight(RelayWeight::Measured(1000));
            // The default network has 40 relays, and the first 10 are
            // not Guard by default.
            if idx >= 10 {
                builder.rs.add_flags(RelayFlags::GUARD);
                if idx >= 20 {
                    builder.rs.protos("DirCache=2".parse().unwrap());
                } else {
                    builder.rs.protos("".parse().unwrap());
                }
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        // Make sure that we got the numbers we expected.
        assert_eq!(40, netdir.relays().count());
        assert_eq!(30, netdir.relays().filter(Relay::is_flagged_guard).count());
        assert_eq!(
            20,
            netdir
                .relays()
                .filter(|r| r.is_flagged_guard() && r.is_dir_cache())
                .count()
        );

        let params = GuardParams {
            min_filtered_sample_size: 5,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };

        let mut samples: Vec<HashSet<GuardId>> = Vec::new();
        for _ in 0..3 {
            let mut guards = GuardSet::default();
            guards.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
            assert_eq!(guards.guards.len(), params.min_filtered_sample_size);
            assert_eq!(guards.confirmed.len(), 0);
            assert_eq!(guards.primary.len(), 0);
            guards.assert_consistency();

            // make sure all the guards are okay.
            for guard in guards.guards.values() {
                let id = FirstHopId::in_sample(GuardSetSelector::Default, guard.guard_id().clone());
                let relay = id.get_relay(&netdir).unwrap();
                assert!(relay.is_flagged_guard());
                assert!(relay.is_dir_cache());
                assert!(guards.guards.by_all_ids(&relay).is_some());
                {
                    assert!(!guard.is_expired(&params, SystemTime::now()));
                }
            }

            // Make sure that the sample doesn't expand any further.
            guards.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
            assert_eq!(guards.guards.len(), params.min_filtered_sample_size);
            guards.assert_consistency();

            samples.push(guards.sample.into_iter().collect());
        }

        // The probability of getting the same sample 3 times in a row is (20 choose 5)^-2,
        // which is pretty low.  (About 1 in 240 million.)
        assert!(samples[0] != samples[1] || samples[1] != samples[2]);
    }

    #[test]
    fn persistence() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            ..GuardParams::default()
        };

        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(20);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);

        // Pick a guard and mark it as confirmed.
        let id1 = guards.sample[0].clone();
        guards.record_success(&id1, &params, None, t2);
        assert_eq!(&guards.confirmed, &[id1.clone()]);

        // Encode the guards, then decode them.
        let state: GuardSample = (&guards).into();
        let guards2: GuardSet = state.into();

        assert_eq!(&guards2.sample, &guards.sample);
        assert_eq!(&guards2.confirmed, &guards.confirmed);
        assert_eq!(&guards2.confirmed, &[id1]);
        assert_eq!(
            guards
                .guards
                .values()
                .map(Guard::guard_id)
                .collect::<HashSet<_>>(),
            guards2
                .guards
                .values()
                .map(Guard::guard_id)
                .collect::<HashSet<_>>()
        );
        for g in guards.guards.values() {
            let g2 = guards2.guards.by_all_ids(g.guard_id()).unwrap();
            assert_eq!(format!("{:?}", g), format!("{:?}", g2));
        }
    }

    #[test]
    fn select_primary() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 4,
            ..GuardParams::default()
        };
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(20);
        let t3 = t2 + Duration::from_secs(30);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);

        // Pick a guard and mark it as confirmed.
        let id3 = guards.sample[3].clone();
        guards.record_success(&id3, &params, None, t2);
        assert_eq!(&guards.confirmed, &[id3.clone()]);
        let id1 = guards.sample[1].clone();
        guards.record_success(&id1, &params, None, t3);
        assert_eq!(&guards.confirmed, &[id3.clone(), id1.clone()]);

        // Select primary guards and make sure we're obeying the rules.
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 4);
        assert_eq!(&guards.primary[0], &id3);
        assert_eq!(&guards.primary[1], &id1);
        let p3 = guards.primary[2].clone();
        let p4 = guards.primary[3].clone();
        assert_eq!(
            [id1.clone(), id3.clone(), p3.clone(), p4.clone()]
                .iter()
                .unique()
                .count(),
            4
        );

        // Mark another guard as confirmed and see that the list changes to put
        // that guard right after the previously confirmed guards, but we keep
        // one of the previous unconfirmed primary guards.
        guards.record_success(&p4, &params, None, t3);
        assert_eq!(&guards.confirmed, &[id3.clone(), id1.clone(), p4.clone()]);
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 4);
        assert_eq!(&guards.primary[0], &id3);
        assert_eq!(&guards.primary[1], &id1);
        assert_eq!(&guards.primary, &[id3, id1, p4, p3]);
    }

    #[test]
    fn expiration() {
        let netdir = netdir();
        let params = GuardParams::default();
        let t1 = SystemTime::now();

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);
        // note that there are only 10 Guard+V2Dir nodes in the netdir().
        assert_eq!(guards.sample.len(), 10);

        // Mark one guard as confirmed; it will have a different timeout.
        // Pick a guard and mark it as confirmed.
        let id1 = guards.sample[0].clone();
        guards.record_success(&id1, &params, None, t1);
        assert_eq!(&guards.confirmed, &[id1]);

        let one_day = Duration::from_secs(86400);
        guards.expire_old_guards(&params, t1 + one_day * 30);
        assert_eq!(guards.sample.len(), 10); // nothing has expired.

        // This is long enough to make sure that the confirmed guard has expired.
        guards.expire_old_guards(&params, t1 + one_day * 70);
        assert_eq!(guards.sample.len(), 9);

        guards.expire_old_guards(&params, t1 + one_day * 200);
        assert_eq!(guards.sample.len(), 0);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn sampling_and_usage() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            ..GuardParams::default()
        };
        let st1 = SystemTime::now();
        let i1 = Instant::now();
        let sec = Duration::from_secs(1);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(st1, &params, &netdir);
        guards.select_primary_guards(&params);

        // First guard: try it, and let it fail.
        let usage = crate::GuardUsageBuilder::default().build().unwrap();
        let id1 = guards.primary[0].clone();
        let id2 = guards.primary[1].clone();
        let (src, id) = guards.pick_guard_id(&usage, &params, i1).unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id1);

        guards.record_attempt(&id, i1);
        guards.record_failure(&id, None, i1 + sec);

        // Second guard: try it, and try it again, and have it fail.
        let (src, id) = guards.pick_guard_id(&usage, &params, i1 + sec).unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id2);
        guards.record_attempt(&id, i1 + sec);

        let (src, id_x) = guards.pick_guard_id(&usage, &params, i1 + sec).unwrap();
        // We get the same guard this (second) time that we pick it too, since
        // it is a primary guard, and is_pending won't block it.
        assert_eq!(id_x, id);
        assert_eq!(src, ListKind::Primary);
        guards.record_attempt(&id_x, i1 + sec * 2);
        guards.record_failure(&id_x, None, i1 + sec * 3);
        guards.record_failure(&id, None, i1 + sec * 4);

        // Third guard: this one won't be primary.
        let (src, id3) = guards.pick_guard_id(&usage, &params, i1 + sec * 4).unwrap();
        assert_eq!(src, ListKind::Sample);
        assert!(!guards.primary.contains(&id3));
        guards.record_attempt(&id3, i1 + sec * 5);

        // Fourth guard: Third guard will be pending, so a different one gets
        // handed out here.
        let (src, id4) = guards.pick_guard_id(&usage, &params, i1 + sec * 5).unwrap();
        assert_eq!(src, ListKind::Sample);
        assert!(id3 != id4);
        assert!(!guards.primary.contains(&id4));
        guards.record_attempt(&id4, i1 + sec * 6);

        // Look at usability status: primary guards should be usable
        // immediately; third guard should be too (since primary
        // guards are down).  Fourth should not have a known status,
        // since third is pending.
        assert_eq!(
            guards.circ_usability_status(&id1, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id2, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id3, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id4, &usage, &params, i1 + sec * 6),
            None
        );

        // Have both guards succeed.
        guards.record_success(&id3, &params, None, st1 + sec * 7);
        guards.record_success(&id4, &params, None, st1 + sec * 8);

        // Check the impact of having both guards succeed.
        assert!(guards.primary_guards_invalidated);
        guards.select_primary_guards(&params);
        assert_eq!(&guards.primary, &[id3.clone(), id4.clone()]);

        // Next time we ask for a guard, we get a primary guard again.
        let (src, id) = guards
            .pick_guard_id(&usage, &params, i1 + sec * 10)
            .unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id3);

        // If we ask for a directory guard, we get one of the primaries.
        let mut found = HashSet::new();
        let usage = crate::GuardUsageBuilder::default()
            .kind(crate::GuardUsageKind::OneHopDirectory)
            .build()
            .unwrap();
        for _ in 0..64 {
            let (src, id) = guards
                .pick_guard_id(&usage, &params, i1 + sec * 10)
                .unwrap();
            assert_eq!(src, ListKind::Primary);
            assert_eq!(
                guards.circ_usability_status(&id, &usage, &params, i1 + sec * 10),
                Some(true)
            );
            guards.record_attempt_abandoned(&id);
            found.insert(id);
        }
        assert!(found.len() == 2);
        assert!(found.contains(&id3));
        assert!(found.contains(&id4));

        // Since the primaries are now up, other guards are not usable.
        assert_eq!(
            guards.circ_usability_status(&id1, &usage, &params, i1 + sec * 12),
            Some(false)
        );
        assert_eq!(
            guards.circ_usability_status(&id2, &usage, &params, i1 + sec * 12),
            Some(false)
        );
    }

    #[test]
    fn everybodys_down() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let mut st = SystemTime::now();
        let mut inst = Instant::now();
        let sec = Duration::from_secs(1);
        let usage = crate::GuardUsageBuilder::default().build().unwrap();

        let mut guards = GuardSet::default();

        guards.extend_sample_as_needed(st, &params, &netdir);
        guards.select_primary_guards(&params);

        assert_eq!(guards.sample.len(), 5);
        for _ in 0..5 {
            let (_, id) = guards.pick_guard_id(&usage, &params, inst).unwrap();
            guards.record_attempt(&id, inst);
            guards.record_failure(&id, None, inst + sec);

            inst += sec * 2;
            st += sec * 2;
        }

        let e = guards.pick_guard_id(&usage, &params, inst);
        assert!(matches!(e, Err(PickGuardError::AllGuardsDown { .. })));

        // Now in theory we should re-grow when we extend.
        guards.extend_sample_as_needed(st, &params, &netdir);
        guards.select_primary_guards(&params);
        assert_eq!(guards.sample.len(), 10);
    }

    #[test]
    fn retry_primary() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let usage = crate::GuardUsageBuilder::default().build().unwrap();

        let mut guards = GuardSet::default();

        guards.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
        guards.select_primary_guards(&params);

        assert_eq!(guards.primary.len(), 2);
        assert!(!guards.all_primary_guards_are_unreachable());

        // Let one primary guard fail.
        let (kind, p_id1) = guards
            .pick_guard_id(&usage, &params, Instant::now())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        guards.record_failure(&p_id1, None, Instant::now());
        assert!(!guards.all_primary_guards_are_unreachable());

        // Now let the other one fail.
        let (kind, p_id2) = guards
            .pick_guard_id(&usage, &params, Instant::now())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        guards.record_failure(&p_id2, None, Instant::now());
        assert!(guards.all_primary_guards_are_unreachable());

        // Now mark the guards retriable.
        guards.mark_primary_guards_retriable();
        assert!(!guards.all_primary_guards_are_unreachable());
        let (kind, p_id3) = guards
            .pick_guard_id(&usage, &params, Instant::now())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        assert_eq!(p_id3, p_id1);
    }

    #[test]
    fn count_missing_mds() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let usage = crate::GuardUsageBuilder::default().build().unwrap();
        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 2);

        let (_kind, p_id1) = guards
            .pick_guard_id(&usage, &params, Instant::now())
            .unwrap();
        guards.record_success(&p_id1, &params, None, SystemTime::now());
        assert_eq!(guards.n_primary_without_id_info_in(&netdir), 0);

        use tor_netdir::testnet;
        let netdir2 = testnet::construct_custom_netdir(|_idx, bld| {
            let md_so_far = bld.md.testing_md().expect("Couldn't build md?");
            if &p_id1.0.identity(RelayIdType::Ed25519).unwrap() == md_so_far.ed25519_id() {
                bld.omit_md = true;
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        assert_eq!(guards.n_primary_without_id_info_in(&netdir2), 1);
    }

    #[test]
    fn copy_status() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let mut guards1 = GuardSet::default();
        guards1.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
        guards1.select_primary_guards(&params);
        let mut guards2 = guards1.clone();

        // Make a persistent change in guards1, and a different persistent change in guards2.
        let id1 = guards1.primary[0].clone();
        let id2 = guards1.primary[1].clone();
        guards1.record_success(&id1, &params, None, SystemTime::now());
        guards2.record_success(&id2, &params, None, SystemTime::now());
        // Make a non-persistent change in guards2.
        guards2.record_failure(&id2, None, Instant::now());

        // Copy status: make sure non-persistent status changed, and  persistent didn't.
        guards1.copy_ephemeral_status_into_newly_loaded_state(guards2);
        {
            let g1 = guards1.get(&id1).unwrap();
            let g2 = guards1.get(&id2).unwrap();
            assert!(g1.confirmed());
            assert!(!g2.confirmed());
            assert_eq!(g1.reachable(), Reachable::Untried);
            assert_eq!(g2.reachable(), Reachable::Unreachable);
        }

        // Now make a new set of unrelated guards, and make sure that copying
        // from it doesn't change the membership of guards1.
        let mut guards3 = GuardSet::default();
        let g1_set: HashSet<_> = guards1
            .guards
            .values()
            .map(|g| g.guard_id().clone())
            .collect();
        let mut g3_set: HashSet<_> = HashSet::new();
        for _ in 0..4 {
            // There is roughly a 1-in-5000 chance of getting the same set
            // twice, so we loop until that doesn't happen.
            guards3.extend_sample_as_needed(SystemTime::now(), &params, &netdir);
            guards3.select_primary_guards(&params);
            g3_set = guards3
                .guards
                .values()
                .map(|g| g.guard_id().clone())
                .collect();

            // There is roughly a 1-in-5000 chance of getting the same set twice, so
            if g1_set == g3_set {
                guards3 = GuardSet::default();
                continue;
            }
            break;
        }
        assert_ne!(g1_set, g3_set);
        // Do the copy; make sure that the membership is unchanged.
        guards1.copy_ephemeral_status_into_newly_loaded_state(guards3);
        let g1_set_new: HashSet<_> = guards1
            .guards
            .values()
            .map(|g| g.guard_id().clone())
            .collect();
        assert_eq!(g1_set, g1_set_new);
    }
}
