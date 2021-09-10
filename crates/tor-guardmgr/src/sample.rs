//! Logic for manipulating a sampled set of guards, along with various
//! orderings on that sample.

use crate::filter::GuardFilter;
use crate::guard::{Guard, NewlyConfirmed, Reachable};
use crate::{GuardId, GuardParams, GuardUsage, GuardUsageKind};
use tor_netdir::{NetDir, Relay};

use itertools::Itertools;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime};

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
///
/// # Limitations
///
/// Our current guard implementation in arti only uses
/// `GuardSet` at time, but eventually we may want to allow several to
/// exist, of which only one is "active".
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(from = "GuardSample")]
pub(crate) struct GuardSet {
    /// Map from identities to guards, for every guard in this sample.
    guards: HashMap<GuardId, Guard>,
    /// Identities of all the guards in the sample, in sample order.
    ///
    /// This contains the same elements as `self.guards.keys()`, and
    /// only exists to define an ordering on the guards.
    sample: Vec<GuardId>,
    /// Identities of all the confirmed guards in the sample, in
    /// confirmed order.
    ///
    /// This contains a subset of the values in `self.guards.keys()`.
    confirmed: Vec<GuardId>,
    /// Identities of all the primary guards, in preference order
    /// (from best to worst).
    ///
    /// This contains a subset of the values in `self.guards.keys()`.
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
}

impl ListKind {
    /// Return true if this is a primary guard.
    pub(crate) fn is_primary(&self) -> bool {
        self == &ListKind::Primary
    }
}
impl GuardSet {
    /// Return a new empty guard set.
    pub(crate) fn new() -> Self {
        Self::default()
    }

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

    /// Remove all elements from this `GuardSet` that ought to be
    /// referenced by another element, but which are not.
    ///
    /// This method only removes corrupted elements; it doesn't add or
    /// fix anything.  It won't do anything if the `GuardSet` is
    /// well-formed.
    fn fix_consistency(&mut self) {
        let sample_set: HashSet<_> = self.sample.iter().collect();
        self.guards
            .retain(|id, g| g.guard_id() == id && sample_set.contains(id));
        let guards = &self.guards; // avoid borrow issues
        self.sample.retain(|id| guards.contains_key(id));
        self.confirmed.retain(|id| guards.contains_key(id));
        self.primary.retain(|id| guards.contains_key(id));
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
        self.primary
            .retain(|id| guards.get(id).map(|g| filt.permits(g)).unwrap_or(false));

        self.primary_guards_invalidated = true;
    }

    /// Return a serializable state object that can be stored to disk
    /// to capture the current state of this GuardSet.
    fn get_state(&self) -> GuardSample<'_> {
        let guards = self
            .sample
            .iter()
            .map(|id| Cow::Borrowed(self.guards.get(id).expect("Inconsistent state")))
            .collect();

        GuardSample {
            guards,
            confirmed: Cow::Borrowed(&self.confirmed),
        }
    }

    /// Reconstruct a guard state from its serialized representation.
    fn from_state(state: GuardSample<'_>) -> Self {
        let mut guards = HashMap::new();
        let mut sample = Vec::new();
        for guard in state.guards {
            sample.push(guard.guard_id().clone());
            guards.insert(guard.guard_id().clone(), guard.into_owned());
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
        };

        // Fix any inconsistencies in the stored representation.
        let len_pre = guard_set.inner_lengths();
        guard_set.fix_consistency();
        let len_post = guard_set.inner_lengths();
        if len_pre != len_post {
            tracing::info!(
                "Resolved a consistency issue in stored guard state. Diagnostic codes: {:?}, {:?}",
                len_pre,
                len_post
            );
        }
        guard_set
    }

    /// Return true if `relay` is a member of this set.
    fn contains_relay(&self, relay: &Relay<'_>) -> bool {
        // Note: Could implement Borrow instead, but I don't think it'll
        // matter.
        let id = GuardId::from_relay(relay);
        self.guards.contains_key(&id)
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
    ///
    /// # Complications
    ///
    /// For spec conformance, we only consider our filter when
    /// selecting new guards if the filter is "very restrictive".
    /// That makes it possible that this will add fewer
    /// filter-permitted guards than we had wanted.  Because of that,
    /// it's advisable to run this function in a loop until it returns
    /// false.
    pub(crate) fn extend_sample_as_needed(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
        dir: &NetDir,
    ) -> bool {
        self.assert_consistency();
        let n_filtered_usable = self
            .guards
            .values()
            .filter(|g| self.active_filter.permits(*g) && g.reachable() != Reachable::Unreachable)
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

        // What's the most weight we're willing to have in the sample?
        let target_weight = {
            let total_weight = dir.total_weight(tor_netdir::WeightRole::Guard, |r| {
                r.is_flagged_guard() && r.is_dir_cache()
            });
            total_weight
                .ratio(params.max_sample_bw_fraction)
                .unwrap_or(total_weight)
        };
        let mut current_weight: tor_netdir::RelayWeight = self
            .guards
            .values()
            .filter_map(|guard| guard.get_weight(dir))
            .sum();
        if current_weight >= target_weight {
            return false; // Can't add any more weight.
        }

        // Ask the netdir for a set of guards we could use.
        let n_candidates = if self.filter_is_restrictive || self.active_filter.is_unfiltered() {
            n_to_add
        } else {
            // The filter will probably reject a bunch of guards, but we sample
            // before filtering, so we make this larger on an ad-hoc basis.
            n_to_add * 3
        };
        let candidates = dir.pick_n_relays(
            &mut rand::thread_rng(),
            n_candidates,
            tor_netdir::WeightRole::Guard,
            |relay| {
                let filter_ok = if self.filter_is_restrictive {
                    // If we have a very restrictive filter, we only add
                    // relays permitted by that filter.
                    self.active_filter.permits(relay)
                } else {
                    // Otherwise we add any relay to the sample.
                    true
                };
                filter_ok
                    && relay.is_flagged_guard()
                    && relay.is_dir_cache()
                    && !self.contains_relay(relay)
            },
        );

        // Add those candidates to the sample, up to our maximum weight.
        let mut any_added = false;
        let mut n_filtered_usable = n_filtered_usable;
        for candidate in candidates {
            if current_weight >= target_weight
                && self.guards.len() >= params.min_filtered_sample_size
            {
                // Can't add any more weight.  (We only enforce target_weight
                // if we have at least 'min_filtered_sample_size' in
                // our total sample.)
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
            let candidate_weight = dir.relay_weight(&candidate, tor_netdir::WeightRole::Guard);
            if self.active_filter.permits(&candidate) {
                n_filtered_usable += 1;
            }
            current_weight += candidate_weight;
            self.add_guard(&candidate, now, params);
            any_added = true;
        }

        self.assert_consistency();
        any_added
    }

    /// Add `relay` as a new guard.
    ///
    /// Does nothing if it is already a guard.
    fn add_guard(&mut self, relay: &Relay<'_>, now: SystemTime, params: &GuardParams) {
        let id = GuardId::from_relay(relay);
        if self.guards.contains_key(&id) {
            return;
        }
        let guard = Guard::from_relay(relay, now, params);
        self.guards.insert(id.clone(), guard);
        self.sample.push(id);
        self.primary_guards_invalidated = true;
    }

    /// Update the status of every guard  in this sample from a network
    /// directory.
    pub(crate) fn update_status_from_netdir(&mut self, dir: &NetDir) {
        for g in self.guards.values_mut() {
            g.update_from_netdir(dir);
        }
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
            // We only consider guards that the filter allows.
            .filter_map(|id| {
                let g = self.guards.get(id).expect("Inconsistent guard state");
                if self.active_filter.permits(g) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            // The first n_primary guards on that list are primary!
            .take(params.n_primary)
            .collect();

        // Clear exploratory_circ_pending for all primary guards.
        for id in self.primary.iter() {
            if let Some(guard) = self.guards.get_mut(id) {
                guard.note_exploratory_circ(false);
            }
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
        self.guards.retain(|_, g| !g.is_expired(params, now));
        let guards = &self.guards; // to avoid borrowing issue
        self.sample.retain(|id| guards.contains_key(id));
        self.confirmed.retain(|id| guards.contains_key(id));
        self.primary.retain(|id| guards.contains_key(id));
        self.assert_consistency();

        if self.guards.len() < n_pre {
            tracing::debug!(
                "{} guards have been expired as too old.",
                n_pre - self.guards.len()
            );
            self.primary_guards_invalidated = true;
        }
    }

    /// Return an iterator over the Id for every Guard in the sample that
    /// is not known to be Unreachable.
    fn reachable_sample_ids(&self) -> impl Iterator<Item = &GuardId> {
        self.sample.iter().filter(move |id| {
            let g = self.guards.get(id).expect("Inconsistent guard state");
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
        // XXXX: This isn't what the spec says.  It also says:
        //
        // * Among guards that do not appear in {CONFIRMED_GUARDS},
        // {is_pending}==true guards have higher priority.
        // * Among those, the guard with earlier {last_tried_connect} time
        // has higher priority.
        // * Finally, among guards that do not appear in
        // {CONFIRMED_GUARDS} with {is_pending==false}, all have equal
        // priority.

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
            .filter_map(move |(p, id)| self.guards.get(id).map(|g| (p, g)))
    }

    /// Return true if `guard_id` is the identity for a primary guard.
    fn guard_is_primary(&self, guard_id: &GuardId) -> bool {
        // This is O(n), but the list is short.
        self.primary.contains(guard_id)
    }

    /// For every guard that has been marked as `Unreachable` for too long,
    /// mark it as `Unknown`.
    pub(crate) fn consider_all_retries(&mut self, now: Instant) {
        for guard in self.guards.values_mut() {
            guard.consider_retry(now);
        }
    }

    /// Mark every `Unreachable` primary guard as `Unknown`.
    pub(crate) fn mark_primary_guards_retriable(&mut self) {
        for id in self.primary.iter() {
            if let Some(g) = self.guards.get_mut(id) {
                g.mark_retriable();
            }
        }
    }

    /// Mark every `Unreachable` guard as `Unknown`.
    pub(crate) fn mark_all_guards_retriable(&mut self) {
        for (_, g) in self.guards.iter_mut() {
            g.mark_retriable();
        }
    }

    /// Record that an attempt has begun to use the guard with
    /// `guard_id`.
    pub(crate) fn record_attempt(&mut self, guard_id: &GuardId, now: Instant) {
        let is_primary = self.guard_is_primary(guard_id);
        if let Some(guard) = self.guards.get_mut(guard_id) {
            guard.record_attempt(now);

            if !is_primary {
                guard.note_exploratory_circ(true);
            }
        }
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just succeeded.
    pub(crate) fn record_success(
        &mut self,
        guard_id: &GuardId,
        params: &GuardParams,
        now: SystemTime,
    ) {
        self.assert_consistency();
        if let Some(guard) = self.guards.get_mut(guard_id) {
            let newly_confirmed = guard.record_success(now, params);

            if newly_confirmed == NewlyConfirmed::Yes {
                self.confirmed.push(guard_id.clone());
                self.primary_guards_invalidated = true;
            }
        }
        self.assert_consistency();
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just failed.
    pub(crate) fn record_failure(&mut self, guard_id: &GuardId, now: Instant) {
        // TODO use instant uniformly for in-process, and systemtime for storage?
        let is_primary = self.guard_is_primary(guard_id);
        if let Some(guard) = (&mut self.guards).get_mut(guard_id) {
            guard.record_failure(now, is_primary);
        }
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just been abandoned, without learning whether it succeeded or failed.
    pub(crate) fn record_attempt_abandoned(&mut self, guard_id: &GuardId) {
        if let Some(guard) = (&mut self.guards).get_mut(guard_id) {
            guard.note_exploratory_circ(false)
        }
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

        let cutoff = now - params.np_connect_timeout;

        for (src, guard) in self.preference_order() {
            if guard.guard_id() == guard_id {
                return Some(true);
            }
            if self.active_filter.permits(guard) && guard.conforms_to_usage(usage) {
                match (src, guard.reachable()) {
                    (_, Reachable::Reachable) => return Some(false),
                    (_, Reachable::Unreachable) => (),
                    (ListKind::Primary, Reachable::Unknown) => return Some(false),
                    (_, Reachable::Unknown) => {
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
    /// On success, returns the kind of guard that we got, and its identity.
    // XXXX probably caller has to do other stuff too depending on the netdir.
    pub(crate) fn pick_guard(
        &self,
        usage: &GuardUsage,
        params: &GuardParams,
    ) -> Result<(ListKind, GuardId), PickGuardError> {
        debug_assert!(!self.primary_guards_invalidated);
        let n_options = match usage.kind {
            GuardUsageKind::OneHopDirectory => params.dir_parallelism,
            GuardUsageKind::Data => params.data_parallelism,
        };

        let mut options: Vec<_> = self
            .preference_order()
            .filter(|(_, g)| {
                self.active_filter.permits(*g)
                    && g.reachable() != Reachable::Unreachable
                    && !g.exploratory_circ_pending()
                    && g.conforms_to_usage(usage)
            })
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
            None => Err(PickGuardError::EveryoneIsDown),
        }
    }
}

/// State object used to serialize and deserialize a [`GuardSet`].
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GuardSample<'a> {
    /// Equivalent to `GuardSet.guards.values()`, except in sample order.
    guards: Vec<Cow<'a, Guard>>,
    /// The identities for the confirmed members of `guards`, in confirmed order.
    confirmed: Cow<'a, Vec<GuardId>>,
    // XXXX Do we need a HashMap to represent additional fields? I think we may.
}
use serde::Serializer;

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

/// A error caused by a failure to pick a guard.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PickGuardError {
    /// All members of the current sample were down, or waiting for
    /// other circuits to finish.
    #[error("Everybody is either down or pending")]
    EveryoneIsDown,

    /// We had no members in the current sample.
    #[error("The current sample is empty")]
    SampleIsEmpty,
}
