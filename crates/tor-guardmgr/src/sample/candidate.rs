//! This module defines and implements traits used to create a guard sample from
//! either bridges or relays.

use std::{sync::Arc, time::SystemTime};

use tor_linkspec::{ByRelayIds, ChanTarget, HasRelayIds, OwnedChanTarget};
use tor_netdir::{NetDir, Relay, RelayWeight};
use tor_relay_selection::{RelayExclusion, RelaySelector, RelayUsage};

use crate::{GuardFilter, GuardParams};

/// A "Universe" is a source from which guard candidates are drawn, and from
/// which guards are updated.
pub(crate) trait Universe {
    /// Check whether this universe contains a candidate for the given guard.
    ///
    /// Return `Some(true)` if it definitely does; `Some(false)` if it
    /// definitely does not, and `None` if we cannot tell without downloading
    /// more information.
    fn contains<T: ChanTarget>(&self, guard: &T) -> Option<bool>;

    /// Return full information about a member of this universe for a given guard.
    fn status<T: ChanTarget>(&self, guard: &T) -> CandidateStatus<Candidate>;

    /// Return an (approximate) timestamp describing when this universe was
    /// generated.
    ///
    /// This timestamp is used to determine how long a guard has been listed or
    /// unlisted.
    fn timestamp(&self) -> SystemTime;

    /// Return information about how much of this universe has been added to
    /// `sample`, and how much we're willing to add according to `params`.
    fn weight_threshold<T>(&self, sample: &ByRelayIds<T>, params: &GuardParams) -> WeightThreshold
    where
        T: HasRelayIds;

    /// Return up to `n` of new candidate guards from this Universe.
    ///
    /// Only return elements that have no conflicts with identities in
    /// `pre_existing`, and which obey `filter`.
    fn sample<T>(
        &self,
        pre_existing: &ByRelayIds<T>,
        filter: &GuardFilter,
        n: usize,
    ) -> Vec<(Candidate, RelayWeight)>
    where
        T: HasRelayIds;
}

/// Information about a single guard candidate, as returned by
/// [`Universe::status`].
#[derive(Clone, Debug)]
pub(crate) enum CandidateStatus<T> {
    /// The candidate is definitely present in some form.
    Present(T),
    /// The candidate is definitely not in the [`Universe`].
    Absent,
    /// We would need to download more directory information to be sure whether
    /// this candidate is in the [`Universe`].
    Uncertain,
}

/// Information about a candidate that we have selected as a guard.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    /// True if the candidate is not currently disabled for use as a guard.
    ///
    /// (To be enabled, it must be in the lastest directory, with the Fast,
    /// Stable, and Guard flags.)
    pub(crate) listed_as_guard: bool,
    /// True if the candidate can be used as a directory cache.
    pub(crate) is_dir_cache: bool,
    /// True if we have complete directory information about this candidate.
    pub(crate) full_dir_info: bool,
    /// Information about connecting to the candidate and using it to build
    /// a channel.
    pub(crate) owned_target: OwnedChanTarget,
    /// How should we display information about this candidate if we select it?
    pub(crate) sensitivity: crate::guard::DisplayRule,
}

/// Information about how much of the universe we are using in a guard sample,
/// and how much we are allowed to use.
///
/// We use this to avoid adding the whole network to our guard sample.
#[derive(Debug, Clone)]
pub(crate) struct WeightThreshold {
    /// The amount of the universe that we are using, in [`RelayWeight`].
    pub(crate) current_weight: RelayWeight,
    /// The greatest amount that we are willing to use, in [`RelayWeight`].
    ///
    /// We can violate this maximum if it's necessary in order to meet our
    /// minimum number of guards; otherwise, were're willing to add a _single_
    /// guard that exceeds this threshold, but no more.
    pub(crate) maximum_weight: RelayWeight,
}

impl Universe for NetDir {
    fn timestamp(&self) -> SystemTime {
        NetDir::lifetime(self).valid_after()
    }

    fn contains<T: ChanTarget>(&self, guard: &T) -> Option<bool> {
        NetDir::ids_listed(self, guard)
    }

    fn status<T: ChanTarget>(&self, guard: &T) -> CandidateStatus<Candidate> {
        // TODO #504 - if we make a data extractor for Relays, we'll want
        // to use it here.
        match NetDir::by_ids(self, guard) {
            Some(relay) => CandidateStatus::Present(Candidate {
                listed_as_guard: relay.is_suitable_as_guard(),
                is_dir_cache: relay.is_dir_cache(),
                owned_target: OwnedChanTarget::from_chan_target(&relay),
                full_dir_info: true,
                sensitivity: crate::guard::DisplayRule::Sensitive,
            }),
            None => match NetDir::ids_listed(self, guard) {
                Some(true) => panic!("ids_listed said true, but by_ids said none!"),
                Some(false) => CandidateStatus::Absent,
                None => CandidateStatus::Uncertain,
            },
        }
    }

    fn weight_threshold<T>(&self, sample: &ByRelayIds<T>, params: &GuardParams) -> WeightThreshold
    where
        T: HasRelayIds,
    {
        // When adding from a netdir, we impose a limit on the fraction of the
        // universe we're willing to add.
        let maximum_weight = {
            // TODO #504 - to convert this, we need tor_relay_selector to apply
            // to UncheckedRelay.
            let total_weight = self.total_weight(tor_netdir::WeightRole::Guard, |r| {
                let d = r.low_level_details();
                d.is_suitable_as_guard() && d.is_dir_cache()
            });
            total_weight
                .ratio(params.max_sample_bw_fraction)
                .unwrap_or(total_weight)
        };

        let current_weight: tor_netdir::RelayWeight = sample
            .values()
            .filter_map(|guard| {
                self.weight_by_rsa_id(guard.rsa_identity()?, tor_netdir::WeightRole::Guard)
            })
            .sum();

        WeightThreshold {
            current_weight,
            maximum_weight,
        }
    }

    fn sample<T>(
        &self,
        pre_existing: &ByRelayIds<T>,
        filter: &GuardFilter,
        n: usize,
    ) -> Vec<(Candidate, RelayWeight)>
    where
        T: HasRelayIds,
    {
        /// Return the weight for this relay, if we can find it.
        ///
        /// (We should always be able to find it as `NetDir`s are constructed
        /// today.)
        fn weight(dir: &NetDir, relay: &Relay<'_>) -> Option<RelayWeight> {
            dir.weight_by_rsa_id(relay.rsa_identity()?, tor_netdir::WeightRole::Guard)
        }

        let already_selected = pre_existing
            .values()
            .flat_map(|item| item.identities())
            .map(|id| id.to_owned())
            .collect();
        let mut sel = RelaySelector::new(
            RelayUsage::new_guard(),
            RelayExclusion::exclude_identities(already_selected),
        );
        filter.add_to_selector(&mut sel);

        let (relays, _outcome) = sel.select_n_relays(&mut rand::thread_rng(), n, self);
        // TODO: report _outcome somehow.
        relays
            .iter()
            .map(|relay| {
                (
                    Candidate {
                        listed_as_guard: true,
                        is_dir_cache: true,
                        full_dir_info: true,
                        owned_target: OwnedChanTarget::from_chan_target(relay),
                        sensitivity: crate::guard::DisplayRule::Sensitive,
                    },
                    // TODO: It would be better not to need this function.
                    weight(self, relay).unwrap_or_else(|| RelayWeight::from(0)),
                )
            })
            .collect()
    }
}

/// Reference to a [`Universe`] of one of the types supported by this crate.
///
/// This enum exists because `Universe` is not dyn-compatible.
#[derive(Clone, Debug)]
pub(crate) enum UniverseRef {
    /// A reference to a netdir.
    NetDir(Arc<NetDir>),
    /// A BridgeSet (which is always references internally)
    #[cfg(feature = "bridge-client")]
    BridgeSet(crate::bridge::BridgeSet),
}

impl Universe for UniverseRef {
    fn contains<T: ChanTarget>(&self, guard: &T) -> Option<bool> {
        match self {
            UniverseRef::NetDir(r) => r.contains(guard),
            #[cfg(feature = "bridge-client")]
            UniverseRef::BridgeSet(r) => r.contains(guard),
        }
    }

    fn status<T: ChanTarget>(&self, guard: &T) -> CandidateStatus<Candidate> {
        match self {
            UniverseRef::NetDir(r) => r.status(guard),
            #[cfg(feature = "bridge-client")]
            UniverseRef::BridgeSet(r) => r.status(guard),
        }
    }

    fn timestamp(&self) -> SystemTime {
        match self {
            UniverseRef::NetDir(r) => r.timestamp(),
            #[cfg(feature = "bridge-client")]
            UniverseRef::BridgeSet(r) => r.timestamp(),
        }
    }

    fn weight_threshold<T>(&self, sample: &ByRelayIds<T>, params: &GuardParams) -> WeightThreshold
    where
        T: HasRelayIds,
    {
        match self {
            UniverseRef::NetDir(r) => r.weight_threshold(sample, params),
            #[cfg(feature = "bridge-client")]
            UniverseRef::BridgeSet(r) => r.weight_threshold(sample, params),
        }
    }

    fn sample<T>(
        &self,
        pre_existing: &ByRelayIds<T>,
        filter: &GuardFilter,
        n: usize,
    ) -> Vec<(Candidate, RelayWeight)>
    where
        T: HasRelayIds,
    {
        match self {
            UniverseRef::NetDir(r) => r.sample(pre_existing, filter, n),
            #[cfg(feature = "bridge-client")]
            UniverseRef::BridgeSet(r) => r.sample(pre_existing, filter, n),
        }
    }
}
