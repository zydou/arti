//! This module defines and implements traits used to create a guard sample from
//! either bridges or relays.

use std::time::SystemTime;

use tor_linkspec::{HasRelayIds, OwnedChanTarget};
use tor_netdir::NetDir;

/// A "Universe" is a source from which guard candidates are drawn, and from
/// which guards are updated.
pub(crate) trait Universe {
    /// Check whether this universe contains a candidate with the given
    /// identities.
    ///
    /// Return `Some(true)` if it definitely does; `Some(false)` if it
    /// definitely does not, and `None` if we cannot tell without downloading
    /// more information.
    fn contains<T: HasRelayIds>(&self, id: &T) -> Option<bool>;

    /// Return full information about a member of this universe, by its identity.
    fn status<T: HasRelayIds>(&self, id: &T) -> CandidateStatus;

    /// Return the time at which this Universe last changed.  This can be
    /// approximate.
    fn timestamp(&self) -> SystemTime;
}

/// Information about a single guard candidate, as returned by
/// [`Universe::status`].
#[derive(Clone, Debug)]
pub(crate) enum CandidateStatus {
    /// The candidate is definitely present in some form.
    Present {
        /// True if the candidate is not currently disabled for use as a guard.
        listed_as_guard: bool,
        /// True if the candidate can be used as a directory cache.
        is_dir_cache: bool,
        /// Information about connecting to the candidate and using it to build
        /// a channel.
        owned_target: OwnedChanTarget,
    },
    /// The candidate is definitely not in the [`Universe`].
    Absent,
    /// We would need to download more directory information to be sure whether
    /// this candidate is in the [`Universe`].
    Uncertain,
}

impl Universe for NetDir {
    fn timestamp(&self) -> SystemTime {
        NetDir::lifetime(self).valid_after()
    }

    fn contains<T: HasRelayIds>(&self, id: &T) -> Option<bool> {
        NetDir::ids_listed(self, id)
    }

    fn status<T: HasRelayIds>(&self, id: &T) -> CandidateStatus {
        match NetDir::by_ids(self, id) {
            Some(relay) => CandidateStatus::Present {
                listed_as_guard: relay.is_flagged_guard(),
                is_dir_cache: relay.is_dir_cache(),
                owned_target: OwnedChanTarget::from_chan_target(&relay),
            },
            None => match NetDir::ids_listed(self, id) {
                Some(true) => panic!("ids_listed said true, but by_ids said none!"),
                Some(false) => CandidateStatus::Absent,
                None => CandidateStatus::Uncertain,
            },
        }
    }
}
