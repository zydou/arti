//! Declare the [`FallbackState`] type, which is used to store a set of FallbackDir.

use crate::skew::SkewObservation;
use rand::seq::IteratorRandom;
use std::time::{Duration, Instant};
use tor_linkspec::HasRelayIds;

use super::{DirStatus, FallbackDir, FallbackDirBuilder};
use crate::fallback::default_fallbacks;
use crate::{ids::FallbackId, PickGuardError};
use tor_basic_utils::iter::{FilterCount, IteratorExt as _};
use tor_config::define_list_builder_helper;

/// A list of fallback directories.
///
/// Fallback directories (represented by [`FallbackDir`]) are used by Tor
/// clients when they don't already have enough other directory information to
/// contact the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FallbackList {
    /// The underlying fallbacks in this set.
    fallbacks: Vec<FallbackDir>,
}

impl<T: IntoIterator<Item = FallbackDir>> From<T> for FallbackList {
    fn from(fallbacks: T) -> Self {
        FallbackList {
            fallbacks: fallbacks.into_iter().collect(),
        }
    }
}

define_list_builder_helper! {
    // pub because tor-dirmgr needs it for NetworkConfig.fallback_caches
    pub struct FallbackListBuilder {
        pub(crate) fallbacks: [FallbackDirBuilder],
    }
    built: FallbackList = FallbackList { fallbacks };
    default = default_fallbacks();
}

impl FallbackList {
    /// Return the number of fallbacks in this list.
    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }
    /// Return true if there are no fallbacks in this list.
    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }
    /// Return a random member of this list.
    pub fn choose<R: rand::Rng>(&self, rng: &mut R) -> Result<&FallbackDir, PickGuardError> {
        self.fallbacks
            .iter()
            .choose(rng)
            .ok_or(PickGuardError::NoCandidatesAvailable)
    }
}

/// A set of fallback directories, in usable form.
#[derive(Debug, Clone)]
pub(crate) struct FallbackState {
    /// The list of fallbacks in the set.
    ///
    /// We require that these are sorted and unique by (ED,RSA) keys.
    fallbacks: Vec<Entry>,
}

/// Wrapper type for FallbackDir converted into crate::Guard, and the status
/// information that we store about it.
///
/// Defines a sort order to ensure that we can look up fallback directories by
/// binary search on keys.
#[derive(Debug, Clone)]
pub(super) struct Entry {
    /// The inner fallback directory.
    fallback: FallbackDir,

    /// Whether the directory is currently usable, and if not, when we can retry
    /// it.
    status: DirStatus,
    /// The latest clock skew observation we have from this fallback directory
    /// (if any).
    clock_skew: Option<SkewObservation>,
}

/// Least amount of time we'll wait before retrying a fallback cache.
//
// TODO: we may want to make this configurable to a smaller value for chutney networks.
const FALLBACK_RETRY_FLOOR: Duration = Duration::from_secs(150);

impl From<FallbackDir> for Entry {
    fn from(fallback: FallbackDir) -> Self {
        let status = DirStatus::new(FALLBACK_RETRY_FLOOR);
        Entry {
            fallback,
            status,
            clock_skew: None,
        }
    }
}

impl HasRelayIds for Entry {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        self.fallback.identity(key_type)
    }
}

impl From<&FallbackList> for FallbackState {
    fn from(list: &FallbackList) -> Self {
        let mut fallbacks: Vec<Entry> = list.fallbacks.iter().map(|fb| fb.clone().into()).collect();
        fallbacks.sort_by(|x, y| x.cmp_by_relay_ids(y));
        fallbacks.dedup_by(|x, y| x.same_relay_ids(y));
        FallbackState { fallbacks }
    }
}

impl FallbackState {
    /// Return a random member of this FallbackSet that's usable at `now`.
    pub(crate) fn choose<R: rand::Rng>(
        &self,
        rng: &mut R,
        now: Instant,
        filter: &crate::GuardFilter,
    ) -> Result<&FallbackDir, PickGuardError> {
        if self.fallbacks.is_empty() {
            return Err(PickGuardError::NoCandidatesAvailable);
        }

        let mut running = FilterCount::default();
        let mut filtered = FilterCount::default();

        self.fallbacks
            .iter()
            .filter_cnt(&mut running, |ent| ent.status.usable_at(now))
            .filter_cnt(&mut filtered, |ent| filter.permits(&ent.fallback))
            .choose(rng)
            .map(|ent| &ent.fallback)
            .ok_or_else(|| PickGuardError::AllFallbacksDown {
                retry_at: self.next_retry(),
                running,
                filtered,
            })
    }

    /// Return the next time at which any member of this set will become ready.
    ///
    /// Returns None if no elements are failing.
    fn next_retry(&self) -> Option<Instant> {
        self.fallbacks
            .iter()
            .filter_map(|ent| ent.status.next_retriable())
            .min()
    }

    /// Return a reference to the entry whose identity is `id`, if there is one.
    fn get(&self, id: &FallbackId) -> Option<&Entry> {
        match self.fallbacks.binary_search_by(|e| e.cmp_by_relay_ids(id)) {
            Ok(idx) => Some(&self.fallbacks[idx]),
            Err(_) => None,
        }
    }

    /// Return a mutable reference to the entry whose identity is `id`, if there is one.
    fn get_mut(&mut self, id: &FallbackId) -> Option<&mut Entry> {
        match self.fallbacks.binary_search_by(|e| e.cmp_by_relay_ids(id)) {
            Ok(idx) => Some(&mut self.fallbacks[idx]),
            Err(_) => None,
        }
    }

    /// Return true if this set contains some entry with the given `id`.
    pub(crate) fn contains(&self, id: &FallbackId) -> bool {
        self.get(id).is_some()
    }

    /// Record that a success has occurred for the fallback with the given
    /// identity.
    ///
    /// Be aware that for fallbacks, we only count a successful directory
    /// operation as a success: a circuit success is not enough.
    pub(crate) fn note_success(&mut self, id: &FallbackId) {
        if let Some(entry) = self.get_mut(id) {
            entry.status.note_success();
        }
    }

    /// Record that a failure has occurred for the fallback with the given
    /// identity.
    pub(crate) fn note_failure(&mut self, id: &FallbackId, now: Instant) {
        if let Some(entry) = self.get_mut(id) {
            entry.status.note_failure(now);
        }
    }

    /// Consume `other` and copy all of its fallback status entries into the corresponding entries for `self`.
    pub(crate) fn take_status_from(&mut self, other: FallbackState) {
        use itertools::EitherOrBoth::Both;

        itertools::merge_join_by(self.fallbacks.iter_mut(), other.fallbacks, |a, b| {
            a.fallback.cmp_by_relay_ids(&b.fallback)
        })
        .for_each(|entry| {
            if let Both(entry, other) = entry {
                debug_assert!(entry.fallback.same_relay_ids(&other.fallback));
                entry.status = other.status;
            }
        });
    }

    /// Record that a given fallback has told us about clock skew.
    pub(crate) fn note_skew(&mut self, id: &FallbackId, observation: SkewObservation) {
        if let Some(entry) = self.get_mut(id) {
            entry.clock_skew = Some(observation);
        }
    }

    /// Return an iterator over all the clock skew observations we've made for fallback directories
    pub(crate) fn skew_observations(&self) -> impl Iterator<Item = &SkewObservation> {
        self.fallbacks
            .iter()
            .filter_map(|fb| fb.clock_skew.as_ref())
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

    use super::*;
    use rand::Rng;
    use tor_basic_utils::test_rng::testing_rng;

    /// Construct a `FallbackDir` with random identity keys and addresses.
    ///
    /// Since there are 416 bits of random id here, the risk of collision is
    /// negligible.
    fn rand_fb<R: Rng>(rng: &mut R) -> FallbackDir {
        let ed: [u8; 32] = rng.gen();
        let rsa: [u8; 20] = rng.gen();
        let ip: u32 = rng.gen();
        let mut bld = FallbackDir::builder();
        bld.ed_identity(ed.into())
            .rsa_identity(rsa.into())
            .orports()
            .push(std::net::SocketAddrV4::new(ip.into(), 9090).into());
        bld.build().unwrap()
    }

    #[test]
    fn construct_fallback_set() {
        use rand::seq::SliceRandom;
        use std::cmp::Ordering as O;

        // fabricate some fallbacks.
        let mut rng = testing_rng();
        let fbs = vec![
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
        ];
        let fb_other = rand_fb(&mut rng);
        let id_other = FallbackId::from_relay_ids(&fb_other);

        // basic case: construct a set
        let list: FallbackList = fbs.clone().into();
        assert!(!list.is_empty());
        assert_eq!(list.len(), 4);
        let mut set: FallbackState = (&list).into();

        // inspect the generated set
        assert_eq!(set.fallbacks.len(), 4);
        assert_eq!(
            set.fallbacks[0].cmp_by_relay_ids(&set.fallbacks[1]),
            O::Less
        );
        assert_eq!(
            set.fallbacks[1].cmp_by_relay_ids(&set.fallbacks[2]),
            O::Less
        );
        assert_eq!(
            set.fallbacks[2].cmp_by_relay_ids(&set.fallbacks[3]),
            O::Less
        );

        // use the constructed set a little.
        for fb in fbs.iter() {
            let id = FallbackId::from_relay_ids(fb);
            assert_eq!(set.get_mut(&id).unwrap().cmp_by_relay_ids(&id), O::Equal);
        }
        assert!(set.get_mut(&id_other).is_none());

        // Now try an input set with duplicates.
        let mut redundant_fbs = fbs.clone();
        redundant_fbs.extend(fbs.clone());
        redundant_fbs.extend(fbs[0..2].iter().map(Clone::clone));
        redundant_fbs[..].shuffle(&mut testing_rng());
        let list2 = redundant_fbs.into();
        assert_ne!(&list, &list2);
        let set2: FallbackState = (&list2).into();

        // It should have the same elements, in the same order.
        assert_eq!(set.fallbacks.len(), set2.fallbacks.len());
        assert!(set
            .fallbacks
            .iter()
            .zip(set2.fallbacks.iter())
            .all(|(ent1, ent2)| ent1.same_relay_ids(ent2)));
    }

    #[test]
    fn set_choose() {
        dbg!("X");

        let mut rng = testing_rng();
        let fbs = vec![
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
        ];
        let list: FallbackList = fbs.into();
        let mut set: FallbackState = (&list).into();
        let filter = crate::GuardFilter::unfiltered();

        let mut counts = [0_usize; 4];
        let now = Instant::now();
        dbg!("A");
        fn lookup_idx(set: &FallbackState, id: &impl HasRelayIds) -> Option<usize> {
            set.fallbacks
                .binary_search_by(|ent| ent.fallback.cmp_by_relay_ids(id))
                .ok()
        }
        // Basic case: everybody is up.
        for _ in 0..100 {
            let fb = set.choose(&mut rng, now, &filter).unwrap();
            let idx = lookup_idx(&set, fb).unwrap();
            counts[idx] += 1;
        }
        dbg!("B");
        assert!(counts.iter().all(|v| *v > 0));

        // Mark somebody down and make sure they don't get chosen.
        let ids: Vec<_> = set
            .fallbacks
            .iter()
            .map(|ent| FallbackId::from_relay_ids(&ent.fallback))
            .collect();
        set.note_failure(&ids[2], now);
        counts = [0; 4];
        for _ in 0..100 {
            let fb = set.choose(&mut rng, now, &filter).unwrap();
            let idx = lookup_idx(&set, fb).unwrap();
            counts[idx] += 1;
        }
        assert_eq!(counts.iter().filter(|v| **v > 0).count(), 3);
        assert_eq!(counts[2], 0);

        // Mark everybody down; make sure we get the right error.
        for id in ids.iter() {
            set.note_failure(id, now);
        }
        assert!(matches!(
            set.choose(&mut rng, now, &filter),
            Err(PickGuardError::AllFallbacksDown { .. })
        ));

        // Construct an empty set; make sure we get the right error.
        let empty_set = FallbackState::from(&FallbackList::from(vec![]));
        assert!(matches!(
            empty_set.choose(&mut rng, now, &filter),
            Err(PickGuardError::NoCandidatesAvailable)
        ));

        // TODO: test restrictions and filters once they're implemented.
    }

    #[test]
    fn test_status() {
        let mut rng = testing_rng();
        let fbs = vec![
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
            rand_fb(&mut rng),
        ];
        let list: FallbackList = fbs.clone().into();
        let mut set: FallbackState = (&list).into();
        let ids: Vec<_> = set
            .fallbacks
            .iter()
            .map(|ent| FallbackId::from_relay_ids(&ent.fallback))
            .collect();

        let now = Instant::now();

        // There's no "next retry time" when everybody's up.
        assert!(set.next_retry().is_none());

        // Mark somebody down; try accessors.
        set.note_failure(&ids[3], now);
        assert!(set.fallbacks[3].status.next_retriable().unwrap() > now);
        assert!(!set.fallbacks[3].status.usable_at(now));
        assert_eq!(set.next_retry(), set.fallbacks[3].status.next_retriable());

        // Mark somebody else down; try accessors.
        set.note_failure(&ids[0], now);
        assert!(set.fallbacks[0].status.next_retriable().unwrap() > now);
        assert!(!set.fallbacks[0].status.usable_at(now));
        assert_eq!(
            set.next_retry().unwrap(),
            std::cmp::min(
                set.fallbacks[0].status.next_retriable().unwrap(),
                set.fallbacks[3].status.next_retriable().unwrap()
            )
        );

        // Mark somebody as running; try accessors.
        set.note_success(&ids[0]);
        assert!(set.fallbacks[0].status.next_retriable().is_none());
        assert!(set.fallbacks[0].status.usable_at(now));

        // Make a new set with slightly different members; make sure that we can copy stuff successfully.
        let mut fbs2: Vec<_> = fbs
            .into_iter()
            // (Remove the fallback with id==ids[2])
            .filter(|fb| FallbackId::from_relay_ids(fb) != ids[2])
            .collect();
        // add 2 new ones.
        let fbs_new = vec![rand_fb(&mut rng), rand_fb(&mut rng), rand_fb(&mut rng)];
        fbs2.extend(fbs_new.clone());

        let mut set2 = FallbackState::from(&FallbackList::from(fbs2.clone()));
        set2.take_status_from(set); // consumes set.
        assert_eq!(set2.fallbacks.len(), 6); // Started with 4, added 3, removed 1.

        // Make sure that the status entries  are correctly copied.
        assert!(set2.get_mut(&ids[0]).unwrap().status.usable_at(now));
        assert!(set2.get_mut(&ids[1]).unwrap().status.usable_at(now));
        assert!(set2.get_mut(&ids[2]).is_none());
        assert!(!set2.get_mut(&ids[3]).unwrap().status.usable_at(now));

        // Make sure that the new fbs are there.
        for new_fb in fbs_new {
            assert!(set2
                .get_mut(&FallbackId::from_relay_ids(&new_fb))
                .unwrap()
                .status
                .usable_at(now));
        }
    }
}
