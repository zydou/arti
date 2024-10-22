//! Define a type for a set of HasRelayIds objects that can be looked up by any
//! of their keys.

use tor_basic_utils::{n_key_list, n_key_set};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use crate::{HasRelayIds, RelayIdRef};

n_key_list! {
    /// A list of objects that can be accessed by relay identity.
    ///
    /// Multiple objects in the list can have a given relay identity.
    ///
    /// # Invariants
    ///
    /// Every object in the list **must** have at least one recognized relay identity; if it does
    /// not, it cannot be inserted.
    ///
    /// This list may panic or give incorrect results if the values can change their keys through
    /// interior mutability.
    #[derive(Clone, Debug)]
    pub struct[H:HasRelayIds] ListByRelayIds[H] for H
    {
        (Option) rsa: RsaIdentity { rsa_identity() },
        (Option) ed25519: Ed25519Identity { ed_identity() },
    }
}

n_key_set! {
    /// A set of objects that can be accessed by relay identity.
    ///
    /// No more than one object in the set can have any given relay identity.
    ///
    /// # Invariants
    ///
    /// Every object in the set MUST have at least one recognized relay
    /// identity; if it does not, it cannot be inserted.
    ///
    /// This set may panic or give incorrect results if the values can change their
    /// keys through interior mutability.
    ///
    #[derive(Clone, Debug)]
    pub struct[H:HasRelayIds] ByRelayIds[H] for H
    {
        (Option) rsa: RsaIdentity { rsa_identity() },
        (Option) ed25519: Ed25519Identity { ed_identity() },
    }
}

impl<H: HasRelayIds> ByRelayIds<H> {
    /// Return the value in this set (if any) that has the key `key`.
    pub fn by_id<'a, T>(&self, key: T) -> Option<&H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.by_rsa(rsa),
        }
    }

    /// Return the value in this set (if any) that has the key `key`.
    pub fn remove_by_id<'a, T>(&mut self, key: T) -> Option<H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.remove_by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.remove_by_rsa(rsa),
        }
    }

    /// Modify the value in this set (if any) that has the key `key`.
    ///
    /// Return values are as for [`modify_by_ed25519`](Self::modify_by_ed25519)
    pub fn modify_by_id<'a, T, F>(&mut self, key: T, func: F) -> Vec<H>
    where
        T: Into<RelayIdRef<'a>>,
        F: FnOnce(&mut H),
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.modify_by_ed25519(ed, func),
            RelayIdRef::Rsa(rsa) => self.modify_by_rsa(rsa, func),
        }
    }

    /// Return the value in this set (if any) that has _all_ the relay IDs
    /// that `key` does.
    ///
    /// Return `None` if `key` has no relay IDs.
    pub fn by_all_ids<T>(&self, key: &T) -> Option<&H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        self.by_id(any_id)
            .filter(|val| val.has_all_relay_ids_from(key))
    }

    /// Modify the value in this set (if any) that has _all_ the relay IDs
    /// that `key` does.
    ///
    /// Return values are as for [`modify_by_ed25519`](Self::modify_by_ed25519)
    pub fn modify_by_all_ids<T, F>(&mut self, key: &T, func: F) -> Vec<H>
    where
        T: HasRelayIds,
        F: FnOnce(&mut H),
    {
        let any_id = match key.identities().next() {
            Some(id) => id,
            None => return Vec::new(),
        };
        self.modify_by_id(any_id, |val| {
            if val.has_all_relay_ids_from(key) {
                func(val);
            }
        })
    }

    /// Remove the single value in this set (if any) that has _exactly the same_
    /// relay IDs that `key` does
    pub fn remove_exact<T>(&mut self, key: &T) -> Option<H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        if self
            .by_id(any_id)
            .filter(|ent| ent.same_relay_ids(key))
            .is_some()
        {
            self.remove_by_id(any_id)
        } else {
            None
        }
    }

    /// Remove the single value in this set (if any) that has all the same
    /// relay IDs that `key` does. If `key` does not have any relay IDs, no
    /// value is returned.
    pub fn remove_by_all_ids<T>(&mut self, key: &T) -> Option<H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        if self
            .by_id(any_id)
            .filter(|ent| ent.has_all_relay_ids_from(key))
            .is_some()
        {
            self.remove_by_id(any_id)
        } else {
            None
        }
    }

    /// Return a reference to every element in this set that shares _any_ ID
    /// with `key`.
    ///
    /// No element is returned more than once.
    pub fn all_overlapping<T>(&self, key: &T) -> Vec<&H>
    where
        T: HasRelayIds,
    {
        use by_address::ByAddress;
        use std::collections::HashSet;

        let mut items: HashSet<ByAddress<&H>> = HashSet::new();

        for ident in key.identities() {
            if let Some(found) = self.by_id(ident) {
                items.insert(ByAddress(found));
            }
        }

        items.into_iter().map(|by_addr| by_addr.0).collect()
    }
}

impl<H: HasRelayIds> ListByRelayIds<H> {
    /// Return an iterator of the values in this list that have the key `key`.
    pub fn by_id<'a, T>(&self, key: T) -> ListByRelayIdsIter<H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.by_rsa(rsa),
        }
    }

    /// Return the values in this list that have *all* the relay IDs that `key` does.
    ///
    /// Returns an empty iterator if `key` has no relay IDs.
    pub fn by_all_ids<'a>(&'a self, key: &'a impl HasRelayIds) -> impl Iterator<Item = &'a H> + 'a {
        // TODO: see comments on `empty_iterator`
        #[allow(deprecated)]
        key.identities()
            .next()
            .map_or_else(|| self.empty_iterator(), |id| self.by_id(id))
            .filter(|val| val.has_all_relay_ids_from(key))
    }

    /// Return a reference to every element in this set that shares *any* ID with `key`.
    ///
    /// No element is returned more than once. Equality is compared using
    /// [`ByAddress`](by_address::ByAddress).
    pub fn all_overlapping<T>(&self, key: &T) -> Vec<&H>
    where
        T: HasRelayIds,
    {
        use by_address::ByAddress;
        use std::collections::HashSet;

        let mut items: HashSet<ByAddress<&H>> = HashSet::new();

        for ident in key.identities() {
            for found in self.by_id(ident) {
                items.insert(ByAddress(found));
            }
        }

        items.into_iter().map(|by_addr| by_addr.0).collect()
    }

    /// Return a reference to every element in this list whose relay IDs are a subset of the relay
    /// IDs that `key` has.
    ///
    /// No element is returned more than once. Equality is compared using
    /// [`ByAddress`](by_address::ByAddress).
    pub fn all_subset<T>(&self, key: &T) -> Vec<&H>
    where
        T: HasRelayIds,
    {
        use by_address::ByAddress;
        use std::collections::HashSet;

        let mut items: HashSet<ByAddress<&H>> = HashSet::new();

        for ident in key.identities() {
            for found in self.by_id(ident) {
                // if 'key's relay ids are a superset of 'found's relay ids
                if key.has_all_relay_ids_from(found) {
                    items.insert(ByAddress(found));
                }
            }
        }

        items.into_iter().map(|by_addr| by_addr.0).collect()
    }

    /// Return the values in this list that have the key `key` and where `filter` returns `true`.
    pub fn remove_by_id<'a, T>(&mut self, key: T, filter: impl FnMut(&H) -> bool) -> Vec<H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.remove_by_ed25519(ed, filter),
            RelayIdRef::Rsa(rsa) => self.remove_by_rsa(rsa, filter),
        }
    }

    /// Remove and return the values in this list that have *exactly the same* relay IDs that `key`
    /// does.
    pub fn remove_exact<T>(&mut self, key: &T) -> Vec<H>
    where
        T: HasRelayIds,
    {
        let Some(id) = key.identities().next() else {
            return Vec::new();
        };

        self.remove_by_id(id, |val| val.same_relay_ids(key))
    }

    /// Remove and return the values in this list that have all the same relay IDs that `key` does.
    ///
    /// If `key` has no relay IDs, then no values are removed.
    pub fn remove_by_all_ids<T>(&mut self, key: &T) -> Vec<H>
    where
        T: HasRelayIds,
    {
        let Some(id) = key.identities().next() else {
            return Vec::new();
        };

        self.remove_by_id(id, |val| val.has_all_relay_ids_from(key))
    }
}

pub use tor_basic_utils::n_key_list::Error as ListByRelayIdsError;
pub use tor_basic_utils::n_key_set::Error as ByRelayIdsError;

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
    use crate::{RelayIds, RelayIdsBuilder};

    fn sort<T: std::cmp::Ord>(i: impl Iterator<Item = T>) -> Vec<T> {
        let mut v: Vec<_> = i.collect();
        v.sort();
        v
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn lookup() {
        let rsa1: RsaIdentity = (*b"12345678901234567890").into();
        let rsa2: RsaIdentity = (*b"abcefghijklmnopqrstu").into();
        let rsa3: RsaIdentity = (*b"abcefghijklmnopQRSTU").into();
        let ed1: Ed25519Identity = (*b"12345678901234567890123456789012").into();
        let ed2: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyzABCDEFG").into();
        let ed3: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyz1234567").into();

        let keys1 = RelayIdsBuilder::default()
            .rsa_identity(rsa1)
            .ed_identity(ed1)
            .build()
            .unwrap();

        let keys2 = RelayIdsBuilder::default()
            .rsa_identity(rsa2)
            .ed_identity(ed2)
            .build()
            .unwrap();

        // `ByRelayIds` and `ListByRelayIds` work similarly in the case where we only add a single
        // value per key, so we can test them both here with the same test cases.

        let mut set = ByRelayIds::new();
        set.insert(keys1.clone());
        set.insert(keys2.clone());

        let mut list = ListByRelayIds::new();
        list.insert(keys1.clone());
        list.insert(keys2.clone());

        // Try by_id
        assert_eq!(set.by_id(&rsa1), Some(&keys1));
        assert_eq!(set.by_id(&ed1), Some(&keys1));
        assert_eq!(set.by_id(&rsa2), Some(&keys2));
        assert_eq!(set.by_id(&ed2), Some(&keys2));
        assert_eq!(set.by_id(&rsa3), None);
        assert_eq!(set.by_id(&ed3), None);
        assert_eq!(sort(list.by_id(&rsa1)), [&keys1]);
        assert_eq!(sort(list.by_id(&ed1)), [&keys1]);
        assert_eq!(sort(list.by_id(&rsa2)), [&keys2]);
        assert_eq!(sort(list.by_id(&ed2)), [&keys2]);
        assert_eq!(list.by_id(&rsa3).len(), 0);
        assert_eq!(list.by_id(&ed3).len(), 0);

        // Try exact lookup
        assert_eq!(set.by_all_ids(&keys1), Some(&keys1));
        assert_eq!(set.by_all_ids(&keys2), Some(&keys2));
        assert_eq!(set.by_all_ids(&RelayIds::empty()), None);
        assert_eq!(sort(list.by_all_ids(&keys1)), [&keys1]);
        assert_eq!(sort(list.by_all_ids(&keys2)), [&keys2]);
        assert!(sort(list.by_all_ids(&RelayIds::empty())).is_empty());
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .build()
                .unwrap();
            assert_eq!(set.by_all_ids(&search), Some(&keys1));
            assert_eq!(sort(list.by_all_ids(&search)), [&keys1]);
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .ed_identity(ed2)
                .build()
                .unwrap();
            assert_eq!(set.by_all_ids(&search), None);
            assert!(sort(list.by_all_ids(&search)).is_empty());
        }

        // Try looking for overlap
        assert_eq!(set.all_overlapping(&keys1), vec![&keys1]);
        assert_eq!(set.all_overlapping(&keys2), vec![&keys2]);
        assert_eq!(list.all_overlapping(&keys1), vec![&keys1]);
        assert_eq!(list.all_overlapping(&keys2), vec![&keys2]);
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .ed_identity(ed2)
                .build()
                .unwrap();
            let answer = set.all_overlapping(&search);
            assert_eq!(answer.len(), 2);
            assert!(answer.contains(&&keys1));
            assert!(answer.contains(&&keys2));
            let answer = list.all_overlapping(&search);
            assert_eq!(answer.len(), 2);
            assert!(answer.contains(&&keys1));
            assert!(answer.contains(&&keys2));
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa2)
                .build()
                .unwrap();
            assert_eq!(set.all_overlapping(&search), vec![&keys2]);
            assert_eq!(list.all_overlapping(&search), vec![&keys2]);
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa3)
                .build()
                .unwrap();
            assert!(set.all_overlapping(&search).is_empty());
            assert!(list.all_overlapping(&search).is_empty());
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn remove_exact() {
        let rsa1: RsaIdentity = (*b"12345678901234567890").into();
        let rsa2: RsaIdentity = (*b"abcefghijklmnopqrstu").into();
        let ed1: Ed25519Identity = (*b"12345678901234567890123456789012").into();
        let ed2: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyzABCDEFG").into();

        let keys1 = RelayIdsBuilder::default()
            .rsa_identity(rsa1)
            .ed_identity(ed1)
            .build()
            .unwrap();

        let keys2 = RelayIdsBuilder::default()
            .rsa_identity(rsa2)
            .ed_identity(ed2)
            .build()
            .unwrap();

        // `ByRelayIds` and `ListByRelayIds` work similarly in the case where we only add a single
        // value per key, so we can test them both here with the same test cases.

        let mut set = ByRelayIds::new();
        set.insert(keys1.clone());
        set.insert(keys2.clone());
        assert_eq!(set.len(), 2);

        let mut list = ListByRelayIds::new();
        list.insert(keys1.clone());
        list.insert(keys2.clone());
        assert_eq!(list.len(), 2);

        assert_eq!(set.remove_exact(&keys1), Some(keys1.clone()));
        assert_eq!(set.len(), 1);
        assert_eq!(list.remove_exact(&keys1), vec![keys1.clone()]);
        assert_eq!(list.len(), 1);

        {
            let search = RelayIdsBuilder::default().ed_identity(ed2).build().unwrap();

            // We're calling remove_exact, but we did not list _all_ the keys in keys2.
            assert_eq!(set.remove_exact(&search), None);
            assert_eq!(set.len(), 1);
            assert_eq!(list.remove_exact(&search), vec![]);
            assert_eq!(list.len(), 1);

            // If we were to use `remove_by_all_ids` with a search that didn't
            // match, it wouldn't work.
            let no_match = RelayIdsBuilder::default()
                .ed_identity(ed2)
                .rsa_identity(rsa1)
                .build()
                .unwrap();
            assert_eq!(set.remove_by_all_ids(&no_match), None);
            assert_eq!(set.len(), 1);
            assert_eq!(list.remove_by_all_ids(&no_match), vec![]);
            assert_eq!(list.len(), 1);

            // If we use `remove_by_all_ids` with the original search, though,
            // it will remove the element.
            assert_eq!(set.remove_by_all_ids(&search), Some(keys2.clone()));
            assert!(set.is_empty());
            assert_eq!(list.remove_by_all_ids(&search), vec![keys2.clone()]);
            assert!(list.is_empty());
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn all_subset() {
        let rsa1: RsaIdentity = (*b"12345678901234567890").into();
        let rsa2: RsaIdentity = (*b"abcefghijklmnopqrstu").into();
        let ed1: Ed25519Identity = (*b"12345678901234567890123456789012").into();

        // one rsa id and one ed id
        let keys1 = RelayIdsBuilder::default()
            .rsa_identity(rsa1)
            .ed_identity(ed1)
            .build()
            .unwrap();

        // one rsa id
        let keys2 = RelayIdsBuilder::default()
            .rsa_identity(rsa2)
            .build()
            .unwrap();

        let mut list = ListByRelayIds::new();
        list.insert(keys1.clone());
        list.insert(keys2.clone());

        assert_eq!(list.all_subset(&keys1), vec![&keys1]);
        assert_eq!(list.all_subset(&keys2), vec![&keys2]);

        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .build()
                .unwrap();
            assert!(list.all_subset(&search).is_empty());
        }

        {
            let search = RelayIdsBuilder::default().ed_identity(ed1).build().unwrap();
            assert!(list.all_subset(&search).is_empty());
        }

        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa2)
                .build()
                .unwrap();
            assert_eq!(list.all_subset(&search), vec![&keys2]);
        }

        {
            let search = RelayIdsBuilder::default()
                .ed_identity(ed1)
                .rsa_identity(rsa2)
                .build()
                .unwrap();
            assert_eq!(list.all_subset(&search), vec![&keys2]);
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn list_by_relay_ids() {
        #[derive(Clone, Debug)]
        struct ErsatzChannel<T> {
            val: T,
            ids: RelayIds,
        }

        impl<T> ErsatzChannel<T> {
            fn new(val: T, ids: RelayIds) -> Self {
                Self { val, ids }
            }
        }

        impl<T> HasRelayIds for ErsatzChannel<T> {
            fn identity(&self, key_type: crate::RelayIdType) -> Option<RelayIdRef<'_>> {
                self.ids.identity(key_type)
            }
        }

        // helper to build a `RelayIds` to make tests shorter
        fn ids(
            rsa: impl Into<Option<RsaIdentity>>,
            ed: impl Into<Option<Ed25519Identity>>,
        ) -> RelayIds {
            let mut ids = RelayIdsBuilder::default();
            if let Some(rsa) = rsa.into() {
                ids.rsa_identity(rsa);
            }
            if let Some(ed) = ed.into() {
                ids.ed_identity(ed);
            }
            ids.build().unwrap()
        }

        // ids for relay A
        let rsa_a: RsaIdentity = (*b"12345678901234567890").into();
        let ed_a: Ed25519Identity = (*b"12345678901234567890123456789012").into();

        // ids for relay B
        let ed_b: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyzABCDEFG").into();
        let rsa_b: RsaIdentity = (*b"abcefghijklmnopqrstu").into();

        // channel to A with all ids
        let channel_a_all = ErsatzChannel::new("channel-a-all", ids(rsa_a, ed_a));

        // channel to A with only the rsa id
        let channel_a_rsa_only_1 = ErsatzChannel::new("channel-a-rsa-only-1", ids(rsa_a, None));

        // channel to A with only the rsa id; this could for example represent a channel with the
        // same relay id as above but at a different ip address
        let channel_a_rsa_only_2 = ErsatzChannel::new("channel-a-rsa-only-2", ids(rsa_a, None));

        // channel to A with only the ed id
        let channel_a_ed_only = ErsatzChannel::new("channel-a-ed-only", ids(None, ed_a));

        // channel to B with all ids
        let channel_b_all = ErsatzChannel::new("channel-b-all", ids(rsa_b, ed_b));

        // an "invalid" channel with A's rsa id and B's ed id; this could for example represent an
        // in-progress pending channel that hasn't been verified yet
        let channel_invalid = ErsatzChannel::new("channel-invalid", ids(rsa_a, ed_b));

        let mut list = ListByRelayIds::new();
        list.insert(channel_a_all.clone());
        list.insert(channel_a_rsa_only_1.clone());
        list.insert(channel_a_rsa_only_2.clone());
        list.insert(channel_a_ed_only.clone());
        list.insert(channel_b_all.clone());
        list.insert(channel_invalid.clone());

        // look up by A's rsa id
        assert_eq!(
            sort(list.by_id(&rsa_a).map(|x| x.val)),
            [
                "channel-a-all",
                "channel-a-rsa-only-1",
                "channel-a-rsa-only-2",
                "channel-invalid",
            ],
        );

        // look up by A's ed id
        assert_eq!(
            sort(list.by_id(&ed_a).map(|x| x.val)),
            ["channel-a-all", "channel-a-ed-only"],
        );

        // look up by B's rsa id
        assert_eq!(sort(list.by_id(&rsa_b).map(|x| x.val)), ["channel-b-all"]);

        // look up by B's ed id
        assert_eq!(
            sort(list.by_id(&ed_b).map(|x| x.val)),
            ["channel-b-all", "channel-invalid"],
        );

        // look up by both A's rsa id and ed id
        assert_eq!(
            sort(list.by_all_ids(&ids(rsa_a, ed_a)).map(|x| x.val)),
            ["channel-a-all"],
        );

        // look up by both B's rsa id and ed id
        assert_eq!(
            sort(list.by_all_ids(&ids(rsa_b, ed_b)).map(|x| x.val)),
            ["channel-b-all"],
        );

        // look up by either A's rsa id or ed id
        assert_eq!(
            sort(
                list.all_overlapping(&ids(rsa_a, ed_a))
                    .into_iter()
                    .map(|x| x.val)
            ),
            [
                "channel-a-all",
                "channel-a-ed-only",
                "channel-a-rsa-only-1",
                "channel-a-rsa-only-2",
                "channel-invalid",
            ],
        );

        // look up where channel's ids are a subset of A's ids
        assert_eq!(
            sort(
                list.all_subset(&ids(rsa_a, ed_a))
                    .into_iter()
                    .map(|x| x.val)
            ),
            [
                "channel-a-all",
                "channel-a-ed-only",
                "channel-a-rsa-only-1",
                "channel-a-rsa-only-2",
            ],
        );

        // some sanity checks
        assert_eq!(list.by_all_ids(&ids(None, None)).count(), 0);
        assert!(list.all_overlapping(&ids(None, None)).is_empty());
        assert!(list.all_subset(&ids(None, None)).is_empty());
        assert_eq!(
            sort(
                list.all_overlapping(&ids(rsa_a, None))
                    .into_iter()
                    .map(|x| x.val)
            ),
            sort(list.by_id(&rsa_a).map(|x| x.val)),
        );
        assert_eq!(
            sort(
                list.all_overlapping(&ids(None, ed_b))
                    .into_iter()
                    .map(|x| x.val)
            ),
            sort(list.by_id(&ed_b).map(|x| x.val)),
        );
        assert_eq!(
            sort(list.by_id(&rsa_a).map(|x| x.val)),
            sort(list.by_rsa(&rsa_a).map(|x| x.val)),
        );
        assert_eq!(
            sort(list.by_id(&ed_a).map(|x| x.val)),
            sort(list.by_ed25519(&ed_a).map(|x| x.val)),
        );

        // remove channels with exactly A's rsa id and ed id
        {
            let mut list = list.clone();
            assert_eq!(
                sort(
                    list.remove_exact(&ids(rsa_a, ed_a))
                        .into_iter()
                        .map(|x| x.val)
                ),
                ["channel-a-all"],
            );
            assert_eq!(list.by_all_ids(&ids(rsa_a, ed_a)).count(), 0);
        }

        // remove channels with exactly A's rsa id and no ed id
        {
            let mut list = list.clone();
            assert_eq!(
                sort(
                    list.remove_exact(&ids(rsa_a, None))
                        .into_iter()
                        .map(|x| x.val)
                ),
                ["channel-a-rsa-only-1", "channel-a-rsa-only-2"],
            );
            assert_eq!(
                sort(list.by_all_ids(&ids(rsa_a, None)).map(|x| x.val)),
                ["channel-a-all", "channel-invalid"],
            );
        }

        // remove channels with at least A's rsa id
        {
            let mut list = list.clone();
            assert_eq!(
                sort(
                    list.remove_by_all_ids(&ids(rsa_a, None))
                        .into_iter()
                        .map(|x| x.val)
                ),
                [
                    "channel-a-all",
                    "channel-a-rsa-only-1",
                    "channel-a-rsa-only-2",
                    "channel-invalid",
                ],
            );
            assert_eq!(list.by_all_ids(&ids(rsa_a, None)).count(), 0);
        }
    }
}
