//! Logic for filtering and selecting channels in order to find suitable channels for a target.

use crate::mgr::state::{ChannelState, OpenEntry, PendingEntry};
use crate::mgr::AbstractChannel;
use tor_linkspec::{HasRelayIds, RelayIds};

/// Returns `true` if the open channel is allowed to be used for a new channel request to the
/// target.
pub(crate) fn open_channel_is_allowed<C: AbstractChannel>(
    chan: &OpenEntry<C>,
    target: &impl HasRelayIds,
) -> bool {
    Some(chan)
        // only usable channels
        .filter(|entry| entry.channel.is_usable())
        // only channels which have *all* the relay ids of `target`
        .filter(|entry| entry.channel.has_all_relay_ids_from(target))
        // TODO: only channels which are canonical or have the same address as `target`
        .filter(|_entry| true)
        .is_some()
}

/// Returns `true` if the pending channel could possibly be used for a new channel request to the
/// target. You still need to verify the final built channel with [`open_channel_is_allowed`] before
/// using it.
pub(crate) fn pending_channel_maybe_allowed(
    chan: &PendingEntry,
    target: &impl HasRelayIds,
) -> bool {
    /// An empty [`RelayIds`].
    const EMPTY_IDS: RelayIds = RelayIds::empty();

    // We want to avoid returning pending channels that were initially created from malicious
    // channel requests (for example from malicious relay-extend requests) that build channels which
    // will never complete successfully. Two cases where this can happen are:
    // 1. A malicious channel request asks us to build a channel to a target with a correct relay id
    //    and address, but also an additional incorrect relay id. Later when the target sends its
    //    CERTS cell, all of the relay ids won't match and the channel will fail to build. We don't
    //    want to assign non-malicious channel requests to this pending channel that will eventually
    //    fail to build.
    // 2. A malicious channel request asks us to build a channel to a target with an incorrect
    //    address. This pending channel may stall. We don't want to assign non-malicious channel
    //    requests to this pending channel that will stall for potentially a long time.
    Some(chan)
        // Only channels where `target`s relay ids are a superset of `entry`s relay ids.
        // - Hopefully the built channel will gain the additional ids that are requested by
        //   `target`. This should happen in most cases where none of the channels are made
        //   maliciously, since the `target` should return all of its relay ids in its CERTS cell.
        // - (Addressing 1. above) By only returning pending channels that have a subset of
        //   `target`s relay ids, we ensure that the returned pending channel does not have
        //   additional incorrect relay ids that will intentionally cause the pending channel to
        //   fail.
        // - If the built channel does not gain the remaining ids required by `target, then we won't
        //   be able to use this channel for the channel request to `target`. But we won't be able
        //   to create a new channel either, since we know that that a new channel also won't have
        //   all of the relay ids. So this channel request was doomed from the start.
        // - If the built channel gains additional ids that `target` doesn't have, that's fine and
        //   we can still use the channel for `target`.
        .filter(|entry| target.has_all_relay_ids_from(&entry.ids))
        // TODO: Only channels which have the exact same address list as `target` (the two sets of
        // addresses must match exactly).
        // - (Addressing 2. above) By only returning pending channels that have exactly the same
        //   addresses, we ensure that the returned pending channel does not have any incorrect
        //   addresses that will cause the pending channel to stall.
        // - If the pending channel had additional addresses compared to `target`, the channel could
        //   get built using an address that is not valid for `target` and we wouldn't be able to
        //   use the built channel.
        // - If the pending channel had fewer addresses compared to `target`, the channel would have
        //   a lower possibility of building successfully compared to a newly created channel to
        //   `target`, so this would not be a good channel for us to return.
        .filter(|_entry| true)
        // Don't allow a pending channel that has no relay ids. I don't have a good reason for
        // excluding this, other than "it seems weird".
        .filter(|entry| entry.ids != EMPTY_IDS)
        .is_some()
}

/// Returns the best channel for `target`.
// TODO: remove me when the below TODOs are implemented
#[allow(clippy::only_used_in_recursion)]
pub(crate) fn choose_best_channel<'a, C: AbstractChannel>(
    channels: impl IntoIterator<Item = &'a ChannelState<C>>,
    target: &impl HasRelayIds,
) -> Option<&'a ChannelState<C>> {
    use std::cmp::Ordering;
    use ChannelState::*;

    let channels = channels.into_iter();

    /// Compare two channels to determine the better channel for `target`.
    fn choose_channel<C: AbstractChannel>(
        a: &&ChannelState<C>,
        b: &&ChannelState<C>,
        target: &impl HasRelayIds,
    ) -> Choice {
        // TODO: follow `channel_is_better` in C tor
        match (a, b) {
            // if the open channel is not usable, prefer the pending channel
            (Open(a), Building(_b)) if !a.channel.is_usable() => Choice::Second,
            // otherwise prefer the open channel
            (Open(_a), Building(_b)) => Choice::First,

            // the logic above, but reversed
            (Building(_), Open(_)) => choose_channel(b, a, target).reverse(),

            // not much info to help choose when both channels are pending, but this should be rare
            (Building(_a), Building(_b)) => Choice::Either,

            // both channels are open
            (Open(a), Open(b)) => {
                let a_is_usable = a.channel.is_usable();
                let b_is_usable = b.channel.is_usable();

                // if neither open channel is usable, don't take preference
                if !a_is_usable && !b_is_usable {
                    return Choice::Either;
                }

                // prefer a channel that is usable
                if !a_is_usable {
                    return Choice::Second;
                }
                if !b_is_usable {
                    return Choice::First;
                }

                // TODO: prefer canonical channels

                // TODO: prefer a channel where the address matches the target

                // TODO: prefer the one we think the peer will think is canonical

                // TODO: prefer older channels

                // TODO: use number of circuits as tie-breaker?

                Choice::Either
            }
        }
    }

    // preferred channels will be ordered higher, and we choose the max
    channels.max_by(|a, b| match choose_channel(a, b, target) {
        Choice::First => Ordering::Greater,
        Choice::Second => Ordering::Less,
        Choice::Either => Ordering::Equal,
    })
}

/// Similar to [`Ordering`](std::cmp::Ordering), but is easier to reason about when comparing two
/// objects that don't have a numeric sense of ordering (ex: returning `Greater` is confusing if the
/// ordering isn't numeric).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum Choice {
    /// Choose the first.
    First,
    /// Choose the second.
    Second,
    /// Choose either.
    Either,
}

impl Choice {
    /// Reverses the `Choice`.
    ///
    /// - `First` becomes `Second`.
    /// - `Second` becomes `First`.
    /// - `Either` becomes `Either`.
    fn reverse(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
            Self::Either => Self::Either,
        }
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

    use std::sync::Arc;
    use std::time::Duration;

    use tor_linkspec::RelayIds;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_llcrypto::pk::rsa::RsaIdentity;
    use tor_proto::channel::ChannelPaddingInstructionsUpdates;

    #[derive(Debug)]
    struct FakeChannel {
        usable: bool,
        ids: RelayIds,
    }

    impl AbstractChannel for FakeChannel {
        fn is_usable(&self) -> bool {
            self.usable
        }
        fn duration_unused(&self) -> Option<Duration> {
            None
        }
        fn reparameterize(
            &self,
            _updates: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            Ok(())
        }
        fn engage_padding_activities(&self) {}
    }

    impl HasRelayIds for FakeChannel {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            self.ids.identity(key_type)
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBuildSpec {
        ids: RelayIds,
    }

    impl FakeBuildSpec {
        fn new(ids: RelayIds) -> Self {
            Self { ids }
        }
    }

    impl HasRelayIds for FakeBuildSpec {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            self.ids.identity(key_type)
        }
    }

    /// Assert that two `Option<&T>` point to the same data.
    macro_rules! assert_opt_ptr_eq {
        ($a:expr, $b:expr) => {
            assert_opt_ptr_eq!($a, $b,);
        };
        ($a:expr, $b:expr, $($x:tt)*) => {
            assert_eq!($a.map(std::ptr::from_ref), $b.map(std::ptr::from_ref), $($x)*);
        };
    }

    /// Calls `f` with every permutation of `list`. Don't use with large lists :)
    fn with_permutations<T>(list: &[T], mut f: impl FnMut(Vec<&T>)) {
        use itertools::Itertools;
        for new_list in list.iter().permutations(list.len()) {
            f(new_list);
        }
    }

    /// Helper to make a fake Ed identity from some bytes.
    fn ed(a: &[u8]) -> Ed25519Identity {
        let mut bytes = [0; 32];
        bytes[0..a.len()].copy_from_slice(a);
        bytes.into()
    }

    /// Helper to make a fake rsa identity from some bytes.
    fn rsa(a: &[u8]) -> RsaIdentity {
        let mut bytes = [0; 20];
        bytes[0..a.len()].copy_from_slice(a);
        bytes.into()
    }

    /// Helper to build a `RelayIds` to make tests shorter.
    fn ids(
        rsa: impl Into<Option<RsaIdentity>>,
        ed: impl Into<Option<Ed25519Identity>>,
    ) -> RelayIds {
        let mut ids = tor_linkspec::RelayIdsBuilder::default();
        if let Some(rsa) = rsa.into() {
            ids.rsa_identity(rsa);
        }
        if let Some(ed) = ed.into() {
            ids.ed_identity(ed);
        }
        ids.build().unwrap()
    }

    /// Create an open channel entry.
    fn open_channel<C>(chan: C) -> OpenEntry<C> {
        OpenEntry {
            channel: Arc::new(chan),
            max_unused_duration: Duration::from_secs(0),
        }
    }

    /// Create a pending channel entry with the given IDs.
    fn pending_channel(ids: RelayIds) -> PendingEntry {
        use crate::mgr::state::UniqPendingChanId;
        use futures::FutureExt;
        use oneshot_fused_workaround as oneshot;

        PendingEntry {
            ids,
            pending: oneshot::channel().1.shared(),
            unique_id: UniqPendingChanId::new(),
        }
    }

    #[test]
    fn best_channel_usable_unusable() {
        // two channels where only the first is usable
        let channels = [
            ChannelState::Open(open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"A")),
            })),
            ChannelState::Open(open_channel(FakeChannel {
                usable: false,
                ids: ids(None, ed(b"A")),
            })),
        ];

        // should return the usable channel
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));
        with_permutations(&channels, |x| {
            assert_opt_ptr_eq!(choose_best_channel(x, &target), Some(&channels[0]));
        });
    }

    #[test]
    fn best_channel_open_pending() {
        // a usable open channel and a pending channel
        let channels = [
            ChannelState::Open(open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"A")),
            })),
            ChannelState::Building(pending_channel(ids(None, ed(b"A")))),
        ];

        // should return the open channel
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));
        with_permutations(&channels, |x| {
            assert_opt_ptr_eq!(choose_best_channel(x, &target), Some(&channels[0]));
        });

        // an unusable open channel and a pending channel
        let channels = [
            ChannelState::Open(open_channel(FakeChannel {
                usable: false,
                ids: ids(None, ed(b"A")),
            })),
            ChannelState::Building(pending_channel(ids(None, ed(b"A")))),
        ];

        // should return the pending channel
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));
        with_permutations(&channels, |x| {
            assert_opt_ptr_eq!(choose_best_channel(x, &target), Some(&channels[1]));
        });
    }

    #[test]
    fn best_channel_many() {
        // some misc channels (as we make `choose_best_channel` more complex, hopefull we can add
        // more channels here)
        let channels = [
            ChannelState::Open(open_channel(FakeChannel {
                usable: false,
                ids: ids(None, ed(b"A")),
            })),
            ChannelState::Open(open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"A")),
            })),
            ChannelState::Building(pending_channel(ids(None, ed(b"A")))),
            ChannelState::Building(pending_channel(ids(None, None))),
        ];

        // should return the open+usable channel
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));
        with_permutations(&channels, |x| {
            assert_opt_ptr_eq!(choose_best_channel(x, &target), Some(&channels[1]));
        });
    }

    #[test]
    fn test_open_channel_is_allowed() {
        // target with an ed relay id
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));

        // not allowed: unusable channel
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: false,
                ids: ids(None, ed(b"A")),
            }),
            &target,
        ));

        // allowed: usable channel with correct relay id
        assert!(open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"A")),
            }),
            &target,
        ));

        // not allowed: usable channel with incorrect relay id
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"B")),
            }),
            &target,
        ));

        // not allowed: usable channel with no relay ids
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(None, None),
            }),
            &target,
        ));

        // allowed: usable channel with additional relay id
        assert!(open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"X"), ed(b"A")),
            }),
            &target,
        ));

        // not allowed: usable channel with missing ed relay id
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"X"), None),
            }),
            &target,
        ));

        // target with no relay id
        let target = FakeBuildSpec::new(ids(None, None));

        // not allowed: unusable channel
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: false,
                ids: ids(None, None),
            }),
            &target,
        ));

        // allowed: usable channel with no relay ids
        assert!(open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(None, None),
            }),
            &target,
        ));

        // target with multiple relay ids
        let target = FakeBuildSpec::new(ids(rsa(b"X"), ed(b"A")));

        // not allowed: unusable channel
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: false,
                ids: ids(rsa(b"X"), ed(b"A")),
            }),
            &target,
        ));

        // allowed: usable channel with correct relay ids
        assert!(open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"X"), ed(b"A")),
            }),
            &target,
        ));

        // not allowed: usable channel with partial relay ids
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(None, ed(b"A")),
            }),
            &target,
        ));
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"X"), None),
            }),
            &target,
        ));

        // not allowed: usable channel with one incorrect relay id
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"X"), ed(b"B")),
            }),
            &target,
        ));
        assert!(!open_channel_is_allowed(
            &open_channel(FakeChannel {
                usable: true,
                ids: ids(rsa(b"Y"), ed(b"A")),
            }),
            &target,
        ));
    }

    #[test]
    fn test_pending_channel_maybe_allowed() {
        // target with an ed relay id
        let target = FakeBuildSpec::new(ids(None, ed(b"A")));

        // allowed: channel with same relay id
        assert!(pending_channel_maybe_allowed(
            &pending_channel(ids(None, ed(b"A"))),
            &target,
        ));

        // not allowed: channel with additional relay id
        assert!(!pending_channel_maybe_allowed(
            &pending_channel(ids(rsa(b"X"), ed(b"A"))),
            &target,
        ));

        // target with multiple relay ids
        let target = FakeBuildSpec::new(ids(rsa(b"X"), ed(b"A")));

        // allowed: channel with same relay ids
        assert!(pending_channel_maybe_allowed(
            &pending_channel(ids(rsa(b"X"), ed(b"A"))),
            &target,
        ));

        // allowed: channel with fewer relay ids
        assert!(pending_channel_maybe_allowed(
            &pending_channel(ids(None, ed(b"A"))),
            &target,
        ));
        assert!(pending_channel_maybe_allowed(
            &pending_channel(ids(rsa(b"X"), None)),
            &target,
        ));

        // not allowed: channel with no relay ids
        assert!(!pending_channel_maybe_allowed(
            &pending_channel(ids(None, None)),
            &target,
        ));

        // target with no relay ids
        let target = FakeBuildSpec::new(ids(None, None));

        // not allowed: channel with a relay id
        assert!(!pending_channel_maybe_allowed(
            &pending_channel(ids(None, ed(b"A"))),
            &target,
        ));

        // not allowed: channel with no relay ids
        assert!(!pending_channel_maybe_allowed(
            &pending_channel(ids(None, None)),
            &target,
        ));
    }
}
