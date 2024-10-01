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
        // only channels where `target`s relay ids are a superset of `entry`s relay ids
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
        // TODO: only channels which have the exact same address list as `target` (the two sets of
        // addresses must match exactly)
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
