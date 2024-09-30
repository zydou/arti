//! Abstract implementation of a channel manager

use crate::mgr::state::{OpenEntry, PendingEntry};
use crate::{ChanProvenance, ChannelConfig, ChannelUsage, Dormancy, Error, Result};

use crate::factory::BootstrapReporter;
use async_trait::async_trait;
use futures::future::{FutureExt, Shared};
use oneshot_fused_workaround as oneshot;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use tor_basic_utils::RngExt as _;
use tor_error::internal;
use tor_linkspec::{HasRelayIds, RelayIds};
use tor_netdir::params::NetParameters;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;

mod state;

/// Trait to describe as much of a
/// [`Channel`](tor_proto::channel::Channel) as `AbstractChanMgr`
/// needs to use.
pub(crate) trait AbstractChannel: HasRelayIds {
    /// Return true if this channel is usable.
    ///
    /// A channel might be unusable because it is closed, because it has
    /// hit a bug, or for some other reason.  We don't return unusable
    /// channels back to the user.
    fn is_usable(&self) -> bool;
    /// Return the amount of time a channel has not been in use.
    /// Return None if the channel is currently in use.
    fn duration_unused(&self) -> Option<Duration>;

    /// Reparameterize this channel according to the provided `ChannelPaddingInstructionsUpdates`
    ///
    /// The changed parameters may not be implemented "immediately",
    /// but this will be done "reasonably soon".
    fn reparameterize(
        &self,
        updates: Arc<ChannelPaddingInstructionsUpdates>,
    ) -> tor_proto::Result<()>;

    /// Specify that this channel should do activities related to channel padding
    ///
    /// See [`Channel::engage_padding_activities`]
    ///
    /// [`Channel::engage_padding_activities`]: tor_proto::channel::Channel::engage_padding_activities
    fn engage_padding_activities(&self);
}

/// Trait to describe how channels-like objects are created.
///
/// This differs from [`ChannelFactory`](crate::factory::ChannelFactory) in that
/// it's a purely crate-internal type that we use to decouple the
/// AbstractChanMgr code from actual "what is a channel" concerns.
#[async_trait]
pub(crate) trait AbstractChannelFactory {
    /// The type of channel that this factory can build.
    type Channel: AbstractChannel;
    /// Type that explains how to build an outgoing channel.
    type BuildSpec: HasRelayIds;
    /// The type of byte stream that's required to build channels for incoming connections.
    type Stream;

    /// Construct a new channel to the destination described at `target`.
    ///
    /// This function must take care of all timeouts, error detection,
    /// and so on.
    ///
    /// It should not retry; that is handled at a higher level.
    async fn build_channel(
        &self,
        target: &Self::BuildSpec,
        reporter: BootstrapReporter,
    ) -> Result<Arc<Self::Channel>>;

    /// Construct a new channel for an incoming connection.
    #[cfg(feature = "relay")]
    async fn build_channel_using_incoming(
        &self,
        peer: std::net::SocketAddr,
        stream: Self::Stream,
    ) -> Result<Arc<Self::Channel>>;
}

/// A type- and network-agnostic implementation for [`ChanMgr`](crate::ChanMgr).
///
/// This type does the work of keeping track of open channels and pending
/// channel requests, launching requests as needed, waiting for pending
/// requests, and so forth.
///
/// The actual job of launching connections is deferred to an
/// `AbstractChannelFactory` type.
pub(crate) struct AbstractChanMgr<CF: AbstractChannelFactory> {
    /// All internal state held by this channel manager.
    ///
    /// The most important part is the map from relay identity to channel, or
    /// to pending channel status.
    pub(crate) channels: state::MgrState<CF>,

    /// A bootstrap reporter to give out when building channels.
    pub(crate) reporter: BootstrapReporter,
}

/// Type alias for a future that we wait on to see when a pending
/// channel is done or failed.
type Pending = Shared<oneshot::Receiver<Result<()>>>;

/// Type alias for the sender we notify when we complete a channel (or fail to
/// complete it).
type Sending = oneshot::Sender<Result<()>>;

impl<CF: AbstractChannelFactory + Clone> AbstractChanMgr<CF> {
    /// Make a new empty channel manager.
    pub(crate) fn new(
        connector: CF,
        config: &ChannelConfig,
        dormancy: Dormancy,
        netparams: &NetParameters,
        reporter: BootstrapReporter,
    ) -> Self {
        AbstractChanMgr {
            channels: state::MgrState::new(connector, config.clone(), dormancy, netparams),
            reporter,
        }
    }

    /// Run a function to modify the channel builder in this object.
    #[allow(dead_code)]
    pub(crate) fn with_mut_builder<F>(&self, func: F)
    where
        F: FnOnce(&mut CF),
    {
        self.channels.with_mut_builder(func);
    }

    /// Remove every unusable entry from this channel manager.
    #[cfg(test)]
    pub(crate) fn remove_unusable_entries(&self) -> Result<()> {
        self.channels.remove_unusable()
    }

    /// Helper: return the objects used to inform pending tasks
    /// about a newly open or failed channel.
    fn setup_launch<C>(
        &self,
        ids: RelayIds,
    ) -> (state::ChannelState<C>, Sending, state::UniqPendingChanId) {
        let (snd, rcv) = oneshot::channel();
        let pending = rcv.shared();
        let unique_id = state::UniqPendingChanId::new();
        (
            state::ChannelState::Building(state::PendingEntry {
                ids,
                pending,
                unique_id,
            }),
            snd,
            unique_id,
        )
    }

    /// Build a channel for an incoming stream. See
    /// [`ChanMgr::handle_incoming`](crate::ChanMgr::handle_incoming).
    #[cfg(feature = "relay")]
    pub(crate) async fn handle_incoming(
        &self,
        src: std::net::SocketAddr,
        stream: CF::Stream,
    ) -> Result<Arc<CF::Channel>> {
        let chan_builder = self.channels.builder();
        let _outcome = chan_builder
            .build_channel_using_incoming(src, stream)
            .await?;

        // TODO RELAY: we need to do something with the channel here now that we've created it
        todo!();
    }

    /// Get a channel corresponding to the identities of `target`.
    ///
    /// If a usable channel exists with that identity, return it.
    ///
    /// If no such channel exists already, and none is in progress,
    /// launch a new request using `target`.
    ///
    /// If no such channel exists already, but we have one that's in
    /// progress, wait for it to succeed or fail.
    pub(crate) async fn get_or_launch(
        &self,
        target: CF::BuildSpec,
        usage: ChannelUsage,
    ) -> Result<(Arc<CF::Channel>, ChanProvenance)> {
        use ChannelUsage as CU;

        let chan = self.get_or_launch_internal(target).await?;

        match usage {
            CU::Dir | CU::UselessCircuit => {}
            CU::UserTraffic => chan.0.engage_padding_activities(),
        }

        Ok(chan)
    }

    /// Get a channel whose identity is `ident` - internal implementation
    async fn get_or_launch_internal(
        &self,
        target: CF::BuildSpec,
    ) -> Result<(Arc<CF::Channel>, ChanProvenance)> {
        /// How many times do we try?
        const N_ATTEMPTS: usize = 2;
        let mut attempts_so_far = 0;
        let mut final_attempt = false;
        let mut provenance = ChanProvenance::Preexisting;

        // TODO(nickm): It would be neat to use tor_retry instead.
        let mut last_err = None;

        while attempts_so_far < N_ATTEMPTS || final_attempt {
            attempts_so_far += 1;

            // For each attempt, we _first_ look at the state of the channel map
            // to decide on an `Action`, and _then_ we execute that action.

            // First, see what state we're in, and what we should do about it.
            let action = self.choose_action(&target, final_attempt)?;

            // We are done deciding on our Action! It's time act based on the
            // Action that we chose.
            match action {
                // If this happens, we were trying to make one final check of our state, but
                // we would have had to make additional attempts.
                None => {
                    if !final_attempt {
                        return Err(Error::Internal(internal!(
                            "No action returned while not on final attempt"
                        )));
                    }
                    break;
                }
                // Easy case: we have an error or a channel to return.
                Some(Action::Return(v)) => {
                    return v.map(|chan| (chan, provenance));
                }
                // There's an in-progress channel.  Wait for it.
                Some(Action::Wait(pend)) => {
                    match pend.await {
                        Ok(Ok(())) => {
                            // We were waiting for a channel, and it succeeded, or it
                            // got cancelled.  But it might have gotten more
                            // identities while negotiating than it had when it was
                            // launched, or it might have failed to get all the
                            // identities we want. Check for this.
                            final_attempt = true;
                            provenance = ChanProvenance::NewlyCreated;
                            last_err.get_or_insert(Error::RequestCancelled);
                        }
                        Ok(Err(e)) => {
                            last_err = Some(e);
                        }
                        Err(_) => {
                            last_err =
                                Some(Error::Internal(internal!("channel build task disappeared")));
                        }
                    }
                }
                // We need to launch a channel.
                Some(Action::Launch((send, pending_id))) => {
                    let connector = self.channels.builder();
                    let outcome = connector
                        .build_channel(&target, self.reporter.clone())
                        .await;
                    let status = self.handle_build_outcome(&target, pending_id, outcome);

                    // It's okay if all the receivers went away:
                    // that means that nobody was waiting for this channel.
                    let _ignore_err = send.send(status.clone().map(|_| ()));

                    match status {
                        Ok(Some(chan)) => {
                            return Ok((chan, ChanProvenance::NewlyCreated));
                        }
                        Ok(None) => {
                            final_attempt = true;
                            provenance = ChanProvenance::NewlyCreated;
                            last_err.get_or_insert(Error::RequestCancelled);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
            }

            // End of this attempt. We will try again...
        }

        Err(last_err.unwrap_or_else(|| Error::Internal(internal!("no error was set!?"))))
    }

    /// Helper: based on our internal state, decide which action to take when
    /// asked for a channel, and update our internal state accordingly.
    ///
    /// If `final_attempt` is true, then we will not pick any action that does
    /// not result in an immediate result. If we would pick such an action, we
    /// instead return `Ok(None)`.  (We could instead have the caller detect
    /// such actions, but it's less efficient to construct them, insert them,
    /// and immediately revert them.)
    fn choose_action(
        &self,
        target: &CF::BuildSpec,
        final_attempt: bool,
    ) -> Result<Option<Action<CF::Channel>>> {
        use state::ChannelState::*;

        // The idea here is to choose the channel in two steps:
        //
        // - Eligibility: Get channels from the channel map and filter them down to only channels
        //   which are eligible to be returned.
        // - Ranking: From the eligible channels, choose the best channel.
        //
        // Another way to choose the channel could be something like: first try all canonical open
        // channels, then all non-canonical open channels, then all pending channels with all
        // matching relay ids, then remaining pending channels, etc. But this ends up being hard to
        // follow and inflexible (what if you want to prioritize pending channels over non-canonical
        // open channels?).

        self.channels.with_channels(|channel_map| {
            // Open channels which are allowed for requests to `target`.
            let open_channels = channel_map
                // channels with all target relay identifiers
                .by_all_ids(target)
                .filter(|entry| match entry {
                    Open(x) => Self::open_channel_is_allowed(x, target),
                    Building(_) => false,
                });

            // Pending channels which will *probably* be allowed for requests to `target` once they
            // complete.
            let pending_channels = channel_map
                // channels that have a subset of the relay ids of `target`
                .all_subset(target)
                .into_iter()
                .filter(|entry| match entry {
                    Open(_) => false,
                    Building(x) => Self::pending_channel_maybe_allowed(x, target),
                });

            match Self::choose_best_channel(open_channels.chain(pending_channels), target) {
                Some(Open(OpenEntry { channel, .. })) => {
                    // This entry is a perfect match for the target keys: we'll return the open
                    // entry.
                    return Ok(Some(Action::Return(Ok(channel.clone()))));
                }
                Some(Building(PendingEntry { pending, .. })) => {
                    // This entry is potentially a match for the target identities: we'll return the
                    // pending entry. (We don't know for sure if it will match once it completes,
                    // since we might discover additional keys beyond those listed for this pending
                    // entry.)
                    if final_attempt {
                        // We don't launch an attempt in this case.
                        return Ok(None);
                    }
                    return Ok(Some(Action::Wait(pending.clone())));
                }
                None => {}
            }

            // It's possible we know ahead of time that building a channel would be unsuccessful.
            if channel_map
                // channels with at least one id in common with `target`
                .all_overlapping(target)
                .into_iter()
                // but not channels which completely satisfy the id requirements of `target`
                .filter(|entry| !entry.has_all_relay_ids_from(target))
                .any(|entry| matches!(entry, Open(OpenEntry{ channel, ..}) if channel.is_usable()))
            {
                // At least one *open, usable* channel has been negotiated that overlaps only
                // partially with our target: it has proven itself to have _one_ of our target
                // identities, but not all.
                //
                // Because this channel exists, we know that our target cannot succeed, since relays
                // are not allowed to share _any_ identities.
                return Ok(Some(Action::Return(Err(Error::IdentityConflict))));
            }

            if final_attempt {
                // We don't launch an attempt in this case.
                return Ok(None);
            }

            // Great, nothing interfered at all.
            let (new_state, send, pending_id) = self.setup_launch(RelayIds::from_relay_ids(target));
            channel_map.try_insert(new_state)?;
            // TODO: Later code could return with an error before the code that eventually removes
            // this entry, and then this entry would then be left in the map forever. We should have
            // a better cleanup procedure for channels.
            Ok(Some(Action::Launch((send, pending_id))))
        })?
    }

    /// We just tried to build a channel: Handle the outcome and decide what to
    /// do.
    ///
    /// Return `Ok(None)` if we have a transient error that we expect will be
    /// cleaned up by one final call to `choose_action`.
    fn handle_build_outcome(
        &self,
        target: &CF::BuildSpec,
        pending_id: state::UniqPendingChanId,
        outcome: Result<Arc<CF::Channel>>,
    ) -> Result<Option<Arc<CF::Channel>>> {
        use state::ChannelState::{self, *};

        /// Remove the pending channel with `pending_id` and a `relay_id` from `channel_map`.
        fn remove_pending_chan<C: AbstractChannel>(
            channel_map: &mut tor_linkspec::ListByRelayIds<ChannelState<C>>,
            relay_id: tor_linkspec::RelayIdRef<'_>,
            pending_id: state::UniqPendingChanId,
        ) {
            // we need only one relay id to locate it, even if it has multiple relay ids
            let removed = channel_map.remove_by_id(relay_id, |c| {
                let Building(c) = c else {
                    return false;
                };
                c.unique_id == pending_id
            });
            debug_assert_eq!(removed.len(), 1, "expected to remove exactly one channel");
        }

        let relay_id = target
            .identities()
            .next()
            .ok_or(internal!("relay target had no id"))?;

        match outcome {
            Ok(chan) => {
                // The channel got built: remember it, tell the
                // others, and return it.
                self.channels
                    .with_channels_and_params(|channel_map, channels_params| {
                        // Remove the pending channel.
                        remove_pending_chan(channel_map, relay_id, pending_id);

                        // This isn't great.  We context switch to the newly-created
                        // channel just to tell it how and whether to do padding.  Ideally
                        // we would pass the params at some suitable point during
                        // building.  However, that would involve the channel taking a
                        // copy of the params, and that must happen in the same channel
                        // manager lock acquisition span as the one where we insert the
                        // channel into the table so it will receive updates.  I.e.,
                        // here.
                        let update = channels_params.initial_update();
                        if let Some(update) = update {
                            chan.reparameterize(update.into())
                                .map_err(|_| internal!("failure on new channel"))?;
                        }
                        let new_entry = Open(OpenEntry {
                            channel: chan.clone(),
                            max_unused_duration: Duration::from_secs(
                                rand::thread_rng()
                                    .gen_range_checked(180..270)
                                    .expect("not 180 < 270 !"),
                            ),
                        });
                        channel_map.insert(new_entry);
                        Ok(Some(chan))
                    })?
            }
            Err(e) => {
                // The channel failed. Make it non-pending, tell the
                // others, and set the error.
                self.channels.with_channels(|channel_map| {
                    // Remove the pending channel.
                    remove_pending_chan(channel_map, relay_id, pending_id);
                })?;
                Err(e)
            }
        }
    }

    /// Returns `true` if the open channel is allowed to be used for a new channel request to the
    /// target.
    fn open_channel_is_allowed(chan: &OpenEntry<CF::Channel>, target: &impl HasRelayIds) -> bool {
        Some(chan)
            // only usable channels
            .filter(|entry| entry.channel.is_usable())
            // only channels which have *all* the relay ids of `target`
            .filter(|entry| entry.channel.has_all_relay_ids_from(target))
            // TODO: only channels which are canonical or have the same address as `target`
            .filter(|_entry| true)
            .is_some()
    }

    /// Returns `true` if the pending channel could possibly be used for a new channel request to
    /// the target. You still need to verify the final built channel with
    /// [`open_channel_is_allowed`](Self::open_channel_is_allowed) before using it.
    fn pending_channel_maybe_allowed(chan: &PendingEntry, target: &impl HasRelayIds) -> bool {
        // We want to avoid returning pending channels that were initially created from malicious
        // channel requests (for example from malicious relay-extend requests) that build channels
        // which will never complete successfully. Two cases where this can happen are:
        // 1. A malicious channel request asks us to build a channel to a target with a correct
        //    relay id and address, but also an additional incorrect relay id. Later when the target
        //    sends its CERTS cell, all of the relay ids won't match and the channel will fail to
        //    build. We don't want to assign non-malicious channel requests to this pending channel
        //    that will eventually fail to build.
        // 2. A malicious channel request asks us to build a channel to a target with an incorrect
        //    address. This pending channel may stall. We don't want to assign non-malicious channel
        //    requests to this pending channel that will stall for potentially a long time.
        Some(chan)
            // only channels where `target`s relay ids are a superset of `entry`s relay ids
            // - Hopefully the built channel will gain the additional ids that are requested by
            //   `target`. This should happen in most cases where none of the channels are made
            //   maliciously, since the `target` should return all of its relay ids in its CERTS
            //   cell.
            // - (Addressing 1. above) By only returning pending channels that have a subset of
            //   `target`s relay ids, we ensure that the returned pending channel does not have
            //   additional incorrect relay ids that will intentionally cause the pending channel to
            //   fail.
            // - If the built channel does not gain the remaining ids required by `target, then we
            //   won't be able to use this channel for the channel request to `target`. But we won't
            //   be able to create a new channel either, since we know that that a new channel also
            //   won't have all of the relay ids. So this channel request was doomed from the start.
            // - If the built channel gains additional ids that `target` doesn't have, that's fine
            //   and we can still use the channel for `target`.
            .filter(|entry| target.has_all_relay_ids_from(&entry.ids))
            // TODO: only channels which have the exact same address list as `target` (the two sets
            // of addresses must match exactly)
            // - (Addressing 2. above) By only returning pending channels that have exactly the same
            //   addresses, we ensure that the returned pending channel does not have any incorrect
            //   addresses that will cause the pending channel to stall.
            // - If the pending channel had additional addresses compared to `target`, the channel
            //   could get built using an address that is not valid for `target` and we wouldn't be
            //   able to use the built channel.
            // - If the pending channel had fewer addresses compared to `target`, the channel would
            //   have a lower possibility of building successfully compared to a newly created
            //   channel to `target`, so this would not be a good channel for us to return.
            .filter(|_entry| true)
            .is_some()
    }

    /// Returns the best channel for `target`.
    // TODO: remove me when the below TODOs are implemented
    #[allow(clippy::only_used_in_recursion)]
    fn choose_best_channel<'a>(
        channels: impl Iterator<Item = &'a state::ChannelState<CF::Channel>>,
        target: &impl HasRelayIds,
    ) -> Option<&'a state::ChannelState<CF::Channel>> {
        use state::ChannelState::*;
        use std::cmp::Ordering;

        /// Compare two channels to determine the better channel for `target`.
        fn choose_channel<C: AbstractChannel>(
            a: &&state::ChannelState<C>,
            b: &&state::ChannelState<C>,
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

                // not much info to help choose when both channels are pending, but this should be
                // rare
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

    /// Update the netdir
    pub(crate) fn update_netparams(
        &self,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels.reconfigure_general(None, None, netparams)
    }

    /// Notifies the chanmgr to be dormant like dormancy
    pub(crate) fn set_dormancy(
        &self,
        dormancy: Dormancy,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels
            .reconfigure_general(None, Some(dormancy), netparams)
    }

    /// Reconfigure all channels
    pub(crate) fn reconfigure(
        &self,
        config: &ChannelConfig,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels
            .reconfigure_general(Some(config), None, netparams)
    }

    /// Expire any channels that have been unused longer than
    /// their maximum unused duration assigned during creation.
    ///
    /// Return a duration from now until next channel expires.
    ///
    /// If all channels are in use or there are no open channels,
    /// return 180 seconds which is the minimum value of
    /// max_unused_duration.
    pub(crate) fn expire_channels(&self) -> Duration {
        self.channels.expire_channels()
    }

    /// Test only: return the open usable channels with a given `ident`.
    #[cfg(test)]
    pub(crate) fn get_nowait<'a, T>(&self, ident: T) -> Vec<Arc<CF::Channel>>
    where
        T: Into<tor_linkspec::RelayIdRef<'a>>,
    {
        use state::ChannelState::*;
        self.channels
            .with_channels(|channel_map| {
                channel_map
                    .by_id(ident)
                    .filter_map(|entry| match entry {
                        Open(ref ent) if ent.channel.is_usable() => Some(Arc::clone(&ent.channel)),
                        _ => None,
                    })
                    .collect()
            })
            .expect("Poisoned lock")
    }
}

/// Possible actions that we'll decide to take when asked for a channel.
#[allow(clippy::large_enum_variant)]
enum Action<C> {
    /// We found no channel.  We're going to launch a new one,
    /// then tell everybody about it.
    Launch((Sending, state::UniqPendingChanId)),
    /// We found an in-progress attempt at making a channel.
    /// We're going to wait for it to finish.
    Wait(Pending),
    /// We found a usable channel.  We're going to return it.
    Return(Result<Arc<C>>),
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
    use crate::Error;

    use futures::join;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tor_error::bad_api_usage;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;

    use crate::ChannelUsage as CU;
    use tor_rtcompat::{task::yield_now, test_with_one_runtime, Runtime};

    #[derive(Clone)]
    struct FakeChannelFactory<RT> {
        runtime: RT,
    }

    #[derive(Clone, Debug)]
    struct FakeChannel {
        ed_ident: Ed25519Identity,
        mood: char,
        closing: Arc<AtomicBool>,
        detect_reuse: Arc<char>,
        // last_params: Option<ChannelPaddingInstructionsUpdates>,
    }

    impl PartialEq for FakeChannel {
        fn eq(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.detect_reuse, &other.detect_reuse)
        }
    }

    impl AbstractChannel for FakeChannel {
        fn is_usable(&self) -> bool {
            !self.closing.load(Ordering::SeqCst)
        }
        fn duration_unused(&self) -> Option<Duration> {
            None
        }
        fn reparameterize(
            &self,
            _updates: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            // *self.last_params.lock().unwrap() = Some((*updates).clone());
            Ok(())
        }
        fn engage_padding_activities(&self) {}
    }

    impl HasRelayIds for FakeChannel {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            match key_type {
                tor_linkspec::RelayIdType::Ed25519 => Some((&self.ed_ident).into()),
                _ => None,
            }
        }
    }

    impl FakeChannel {
        fn start_closing(&self) {
            self.closing.store(true, Ordering::SeqCst);
        }
    }

    impl<RT: Runtime> FakeChannelFactory<RT> {
        fn new(runtime: RT) -> Self {
            FakeChannelFactory { runtime }
        }
    }

    fn new_test_abstract_chanmgr<R: Runtime>(runtime: R) -> AbstractChanMgr<FakeChannelFactory<R>> {
        let cf = FakeChannelFactory::new(runtime);
        AbstractChanMgr::new(
            cf,
            &ChannelConfig::default(),
            Default::default(),
            &Default::default(),
            BootstrapReporter::fake(),
        )
    }

    #[derive(Clone, Debug)]
    struct FakeBuildSpec(u32, char, Ed25519Identity);

    impl HasRelayIds for FakeBuildSpec {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            match key_type {
                tor_linkspec::RelayIdType::Ed25519 => Some((&self.2).into()),
                _ => None,
            }
        }
    }

    /// Helper to make a fake Ed identity from a u32.
    fn u32_to_ed(n: u32) -> Ed25519Identity {
        let mut bytes = [0; 32];
        bytes[0..4].copy_from_slice(&n.to_be_bytes());
        bytes.into()
    }

    #[async_trait]
    impl<RT: Runtime> AbstractChannelFactory for FakeChannelFactory<RT> {
        type Channel = FakeChannel;
        type BuildSpec = FakeBuildSpec;
        type Stream = ();

        async fn build_channel(
            &self,
            target: &Self::BuildSpec,
            _reporter: BootstrapReporter,
        ) -> Result<Arc<FakeChannel>> {
            yield_now().await;
            let FakeBuildSpec(ident, mood, id) = *target;
            let ed_ident = u32_to_ed(ident);
            assert_eq!(ed_ident, id);
            match mood {
                // "X" means never connect.
                '❌' | '🔥' => return Err(Error::UnusableTarget(bad_api_usage!("emoji"))),
                // "zzz" means wait for 15 seconds then succeed.
                '💤' => {
                    self.runtime.sleep(Duration::new(15, 0)).await;
                }
                _ => {}
            }
            Ok(Arc::new(FakeChannel {
                ed_ident,
                mood,
                closing: Arc::new(AtomicBool::new(false)),
                detect_reuse: Default::default(),
                // last_params: None,
            }))
        }

        #[cfg(feature = "relay")]
        async fn build_channel_using_incoming(
            &self,
            _peer: std::net::SocketAddr,
            _stream: Self::Stream,
        ) -> Result<Arc<Self::Channel>> {
            unimplemented!()
        }
    }

    #[test]
    fn connect_one_ok() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);
            let target = FakeBuildSpec(413, '!', u32_to_ed(413));
            let chan1 = mgr
                .get_or_launch(target.clone(), CU::UserTraffic)
                .await
                .unwrap()
                .0;
            let chan2 = mgr.get_or_launch(target, CU::UserTraffic).await.unwrap().0;

            assert_eq!(chan1, chan2);
            assert_eq!(mgr.get_nowait(&u32_to_ed(413)), vec![chan1]);
        });
    }

    #[test]
    fn connect_one_fail() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // This is set up to always fail.
            let target = FakeBuildSpec(999, '❌', u32_to_ed(999));
            let res1 = mgr.get_or_launch(target, CU::UserTraffic).await;
            assert!(matches!(res1, Err(Error::UnusableTarget(_))));

            assert!(mgr.get_nowait(&u32_to_ed(999)).is_empty());
        });
    }

    #[test]
    fn test_concurrent() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // TODO(nickm): figure out how to make these actually run
            // concurrently. Right now it seems that they don't actually
            // interact.
            let (ch3a, ch3b, ch44a, ch44b, ch86a, ch86b) = join!(
                mgr.get_or_launch(FakeBuildSpec(3, 'a', u32_to_ed(3)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(3, 'b', u32_to_ed(3)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(44, 'a', u32_to_ed(44)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(44, 'b', u32_to_ed(44)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(86, '❌', u32_to_ed(86)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(86, '🔥', u32_to_ed(86)), CU::UserTraffic),
            );
            let ch3a = ch3a.unwrap();
            let ch3b = ch3b.unwrap();
            let ch44a = ch44a.unwrap();
            let ch44b = ch44b.unwrap();
            let err_a = ch86a.unwrap_err();
            let err_b = ch86b.unwrap_err();

            assert_eq!(ch3a, ch3b);
            assert_eq!(ch44a, ch44b);
            assert_ne!(ch44a, ch3a);

            assert!(matches!(err_a, Error::UnusableTarget(_)));
            assert!(matches!(err_b, Error::UnusableTarget(_)));
        });
    }

    #[test]
    fn unusable_entries() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            let (ch3, ch4, ch5) = join!(
                mgr.get_or_launch(FakeBuildSpec(3, 'a', u32_to_ed(3)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(4, 'a', u32_to_ed(4)), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(5, 'a', u32_to_ed(5)), CU::UserTraffic),
            );

            let ch3 = ch3.unwrap().0;
            let _ch4 = ch4.unwrap();
            let ch5 = ch5.unwrap().0;

            ch3.start_closing();
            ch5.start_closing();

            let ch3_new = mgr
                .get_or_launch(FakeBuildSpec(3, 'b', u32_to_ed(3)), CU::UserTraffic)
                .await
                .unwrap()
                .0;
            assert_ne!(ch3, ch3_new);
            assert_eq!(ch3_new.mood, 'b');

            mgr.remove_unusable_entries().unwrap();

            assert!(!mgr.get_nowait(&u32_to_ed(3)).is_empty());
            assert!(!mgr.get_nowait(&u32_to_ed(4)).is_empty());
            assert!(mgr.get_nowait(&u32_to_ed(5)).is_empty());
        });
    }
}
