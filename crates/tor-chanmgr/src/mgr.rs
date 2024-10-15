//! Abstract implementation of a channel manager

use crate::mgr::state::{ChannelForTarget, PendingChannelHandle};
use crate::{ChanProvenance, ChannelConfig, ChannelUsage, Dormancy, Error, Result};

use crate::factory::BootstrapReporter;
use async_trait::async_trait;
use futures::future::Shared;
use oneshot_fused_workaround as oneshot;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use tor_error::internal;
use tor_linkspec::HasRelayIds;
use tor_netdir::params::NetParameters;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;
use tor_proto::memquota::{ChannelAccount, SpecificAccount as _, ToplevelAccount};

mod select;
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
        memquota: ChannelAccount,
    ) -> Result<Arc<Self::Channel>>;

    /// Construct a new channel for an incoming connection.
    #[cfg(feature = "relay")]
    async fn build_channel_using_incoming(
        &self,
        peer: std::net::SocketAddr,
        stream: Self::Stream,
        memquota: ChannelAccount,
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

    /// The memory quota account that every channel will be a child of
    pub(crate) memquota: ToplevelAccount,
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
        memquota: ToplevelAccount,
    ) -> Self {
        AbstractChanMgr {
            channels: state::MgrState::new(connector, config.clone(), dormancy, netparams),
            reporter,
            memquota,
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

    /// Build a channel for an incoming stream. See
    /// [`ChanMgr::handle_incoming`](crate::ChanMgr::handle_incoming).
    #[cfg(feature = "relay")]
    pub(crate) async fn handle_incoming(
        &self,
        src: std::net::SocketAddr,
        stream: CF::Stream,
    ) -> Result<Arc<CF::Channel>> {
        let chan_builder = self.channels.builder();
        let memquota = ChannelAccount::new(&self.memquota)?;
        let _outcome = chan_builder
            .build_channel_using_incoming(src, stream, memquota)
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
                Some(Action::Launch((handle, send))) => {
                    let connector = self.channels.builder();
                    let memquota = ChannelAccount::new(&self.memquota)?;
                    let outcome = connector
                        .build_channel(&target, self.reporter.clone(), memquota)
                        .await;
                    let status = self.handle_build_outcome(handle, outcome);

                    // It's okay if all the receivers went away:
                    // that means that nobody was waiting for this channel.
                    let _ignore_err = send.send(status.clone().map(|_| ()));

                    match status {
                        Ok(chan) => {
                            return Ok((chan, ChanProvenance::NewlyCreated));
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
    ) -> Result<Option<Action<CF>>> {
        // don't create new channels on the final attempt
        let response = self.channels.request_channel(
            target,
            /* add_new_entry_if_not_found= */ !final_attempt,
        );

        match response {
            Ok(Some(ChannelForTarget::Open(channel))) => Ok(Some(Action::Return(Ok(channel)))),
            Ok(Some(ChannelForTarget::Pending(pending))) => {
                if !final_attempt {
                    Ok(Some(Action::Wait(pending)))
                } else {
                    // don't return a pending channel on the final attempt
                    Ok(None)
                }
            }
            Ok(Some(ChannelForTarget::NewEntry((handle, send)))) => {
                // TODO arti#1654: Later code could return with an error before the code that
                // eventually removes this entry, and then this entry would then be left in the map
                // forever. If this happened, no callers would be able to build channels to this
                // target anymore. We should have a better cleanup procedure for channels.
                Ok(Some(Action::Launch((handle, send))))
            }
            Ok(None) => Ok(None),
            Err(e @ Error::IdentityConflict) => Ok(Some(Action::Return(Err(e)))),
            Err(e) => Err(e),
        }
    }

    /// We just tried to build a channel: Handle the outcome and decide what to
    /// do.
    fn handle_build_outcome(
        &self,
        handle: PendingChannelHandle<CF>,
        outcome: Result<Arc<CF::Channel>>,
    ) -> Result<Arc<CF::Channel>> {
        match outcome {
            Ok(chan) => {
                // The channel got built: remember it and return it.
                self.channels
                    .replace_pending_channel(handle, Arc::clone(&chan))?;
                Ok(chan)
            }
            Err(e) => {
                // The channel failed. Make it non-pending and set the error.
                self.channels.remove_pending_channel(handle)?;
                Err(e)
            }
        }
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
enum Action<'a, CF: AbstractChannelFactory> {
    /// We found no channel.  We're going to launch a new one,
    /// then tell everybody about it.
    Launch((PendingChannelHandle<'a, CF>, Sending)),
    /// We found an in-progress attempt at making a channel.
    /// We're going to wait for it to finish.
    Wait(Pending),
    /// We found a usable channel.  We're going to return it.
    Return(Result<Arc<CF::Channel>>),
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
    use tor_memquota::ArcMemoryQuotaTrackerExt as _;

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
            ToplevelAccount::new_noop(),
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
            _memquota: ChannelAccount,
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
            _memquota: ChannelAccount,
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
