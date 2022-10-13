//! Abstract implementation of a channel manager

use crate::mgr::map::OpenEntry;
use crate::{ChanProvenance, ChannelConfig, ChannelUsage, Dormancy, Error, Result};

use async_trait::async_trait;
use futures::channel::oneshot;
use futures::future::{FutureExt, Shared};
use rand::Rng;
use std::hash::Hash;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use tor_error::internal;
use tor_netdir::params::NetParameters;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;

mod map;

/// Trait to describe as much of a
/// [`Channel`](tor_proto::channel::Channel) as `AbstractChanMgr`
/// needs to use.
pub(crate) trait AbstractChannel: Clone {
    /// Identity type for the other side of the channel.
    type Ident: Hash + Eq + Clone;
    /// Return this channel's identity.
    fn ident(&self) -> &Self::Ident;
    /// Return true if this channel is usable.
    ///
    /// A channel might be unusable because it is closed, because it has
    /// hit a bug, or for some other reason.  We don't return unusable
    /// channels back to the user.
    fn is_usable(&self) -> bool;
    /// Return the amount of time a channel has not been in use.
    /// Return None if the channel is currently in use.
    fn duration_unused(&self) -> Option<Duration>;

    /// Reparameterise this channel according to the provided `ChannelPaddingInstructionsUpdates`
    ///
    /// The changed parameters may not be implemented "immediately",
    /// but this will be done "reasonably soon".
    fn reparameterize(
        &mut self,
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
    /// Type that explains how to build a channel.
    type BuildSpec;

    /// Construct a new channel to the destination described at `target`.
    ///
    /// This function must take care of all timeouts, error detection,
    /// and so on.
    ///
    /// It should not retry; that is handled at a higher level.
    async fn build_channel(&self, target: &Self::BuildSpec) -> Result<Self::Channel>;
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
    /// A 'connector' object that we use to create channels.
    connector: CF,

    /// A map from ed25519 identity to channel, or to pending channel status.
    pub(crate) channels: map::ChannelMap<CF::Channel>,
}

/// Type alias for a future that we wait on to see when a pending
/// channel is done or failed.
type Pending<C> = Shared<oneshot::Receiver<Result<C>>>;

/// Type alias for the sender we notify when we complete a channel (or
/// fail to complete it).
type Sending<C> = oneshot::Sender<Result<C>>;

impl<CF: AbstractChannelFactory> AbstractChanMgr<CF> {
    /// Make a new empty channel manager.
    pub(crate) fn new(
        connector: CF,
        config: &ChannelConfig,
        dormancy: Dormancy,
        netparams: &NetParameters,
    ) -> Self {
        AbstractChanMgr {
            connector,
            channels: map::ChannelMap::new(config.clone(), dormancy, netparams),
        }
    }

    /// Remove every unusable entry from this channel manager.
    #[cfg(test)]
    pub(crate) fn remove_unusable_entries(&self) -> Result<()> {
        self.channels.remove_unusable()
    }

    /// Helper: return the objects used to inform pending tasks
    /// about a newly open or failed channel.
    fn setup_launch<C: Clone>(&self) -> (map::ChannelState<C>, Sending<C>) {
        let (snd, rcv) = oneshot::channel();
        let shared = rcv.shared();
        (map::ChannelState::Building(shared), snd)
    }

    /// Get a channel whose identity is `ident`.
    ///
    /// If a usable channel exists with that identity, return it.
    ///
    /// If no such channel exists already, and none is in progress,
    /// launch a new request using `target`, which must match `ident`.
    ///
    /// If no such channel exists already, but we have one that's in
    /// progress, wait for it to succeed or fail.
    pub(crate) async fn get_or_launch(
        &self,
        ident: <<CF as AbstractChannelFactory>::Channel as AbstractChannel>::Ident,
        target: CF::BuildSpec,
        usage: ChannelUsage,
    ) -> Result<(CF::Channel, ChanProvenance)> {
        use ChannelUsage as CU;

        let chan = self.get_or_launch_internal(ident, target).await?;

        match usage {
            CU::Dir | CU::UselessCircuit => {}
            CU::UserTraffic => chan.0.engage_padding_activities(),
        }

        Ok(chan)
    }

    /// Get a channel whose identity is `ident` - internal implementation
    async fn get_or_launch_internal(
        &self,
        ident: <<CF as AbstractChannelFactory>::Channel as AbstractChannel>::Ident,
        target: CF::BuildSpec,
    ) -> Result<(CF::Channel, ChanProvenance)> {
        use map::ChannelState::*;

        /// Possible actions that we'll decide to take based on the
        /// channel's initial state.
        enum Action<C> {
            /// We found no channel.  We're going to launch a new one,
            /// then tell everybody about it.
            Launch(Sending<C>),
            /// We found an in-progress attempt at making a channel.
            /// We're going to wait for it to finish.
            Wait(Pending<C>),
            /// We found a usable channel.  We're going to return it.
            Return(Result<(C, ChanProvenance)>),
        }
        /// How many times do we try?
        const N_ATTEMPTS: usize = 2;

        // TODO(nickm): It would be neat to use tor_retry instead.
        let mut last_err = None;

        for _ in 0..N_ATTEMPTS {
            // First, see what state we're in, and what we should do
            // about it.
            let action = self
                .channels
                .change_state(&ident, |oldstate| match oldstate {
                    Some(Open(ref ent)) => {
                        if ent.channel.is_usable() {
                            // Good channel. Return it.
                            let action = Action::Return(Ok((
                                ent.channel.clone(),
                                ChanProvenance::Preexisting,
                            )));
                            (oldstate, action)
                        } else {
                            // Unusable channel.  Move to the Building
                            // state and launch a new channel.
                            let (newstate, send) = self.setup_launch();
                            let action = Action::Launch(send);
                            (Some(newstate), action)
                        }
                    }
                    Some(Building(ref pending)) => {
                        let action = Action::Wait(pending.clone());
                        (oldstate, action)
                    }
                    Some(Poisoned(_)) => {
                        // We should never be able to see this state; this
                        // is a bug.
                        (
                            None,
                            Action::Return(Err(Error::Internal(internal!(
                                "Found a poisoned entry"
                            )))),
                        )
                    }
                    None => {
                        // No channel.  Move to the Building
                        // state and launch a new channel.
                        let (newstate, send) = self.setup_launch();
                        let action = Action::Launch(send);
                        (Some(newstate), action)
                    }
                })?;

            // Now we act based on the channel.
            match action {
                // Easy case: we have an error or a channel to return.
                Action::Return(v) => {
                    return v;
                }
                // There's an in-progress channel.  Wait for it.
                Action::Wait(pend) => match pend.await {
                    Ok(Ok(chan)) => return Ok((chan, ChanProvenance::NewlyCreated)),
                    Ok(Err(e)) => {
                        last_err = Some(e);
                    }
                    Err(_) => {
                        last_err =
                            Some(Error::Internal(internal!("channel build task disappeared")));
                    }
                },
                // We need to launch a channel.
                Action::Launch(send) => match self.connector.build_channel(&target).await {
                    Ok(mut chan) => {
                        // The channel got built: remember it, tell the
                        // others, and return it.
                        self.channels
                            .replace_with_params(ident.clone(), |channels_params| {
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
                                Ok(Open(OpenEntry {
                                    channel: chan.clone(),
                                    max_unused_duration: Duration::from_secs(
                                        rand::thread_rng().gen_range(180..270),
                                    ),
                                }))
                            })?;
                        // It's okay if all the receivers went away:
                        // that means that nobody was waiting for this channel.
                        let _ignore_err = send.send(Ok(chan.clone()));
                        return Ok((chan, ChanProvenance::NewlyCreated));
                    }
                    Err(e) => {
                        // The channel failed. Make it non-pending, tell the
                        // others, and set the error.
                        self.channels.remove(&ident)?;
                        // (As above)
                        let _ignore_err = send.send(Err(e.clone()));
                        last_err = Some(e);
                    }
                },
            }
        }

        Err(last_err.unwrap_or_else(|| Error::Internal(internal!("no error was set!?"))))
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

    /// Test only: return the current open usable channel with a given
    /// `ident`, if any.
    #[cfg(test)]
    pub(crate) fn get_nowait(
        &self,
        ident: &<<CF as AbstractChannelFactory>::Channel as AbstractChannel>::Ident,
    ) -> Option<CF::Channel> {
        use map::ChannelState::*;
        match self.channels.get(ident) {
            Ok(Some(Open(ref ent))) if ent.channel.is_usable() => Some(ent.channel.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Error;

    use futures::join;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tor_error::bad_api_usage;

    use crate::ChannelUsage as CU;
    use tor_rtcompat::{task::yield_now, test_with_one_runtime, Runtime};

    struct FakeChannelFactory<RT> {
        runtime: RT,
    }

    #[derive(Clone, Debug)]
    struct FakeChannel {
        ident: u32,
        mood: char,
        closing: Arc<AtomicBool>,
        detect_reuse: Arc<char>,
        last_params: Option<ChannelPaddingInstructionsUpdates>,
    }

    impl PartialEq for FakeChannel {
        fn eq(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.detect_reuse, &other.detect_reuse)
        }
    }

    impl AbstractChannel for FakeChannel {
        type Ident = u32;
        fn ident(&self) -> &u32 {
            &self.ident
        }
        fn is_usable(&self) -> bool {
            !self.closing.load(Ordering::SeqCst)
        }
        fn duration_unused(&self) -> Option<Duration> {
            None
        }
        fn reparameterize(
            &mut self,
            updates: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            self.last_params = Some((*updates).clone());
            Ok(())
        }
        fn engage_padding_activities(&self) {}
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
        )
    }

    #[async_trait]
    impl<RT: Runtime> AbstractChannelFactory for FakeChannelFactory<RT> {
        type Channel = FakeChannel;
        type BuildSpec = (u32, char);

        async fn build_channel(&self, target: &Self::BuildSpec) -> Result<FakeChannel> {
            yield_now().await;
            let (ident, mood) = *target;
            match mood {
                // "X" means never connect.
                '❌' | '🔥' => return Err(Error::UnusableTarget(bad_api_usage!("emoji"))),
                // "zzz" means wait for 15 seconds then succeed.
                '💤' => {
                    self.runtime.sleep(Duration::new(15, 0)).await;
                }
                _ => {}
            }
            Ok(FakeChannel {
                ident,
                mood,
                closing: Arc::new(AtomicBool::new(false)),
                detect_reuse: Default::default(),
                last_params: None,
            })
        }
    }

    #[test]
    fn connect_one_ok() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);
            let target = (413, '!');
            let chan1 = mgr
                .get_or_launch(413, target, CU::UserTraffic)
                .await
                .unwrap()
                .0;
            let chan2 = mgr
                .get_or_launch(413, target, CU::UserTraffic)
                .await
                .unwrap()
                .0;

            assert_eq!(chan1, chan2);

            let chan3 = mgr.get_nowait(&413).unwrap();
            assert_eq!(chan1, chan3);
        });
    }

    #[test]
    fn connect_one_fail() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // This is set up to always fail.
            let target = (999, '❌');
            let res1 = mgr.get_or_launch(999, target, CU::UserTraffic).await;
            assert!(matches!(res1, Err(Error::UnusableTarget(_))));

            let chan3 = mgr.get_nowait(&999);
            assert!(chan3.is_none());
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
                mgr.get_or_launch(3, (3, 'a'), CU::UserTraffic),
                mgr.get_or_launch(3, (3, 'b'), CU::UserTraffic),
                mgr.get_or_launch(44, (44, 'a'), CU::UserTraffic),
                mgr.get_or_launch(44, (44, 'b'), CU::UserTraffic),
                mgr.get_or_launch(86, (86, '❌'), CU::UserTraffic),
                mgr.get_or_launch(86, (86, '🔥'), CU::UserTraffic),
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
                mgr.get_or_launch(3, (3, 'a'), CU::UserTraffic),
                mgr.get_or_launch(4, (4, 'a'), CU::UserTraffic),
                mgr.get_or_launch(5, (5, 'a'), CU::UserTraffic),
            );

            let ch3 = ch3.unwrap().0;
            let _ch4 = ch4.unwrap();
            let ch5 = ch5.unwrap().0;

            ch3.start_closing();
            ch5.start_closing();

            let ch3_new = mgr
                .get_or_launch(3, (3, 'b'), CU::UserTraffic)
                .await
                .unwrap()
                .0;
            assert_ne!(ch3, ch3_new);
            assert_eq!(ch3_new.mood, 'b');

            mgr.remove_unusable_entries().unwrap();

            assert!(mgr.get_nowait(&3).is_some());
            assert!(mgr.get_nowait(&4).is_some());
            assert!(mgr.get_nowait(&5).is_none());
        });
    }
}
