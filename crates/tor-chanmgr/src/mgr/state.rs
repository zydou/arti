//! Simple implementation for the internal map state of a ChanMgr.

use std::time::Duration;

use super::AbstractChannelFactory;
use super::{AbstractChannel, Pending};
use crate::{ChannelConfig, Dormancy, Result};

use std::result::Result as StdResult;
use std::sync::Arc;
use tor_cell::chancell::msg::PaddingNegotiate;
use tor_config::PaddingLevel;
use tor_error::{internal, into_internal};
use tor_linkspec::ByRelayIds;
use tor_linkspec::HasRelayIds;
use tor_linkspec::RelayIds;
use tor_netdir::{params::NetParameters, params::CHANNEL_PADDING_TIMEOUT_UPPER_BOUND};
use tor_proto::channel::padding::Parameters as PaddingParameters;
use tor_proto::channel::padding::ParametersBuilder as PaddingParametersBuilder;
use tor_proto::channel::ChannelPaddingInstructionsUpdates;
use tor_proto::ChannelPaddingInstructions;
use tor_units::{BoundedInt32, IntegerMilliseconds};
use tracing::info;
use void::{ResultVoidExt as _, Void};

#[cfg(test)]
mod padding_test;

/// All mutable state held by an `AbstractChannelMgr`.
///
/// One reason that this is an isolated type is that we want to
/// to limit the amount of code that can see and
/// lock the Mutex here.  (We're using a blocking mutex close to async
/// code, so we need to be careful.)
pub(crate) struct MgrState<C: AbstractChannelFactory> {
    /// The data, within a lock
    ///
    /// (Danger: this uses a blocking mutex close to async code.  This mutex
    /// must never be held while an await is happening.)
    inner: std::sync::Mutex<Inner<C>>,
}

/// A map from channel id to channel state, plus necessary auxiliary state - inside lock
struct Inner<C: AbstractChannelFactory> {
    /// The channel factory type that we store.
    ///
    /// In this module we never use this _as_ an AbstractChannelFactory: we just
    /// hand out clones of it when asked.
    builder: C,

    /// A map from identity to channel, or to pending channel status.
    channels: ByRelayIds<ChannelState<C::Channel>>,

    /// Parameters for channels that we create, and that all existing channels are using
    ///
    /// Will be updated by a background task, which also notifies all existing
    /// `Open` channels via `channels`.
    ///
    /// (Must be protected by the same lock as `channels`, or a channel might be
    /// created using being-replaced parameters, but not get an update.)
    channels_params: ChannelPaddingInstructions,

    /// The configuration (from the config file or API caller)
    config: ChannelConfig,

    /// Dormancy
    ///
    /// The last dormancy information we have been told about and passed on to our channels.
    /// Updated via `MgrState::set_dormancy` and hence `MgrState::reconfigure_general`,
    /// which then uses it to calculate how to reconfigure the channels.
    dormancy: Dormancy,
}

/// The state of a channel (or channel build attempt) within a map.
///
/// A ChannelState can be Open (representing a fully negotiated channel) or
/// Building (representing a pending attempt to build a channel). Both states
/// have a set of RelayIds, but these RelayIds represent slightly different
/// things:
///  * On a Building channel, the set of RelayIds is all the identities that we
///    require the peer to have. (The peer may turn out to have _more_
///    identities than this.)
///  * On an Open channel, the set of RelayIds is all the identities that
///    we were able to successfully authenticate for the peer.
pub(crate) enum ChannelState<C> {
    /// An open channel.
    ///
    /// This channel might not be usable: it might be closing or
    /// broken.  We need to check its is_usable() method before
    /// yielding it to the user.
    Open(OpenEntry<C>),
    /// A channel that's getting built.
    Building(PendingEntry),
}

/// An open channel entry.
#[derive(Clone)]
pub(crate) struct OpenEntry<C> {
    /// The underlying open channel.
    pub(crate) channel: C,
    /// The maximum unused duration allowed for this channel.
    pub(crate) max_unused_duration: Duration,
}

/// An entry for a not-yet-build channel
#[derive(Clone)]
pub(crate) struct PendingEntry {
    /// The keys of the relay to which we're trying to open a channel.
    pub(crate) ids: RelayIds,

    /// A future we can clone and listen on to learn when this channel attempt
    /// is successful or failed.
    ///
    /// This entry will be removed from the map (and possibly replaced with an
    /// `OpenEntry`) _before_ this future becomes ready.
    pub(crate) pending: Pending,
}

impl<C> HasRelayIds for ChannelState<C>
where
    C: HasRelayIds,
{
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match self {
            ChannelState::Open(OpenEntry { channel, .. }) => channel.identity(key_type),
            ChannelState::Building(PendingEntry { ids, .. }) => ids.identity(key_type),
        }
    }
}

impl<C: Clone> ChannelState<C> {
    /// For testing: either give the Open channel inside this state,
    /// or panic if there is none.
    #[cfg(test)]
    fn unwrap_open(&self) -> &C {
        match self {
            ChannelState::Open(ent) => &ent.channel,
            _ => panic!("Not an open channel"),
        }
    }
}

/// Type of the `nf_ito_*` netdir parameters, convenience alias
type NfIto = IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>>;

/// Extract from a `NetParameters` which we need, conveniently organized for our processing
///
/// This type serves two functions at once:
///
///  1. Being a subset of the parameters, we can copy it out of
///     the netdir, before we do more complex processing - and, in particular,
///     before we obtain the lock on `inner` (which we need to actually handle the update,
///     because we need to combine information from the config with that from the netdir).
///
///  2. Rather than four separate named fields, it has arrays, so that it is easy to
///     select the values without error-prone recapitulation of field names.
#[derive(Debug, Clone)]
struct NetParamsExtract {
    /// `nf_ito_*`, the padding timeout parameters from the netdir consensus
    ///
    /// `nf_ito[ 0=normal, 1=reduced ][ 0=low, 1=high ]`
    /// are `nf_ito_{low,high}{,_reduced` from `NetParameters`.
    // TODO we could use some enum or IndexVec or something to make this less `0` and `1`
    nf_ito: [[NfIto; 2]; 2],
}

impl From<&NetParameters> for NetParamsExtract {
    fn from(p: &NetParameters) -> Self {
        NetParamsExtract {
            nf_ito: [
                [p.nf_ito_low, p.nf_ito_high],
                [p.nf_ito_low_reduced, p.nf_ito_high_reduced],
            ],
        }
    }
}

impl NetParamsExtract {
    /// Return the padding timer parameter low end, for reduced-ness `reduced`, as a `u32`
    fn pad_low(&self, reduced: bool) -> IntegerMilliseconds<u32> {
        self.pad_get(reduced, 0)
    }
    /// Return the padding timer parameter high end, for reduced-ness `reduced`, as a `u32`
    fn pad_high(&self, reduced: bool) -> IntegerMilliseconds<u32> {
        self.pad_get(reduced, 1)
    }

    /// Return and converts one padding parameter timer
    ///
    /// Internal function.
    fn pad_get(&self, reduced: bool, low_or_high: usize) -> IntegerMilliseconds<u32> {
        self.nf_ito[usize::from(reduced)][low_or_high]
            .try_map(|v| Ok::<_, Void>(v.into()))
            .void_unwrap()
    }
}

impl<C: AbstractChannel> ChannelState<C> {
    /// Return true if a channel is ready to expire.
    /// Update `expire_after` if a smaller duration than
    /// the given value is required to expire this channel.
    fn ready_to_expire(&self, expire_after: &mut Duration) -> bool {
        let ChannelState::Open(ent) = self else {
            return false;
        };
        let Some(unused_duration) = ent.channel.duration_unused() else {
            // still in use
            return false;
        };
        let max_unused_duration = ent.max_unused_duration;
        let Some(remaining) = max_unused_duration.checked_sub(unused_duration) else {
            // no time remaining; drop now.
            return true;
        };
        *expire_after = std::cmp::min(*expire_after, remaining);
        false
    }
}

impl<C: AbstractChannelFactory> MgrState<C> {
    /// Create a new empty `MgrState`.
    pub(crate) fn new(
        builder: C,
        config: ChannelConfig,
        dormancy: Dormancy,
        netparams: &NetParameters,
    ) -> Self {
        let mut channels_params = ChannelPaddingInstructions::default();
        let netparams = NetParamsExtract::from(netparams);
        let update = parameterize(&mut channels_params, &config, dormancy, &netparams)
            .unwrap_or_else(|e: tor_error::Bug| panic!("bug detected on startup: {:?}", e));
        let _: Option<_> = update; // there are no channels yet, that would need to be told

        MgrState {
            inner: std::sync::Mutex::new(Inner {
                builder,
                channels: ByRelayIds::new(),
                config,
                channels_params,
                dormancy,
            }),
        }
    }

    /// Run a function on the `ByRelayIds` that implements the map in this `MgrState`.
    ///
    /// This function grabs a mutex: do not provide a slow function.
    ///
    /// We provide this function rather than exposing the channels set directly,
    /// to make sure that the calling code doesn't await while holding the lock.
    pub(crate) fn with_channels<F, T>(&self, func: F) -> Result<T>
    where
        F: FnOnce(&mut ByRelayIds<ChannelState<C::Channel>>) -> T,
    {
        let mut inner = self.inner.lock()?;
        Ok(func(&mut inner.channels))
    }

    /// Return a copy of the builder stored in this state.
    pub(crate) fn builder(&self) -> C
    where
        C: Clone,
    {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.builder.clone()
    }

    /// Run a function to modify the builder stored in this state.
    #[allow(dead_code)]
    pub(crate) fn with_mut_builder<F>(&self, func: F)
    where
        F: FnOnce(&mut C),
    {
        let mut inner = self.inner.lock().expect("lock poisoned");
        func(&mut inner.builder);
    }

    /// Run a function on the `ByRelayIds` that implements the map in this `MgrState`.
    ///
    /// This function grabs a mutex: do not provide a slow function.
    ///
    /// We provide this function rather than exposing the channels set directly,
    /// to make sure that the calling code doesn't await while holding the lock.
    pub(crate) fn with_channels_and_params<F, T>(&self, func: F) -> Result<T>
    where
        F: FnOnce(&mut ByRelayIds<ChannelState<C::Channel>>, &ChannelPaddingInstructions) -> T,
    {
        let mut inner = self.inner.lock()?;
        // We need this silly destructuring syntax so that we don't seem to be
        // borrowing the structure mutably and immutably at the same time.
        let Inner {
            ref mut channels,
            ref channels_params,
            ..
        } = &mut *inner;
        Ok(func(channels, channels_params))
    }

    /// Remove every unusable state from the map in this state..
    #[cfg(test)]
    pub(crate) fn remove_unusable(&self) -> Result<()> {
        let mut inner = self.inner.lock()?;
        inner.channels.retain(|state| match state {
            ChannelState::Open(ent) => ent.channel.is_usable(),
            ChannelState::Building(_) => true,
        });
        Ok(())
    }

    /// Reconfigure all channels as necessary
    ///
    /// (By reparameterizing channels as needed)
    /// This function will handle
    ///   - netdir update
    ///   - a reconfiguration
    ///   - dormancy
    ///
    /// For `new_config` and `new_dormancy`, `None` means "no change to previous info".
    pub(super) fn reconfigure_general(
        &self,
        new_config: Option<&ChannelConfig>,
        new_dormancy: Option<Dormancy>,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        use ChannelState as CS;

        // TODO when we support operation as a relay, inter-relay channels ought
        // not to get padding.
        let netdir = {
            let extract = NetParamsExtract::from((*netparams).as_ref());
            drop(netparams);
            extract
        };

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| internal!("poisoned channel manager"))?;
        let inner = &mut *inner;

        if let Some(new_config) = new_config {
            inner.config = new_config.clone();
        }
        if let Some(new_dormancy) = new_dormancy {
            inner.dormancy = new_dormancy;
        }

        let update = parameterize(
            &mut inner.channels_params,
            &inner.config,
            inner.dormancy,
            &netdir,
        )?;

        let update = if let Some(u) = update {
            u
        } else {
            return Ok(());
        };
        let update = Arc::new(update);

        for channel in inner.channels.values() {
            let channel = match channel {
                CS::Open(OpenEntry { channel, .. }) => channel,
                CS::Building(_) => continue,
            };
            // Ignore error (which simply means the channel is closed or gone)
            let _ = channel.reparameterize(update.clone());
        }
        Ok(())
    }

    /// Expire all channels that have been unused for too long.
    ///
    /// Return a Duration until the next time at which
    /// a channel _could_ expire.
    pub(crate) fn expire_channels(&self) -> Duration {
        let mut ret = Duration::from_secs(180);
        self.inner
            .lock()
            .expect("Poisoned lock")
            .channels
            .retain(|chan| !chan.ready_to_expire(&mut ret));
        ret
    }
}

/// Converts config, dormancy, and netdir, into parameter updates
///
/// Calculates new parameters, updating `channels_params` as appropriate.
/// If anything changed, the corresponding update instruction is returned.
///
/// `channels_params` is updated with the new parameters,
/// and the update message, if one is needed, is returned.
///
/// This is called in two places:
///
///  1. During chanmgr creation, it is called once to analyze the initial state
///     and construct a corresponding ChannelPaddingInstructions.
///
///  2. During reconfiguration.
fn parameterize(
    channels_params: &mut ChannelPaddingInstructions,
    config: &ChannelConfig,
    dormancy: Dormancy,
    netdir: &NetParamsExtract,
) -> StdResult<Option<ChannelPaddingInstructionsUpdates>, tor_error::Bug> {
    // Everything in this calculation applies to *all* channels, disregarding
    // channel usage.  Usage is handled downstream, in the channel frontend.
    // See the module doc in `crates/tor-proto/src/channel/padding.rs`.

    let padding_of_level = |level| padding_parameters(level, netdir);
    let send_padding = padding_of_level(config.padding)?;
    let padding_default = padding_of_level(PaddingLevel::default())?;

    let send_padding = match dormancy {
        Dormancy::Active => send_padding,
        Dormancy::Dormant => None,
    };

    let recv_padding = match config.padding {
        PaddingLevel::Reduced => None,
        PaddingLevel::Normal => send_padding,
        PaddingLevel::None => None,
    };

    // Whether the inbound padding approach we are to use, is the same as the default
    // derived from the netdir (disregarding our config and dormancy).
    //
    // Ie, whether the parameters we want are precisely those that a peer would
    // use by default (assuming they have the same view of the netdir as us).
    let recv_equals_default = recv_padding == padding_default;

    let padding_negotiate = if recv_equals_default {
        // Our padding approach is the same as peers' defaults.  So the PADDING_NEGOTIATE
        // message we need to send is the START(0,0).  (The channel frontend elides an
        // initial message of this form, - see crates/tor-proto/src/channel.rs::note_usage.)
        //
        // If the netdir default is no padding, and we previously negotiated
        // padding being enabled, and now want to disable it, we would send
        // START(0,0) rather than STOP.  That is OK (even, arguably, right).
        PaddingNegotiate::start_default()
    } else {
        match recv_padding {
            None => PaddingNegotiate::stop(),
            Some(params) => params.padding_negotiate_cell()?,
        }
    };

    let mut update = channels_params
        .start_update()
        .padding_enable(send_padding.is_some())
        .padding_negotiate(padding_negotiate);
    if let Some(params) = send_padding {
        update = update.padding_parameters(params);
    }
    let update = update.finish();

    Ok(update)
}

/// Given a `NetDirExtract` and whether we're reducing padding, return a `PaddingParameters`
///
/// With `PaddingLevel::None`, or the consensus specifies no padding, will return `None`;
/// but does not account for other reasons why padding might be enabled/disabled.
fn padding_parameters(
    config: PaddingLevel,
    netdir: &NetParamsExtract,
) -> StdResult<Option<PaddingParameters>, tor_error::Bug> {
    let reduced = match config {
        PaddingLevel::Reduced => true,
        PaddingLevel::Normal => false,
        PaddingLevel::None => return Ok(None),
    };

    padding_parameters_builder(reduced, netdir)
        .unwrap_or_else(|e: &str| {
            info!(
                "consensus channel padding parameters wrong, using defaults: {}",
                &e,
            );
            Some(PaddingParametersBuilder::default())
        })
        .map(|p| {
            p.build()
                .map_err(into_internal!("failed to build padding parameters"))
        })
        .transpose()
}

/// Given a `NetDirExtract` and whether we're reducing padding,
/// return a `PaddingParametersBuilder`
///
/// If the consensus specifies no padding, will return `None`;
/// but does not account for other reasons why padding might be enabled/disabled.
///
/// If `Err`, the string is a description of what is wrong with the parameters;
/// the caller should use `PaddingParameters::Default`.
fn padding_parameters_builder(
    reduced: bool,
    netdir: &NetParamsExtract,
) -> StdResult<Option<PaddingParametersBuilder>, &'static str> {
    let mut p = PaddingParametersBuilder::default();

    let low = netdir.pad_low(reduced);
    let high = netdir.pad_high(reduced);
    if low > high {
        return Err("low > high");
    }
    if low.as_millis() == 0 && high.as_millis() == 0 {
        // Zeroes for both channel padding consensus parameters means "don't send padding".
        // padding-spec.txt s2.6, see description of `nf_ito_high`.
        return Ok(None);
    }
    p.low(low);
    p.high(high);
    Ok::<_, &'static str>(Some(p))
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::factory::BootstrapReporter;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;

    fn new_test_state() -> MgrState<FakeChannelFactory> {
        MgrState::new(
            FakeChannelFactory::default(),
            ChannelConfig::default(),
            Default::default(),
            &Default::default(),
        )
    }

    #[derive(Clone, Debug, Default)]
    struct FakeChannelFactory {}

    #[allow(clippy::diverging_sub_expression)] // for unimplemented!() + async_trait
    #[async_trait]
    impl AbstractChannelFactory for FakeChannelFactory {
        type Channel = FakeChannel;

        type BuildSpec = tor_linkspec::OwnedChanTarget;

        async fn build_channel(
            &self,
            _target: &Self::BuildSpec,
            _reporter: BootstrapReporter,
        ) -> Result<FakeChannel> {
            unimplemented!()
        }
    }

    #[derive(Clone, Debug)]
    struct FakeChannel {
        ed_ident: Ed25519Identity,
        usable: bool,
        unused_duration: Option<u64>,
        params_update: Arc<Mutex<Option<Arc<ChannelPaddingInstructionsUpdates>>>>,
    }
    impl AbstractChannel for FakeChannel {
        fn is_usable(&self) -> bool {
            self.usable
        }
        fn duration_unused(&self) -> Option<Duration> {
            self.unused_duration.map(Duration::from_secs)
        }
        fn reparameterize(
            &self,
            update: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            *self.params_update.lock().unwrap() = Some(update);
            Ok(())
        }
        fn engage_padding_activities(&self) {}
    }
    impl tor_linkspec::HasRelayIds for FakeChannel {
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
    /// Get a fake ed25519 identity from the first byte of a string.
    fn str_to_ed(s: &str) -> Ed25519Identity {
        let byte = s.as_bytes()[0];
        [byte; 32].into()
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: true,
            unused_duration: None,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration: Duration::from_secs(180),
        })
    }
    fn ch_with_details(
        ident: &'static str,
        max_unused_duration: Duration,
        unused_duration: Option<u64>,
    ) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: true,
            unused_duration,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration,
        })
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: false,
            unused_duration: None,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration: Duration::from_secs(180),
        })
    }

    #[test]
    fn rmv_unusable() -> Result<()> {
        let map = new_test_state();

        map.with_channels(|map| {
            map.insert(closed("machen"));
            map.insert(ch("feinen"));
            map.insert(closed("wir"));
            map.insert(ch("Fug"));
        })?;

        map.remove_unusable().unwrap();

        map.with_channels(|map| {
            assert!(map.by_id(&str_to_ed("m")).is_none());
            assert!(map.by_id(&str_to_ed("w")).is_none());
            assert!(map.by_id(&str_to_ed("f")).is_some());
            assert!(map.by_id(&str_to_ed("F")).is_some());
        })?;

        Ok(())
    }

    #[test]
    fn reparameterize_via_netdir() -> Result<()> {
        let map = new_test_state();

        // Set some non-default parameters so that we can tell when an update happens
        let _ = map
            .inner
            .lock()
            .unwrap()
            .channels_params
            .start_update()
            .padding_parameters(
                PaddingParametersBuilder::default()
                    .low(1234.into())
                    .build()
                    .unwrap(),
            )
            .finish();

        map.with_channels(|map| {
            map.insert(ch("track"));
        })?;

        let netdir = tor_netdir::testnet::construct_netdir()
            .unwrap_if_sufficient()
            .unwrap();
        let netdir = Arc::new(netdir);

        let with_ch = |f: &dyn Fn(&FakeChannel)| {
            let inner = map.inner.lock().unwrap();
            let ch = inner.channels.by_ed25519(&str_to_ed("t"));
            let ch = ch.unwrap().unwrap_open();
            f(ch);
        };

        eprintln!("-- process a default netdir, which should send an update --");
        map.reconfigure_general(None, None, netdir.clone()).unwrap();
        with_ch(&|ch| {
            assert_eq!(
                format!("{:?}", ch.params_update.lock().unwrap().take().unwrap()),
                // evade field visibility by (ab)using Debug impl
                "ChannelPaddingInstructionsUpdates { padding_enable: None, \
                    padding_parameters: Some(Parameters { \
                        low: IntegerMilliseconds { value: 1500 }, \
                        high: IntegerMilliseconds { value: 9500 } }), \
                    padding_negotiate: None }"
            );
        });
        eprintln!();

        eprintln!("-- process a default netdir again, which should *not* send an update --");
        map.reconfigure_general(None, None, netdir).unwrap();
        with_ch(&|ch| assert!(ch.params_update.lock().unwrap().is_none()));

        Ok(())
    }

    #[test]
    fn expire_channels() -> Result<()> {
        let map = new_test_state();

        // Channel that has been unused beyond max duration allowed is expired
        map.with_channels(|map| {
            map.insert(ch_with_details(
                "wello",
                Duration::from_secs(180),
                Some(181),
            ))
        })?;

        // Minimum value of max unused duration is 180 seconds
        assert_eq!(180, map.expire_channels().as_secs());
        map.with_channels(|map| {
            assert!(map.by_ed25519(&str_to_ed("w")).is_none());
        })?;

        let map = new_test_state();

        // Channel that has been unused for shorter than max unused duration
        map.with_channels(|map| {
            map.insert(ch_with_details(
                "wello",
                Duration::from_secs(180),
                Some(120),
            ));

            map.insert(ch_with_details(
                "yello",
                Duration::from_secs(180),
                Some(170),
            ));

            // Channel that has been unused beyond max duration allowed is expired
            map.insert(ch_with_details(
                "gello",
                Duration::from_secs(180),
                Some(181),
            ));

            // Closed channel should be retained
            map.insert(closed("hello"));
        })?;

        // Return duration until next channel expires
        assert_eq!(10, map.expire_channels().as_secs());
        map.with_channels(|map| {
            assert!(map.by_ed25519(&str_to_ed("w")).is_some());
            assert!(map.by_ed25519(&str_to_ed("y")).is_some());
            assert!(map.by_ed25519(&str_to_ed("h")).is_some());
            assert!(map.by_ed25519(&str_to_ed("g")).is_none());
        })?;
        Ok(())
    }
}
