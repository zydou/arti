//! Simple implementation for the internal map state of a ChanMgr.

use std::time::Duration;

use super::{AbstractChannel, Pending};
use crate::{ChannelConfig, Dormancy, Error, Result};

use std::collections::{hash_map, HashMap};
use std::result::Result as StdResult;
use std::sync::Arc;
use tor_cell::chancell::msg::PaddingNegotiate;
use tor_config::PaddingLevel;
use tor_error::{internal, into_internal};
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

// TODO pt-client:
//
// This map code will no longer work in the bridge setting.  We need to update
// our internal map of channels, so that we can look them up not only by Ed25519
// identity, but by RSA identity too.  We also need a way to be able to get a
// channel only if it matches a specific ChanTarget in its address and transport
// and keys.

/// A map from channel id to channel state, plus necessary auxiliary state
///
/// We make this a separate type instead of just using
/// `Mutex<HashMap<...>>` to limit the amount of code that can see and
/// lock the Mutex here.  (We're using a blocking mutex close to async
/// code, so we need to be careful.)
pub(crate) struct ChannelMap<C: AbstractChannel> {
    /// The data, within a lock
    inner: std::sync::Mutex<Inner<C>>,
}

/// A map from channel id to channel state, plus necessary auxiliary state - inside lock
struct Inner<C: AbstractChannel> {
    /// A map from identity to channel, or to pending channel status.
    ///
    /// (Danger: this uses a blocking mutex close to async code.  This mutex
    /// must never be held while an await is happening.)
    channels: HashMap<C::Ident, ChannelState<C>>,

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
    /// Updated via `ChanMgr::set_dormancy` and hence `ChannelMap::reconfigure_general`,
    /// which then uses it to calculate how to reconfigure the channels.
    dormancy: Dormancy,
}

/// Structure that can only be constructed from within this module.
/// Used to make sure that only we can construct ChannelState::Poisoned.
pub(crate) struct Priv {
    /// (This field is private)
    _unused: (),
}

/// The state of a channel (or channel build attempt) within a map.
pub(crate) enum ChannelState<C> {
    /// An open channel.
    ///
    /// This channel might not be usable: it might be closing or
    /// broken.  We need to check its is_usable() method before
    /// yielding it to the user.
    Open(OpenEntry<C>),
    /// A channel that's getting built.
    Building(Pending<C>),
    /// A temporary invalid state.
    ///
    /// We insert this into the map temporarily as a placeholder in
    /// `change_state()`.
    Poisoned(Priv),
}

/// An open channel entry.
#[derive(Clone)]
pub(crate) struct OpenEntry<C> {
    /// The underlying open channel.
    pub(crate) channel: C,
    /// The maximum unused duration allowed for this channel.
    pub(crate) max_unused_duration: Duration,
}

impl<C: Clone> ChannelState<C> {
    /// Create a new shallow copy of this ChannelState.
    #[cfg(test)]
    fn clone_ref(&self) -> Result<Self> {
        use ChannelState::*;
        match self {
            Open(ent) => Ok(Open(ent.clone())),
            Building(pending) => Ok(Building(pending.clone())),
            Poisoned(_) => Err(Error::Internal(internal!("Poisoned state in channel map"))),
        }
    }

    /// For testing: either give the Open channel inside this state,
    /// or panic if there is none.
    #[cfg(test)]
    fn unwrap_open(&mut self) -> &mut C {
        match self {
            ChannelState::Open(ent) => &mut ent.channel,
            _ => panic!("Not an open channel"),
        }
    }
}

/// Type of the `nf_ito_*` netdir parameters, convenience alias
type NfIto = IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>>;

/// Extract from a `NetDarameters` which we need, conveniently organised for our processing
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
    /// Return the padding timer prameter low end, for reduced-ness `reduced`, as a `u32`
    fn pad_low(&self, reduced: bool) -> IntegerMilliseconds<u32> {
        self.pad_get(reduced, 0)
    }
    /// Return the padding timer prameter high end, for reduced-ness `reduced`, as a `u32`
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
    /// Return an error if `ident`is definitely not a matching
    /// matching identity for this state.
    fn check_ident(&self, ident: &C::Ident) -> Result<()> {
        match self {
            ChannelState::Open(ent) => {
                if ent.channel.ident() == ident {
                    Ok(())
                } else {
                    Err(Error::Internal(internal!("Identity mismatch")))
                }
            }
            ChannelState::Poisoned(_) => {
                Err(Error::Internal(internal!("Poisoned state in channel map")))
            }
            ChannelState::Building(_) => Ok(()),
        }
    }

    /// Return true if a channel is ready to expire.
    /// Update `expire_after` if a smaller duration than
    /// the given value is required to expire this channel.
    fn ready_to_expire(&self, expire_after: &mut Duration) -> bool {
        if let ChannelState::Open(ent) = self {
            let unused_duration = ent.channel.duration_unused();
            if let Some(unused_duration) = unused_duration {
                let max_unused_duration = ent.max_unused_duration;

                if let Some(remaining) = max_unused_duration.checked_sub(unused_duration) {
                    *expire_after = std::cmp::min(*expire_after, remaining);
                    false
                } else {
                    true
                }
            } else {
                // still in use
                false
            }
        } else {
            false
        }
    }
}

impl<C: AbstractChannel> ChannelMap<C> {
    /// Create a new empty ChannelMap.
    pub(crate) fn new(
        config: ChannelConfig,
        dormancy: Dormancy,
        netparams: &NetParameters,
    ) -> Self {
        let mut channels_params = ChannelPaddingInstructions::default();
        let netparams = NetParamsExtract::from(netparams);
        let update = parameterize(&mut channels_params, &config, dormancy, &netparams)
            .unwrap_or_else(|e: tor_error::Bug| panic!("bug detected on startup: {:?}", e));
        let _: Option<_> = update; // there are no channels yet, that would need to be told

        ChannelMap {
            inner: std::sync::Mutex::new(Inner {
                channels: HashMap::new(),
                config,
                channels_params,
                dormancy,
            }),
        }
    }

    /// Return the channel state for the given identity, if any.
    #[cfg(test)]
    pub(crate) fn get(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let inner = self.inner.lock()?;
        inner
            .channels
            .get(ident)
            .map(ChannelState::clone_ref)
            .transpose()
    }

    /// Replace the channel state for `ident` with `newval`, and return the
    /// previous value if any.
    #[cfg(test)]
    pub(crate) fn replace(
        &self,
        ident: C::Ident,
        newval: ChannelState<C>,
    ) -> Result<Option<ChannelState<C>>> {
        newval.check_ident(&ident)?;
        let mut inner = self.inner.lock()?;
        Ok(inner.channels.insert(ident, newval))
    }

    /// Replace the channel state for `ident` with the return value from `func`,
    /// and return the previous value if any.
    ///
    /// Passes a snapshot of the current global channels parameters to `func`.
    /// If those parameters are copied by `func` into an [`AbstractChannel`]
    /// `func` must ensure that that `AbstractChannel` is returned,
    /// so that it will be properly registered and receive params updates.
    pub(crate) fn replace_with_params<F>(
        &self,
        ident: C::Ident,
        func: F,
    ) -> Result<Option<ChannelState<C>>>
    where
        F: FnOnce(&ChannelPaddingInstructions) -> Result<ChannelState<C>>,
    {
        let mut inner = self.inner.lock()?;
        let newval = func(&inner.channels_params)?;
        newval.check_ident(&ident)?;
        Ok(inner.channels.insert(ident, newval))
    }

    /// Remove and return the state for `ident`, if any.
    pub(crate) fn remove(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let mut inner = self.inner.lock()?;
        Ok(inner.channels.remove(ident))
    }

    /// Remove every unusable state from the map.
    #[cfg(test)]
    pub(crate) fn remove_unusable(&self) -> Result<()> {
        let mut inner = self.inner.lock()?;
        inner.channels.retain(|_, state| match state {
            ChannelState::Poisoned(_) => false,
            ChannelState::Open(ent) => ent.channel.is_usable(),
            ChannelState::Building(_) => true,
        });
        Ok(())
    }

    /// Replace the state whose identity is `ident` with a new state.
    ///
    /// The provided function `func` is invoked on the old state (if
    /// any), and must return a tuple containing an optional new
    /// state, and an arbitrary return value for this function.
    ///
    /// Because `func` is run while holding the lock on this object,
    /// it should be fast and nonblocking.  In return, you can be sure
    /// that it's running atomically with respect to other accessors
    /// of this map.
    ///
    /// If `func` panics, or if it returns a channel with a different
    /// identity, this position in the map will be become unusable and
    /// future accesses to that position may fail.
    pub(crate) fn change_state<F, V>(&self, ident: &C::Ident, func: F) -> Result<V>
    where
        F: FnOnce(Option<ChannelState<C>>) -> (Option<ChannelState<C>>, V),
    {
        use hash_map::Entry::*;
        let mut inner = self.inner.lock()?;
        let entry = inner.channels.entry(ident.clone());
        match entry {
            Occupied(mut occupied) => {
                // Temporarily replace the entry for this identity with
                // a poisoned entry.
                let mut oldent = ChannelState::Poisoned(Priv { _unused: () });
                std::mem::swap(occupied.get_mut(), &mut oldent);
                let (newval, output) = func(Some(oldent));
                match newval {
                    Some(mut newent) => {
                        newent.check_ident(ident)?;
                        std::mem::swap(occupied.get_mut(), &mut newent);
                    }
                    None => {
                        occupied.remove();
                    }
                };
                Ok(output)
            }
            Vacant(vacant) => {
                let (newval, output) = func(None);
                if let Some(newent) = newval {
                    newent.check_ident(ident)?;
                    vacant.insert(newent);
                }
                Ok(output)
            }
        }
    }

    /// Reconfigure all channels as necessary
    ///
    /// (By reparameterising channels as needed)
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
            .map_err(|_| internal!("poisonned channel manager"))?;
        let mut inner = &mut *inner;

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

        for channel in inner.channels.values_mut() {
            let channel = match channel {
                CS::Open(OpenEntry { channel, .. }) => channel,
                CS::Building(_) | CS::Poisoned(_) => continue,
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
            .retain(|_id, chan| !chan.ready_to_expire(&mut ret));
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
///  1. During chanmgr creation, it is called once to analyse the initial state
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
        .unwrap_or_else(|e| {
            info!(
                "consensus channel padding parameters wrong, using defaults: {}",
                &e
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
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use std::sync::Arc;
    use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;

    fn new_test_channel_map<C: AbstractChannel>() -> ChannelMap<C> {
        ChannelMap::new(
            ChannelConfig::default(),
            Default::default(),
            &Default::default(),
        )
    }

    #[derive(Eq, PartialEq, Clone, Debug)]
    struct FakeChannel {
        ident: &'static str,
        usable: bool,
        unused_duration: Option<u64>,
        params_update: Option<Arc<ChannelPaddingInstructionsUpdates>>,
    }
    impl AbstractChannel for FakeChannel {
        type Ident = u8;
        fn ident(&self) -> &Self::Ident {
            &self.ident.as_bytes()[0]
        }
        fn is_usable(&self) -> bool {
            self.usable
        }
        fn duration_unused(&self) -> Option<Duration> {
            self.unused_duration.map(Duration::from_secs)
        }
        fn reparameterize(
            &mut self,
            update: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            self.params_update = Some(update);
            Ok(())
        }
        fn engage_padding_activities(&self) {}
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ident,
            usable: true,
            unused_duration: None,
            params_update: None,
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
            ident,
            usable: true,
            unused_duration,
            params_update: None,
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration,
        })
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ident,
            usable: false,
            unused_duration: None,
            params_update: None,
        };
        ChannelState::Open(OpenEntry {
            channel,
            max_unused_duration: Duration::from_secs(180),
        })
    }

    #[test]
    fn simple_ops() {
        let map = new_test_channel_map();
        use ChannelState::Open;

        assert!(map.replace(b'h', ch("hello")).unwrap().is_none());
        assert!(map.replace(b'w', ch("wello")).unwrap().is_none());

        match map.get(&b'h') {
            Ok(Some(Open(ent))) if ent.channel.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.get(&b'W').unwrap().is_none());

        match map.replace(b'h', ch("hebbo")) {
            Ok(Some(Open(ent))) if ent.channel.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.remove(&b'Z').unwrap().is_none());
        match map.remove(&b'h') {
            Ok(Some(Open(ent))) if ent.channel.ident == "hebbo" => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rmv_unusable() {
        let map = new_test_channel_map();

        map.replace(b'm', closed("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'w', closed("wir")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        map.remove_unusable().unwrap();

        assert!(map.get(&b'm').unwrap().is_none());
        assert!(map.get(&b'w').unwrap().is_none());
        assert!(map.get(&b'f').unwrap().is_some());
        assert!(map.get(&b'F').unwrap().is_some());
    }

    #[test]
    fn change() {
        let map = new_test_channel_map();

        map.replace(b'w', ch("wir")).unwrap();
        map.replace(b'm', ch("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        //  Replace Some with Some.
        let (old, v) = map
            .change_state(&b'F', |state| (Some(ch("FUG")), (state, 99_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "Fug");
        assert_eq!(v, 99);
        assert_eq!(map.get(&b'F').unwrap().unwrap().unwrap_open().ident, "FUG");

        // Replace Some with None.
        let (old, v) = map
            .change_state(&b'f', |state| (None, (state, 123_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "feinen");
        assert_eq!(v, 123);
        assert!(map.get(&b'f').unwrap().is_none());

        // Replace None with Some.
        let (old, v) = map
            .change_state(&b'G', |state| (Some(ch("Geheimnisse")), (state, "Hi")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "Hi");
        assert_eq!(
            map.get(&b'G').unwrap().unwrap().unwrap_open().ident,
            "Geheimnisse"
        );

        // Replace None with None
        let (old, v) = map
            .change_state(&b'Q', |state| (None, (state, "---")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "---");
        assert!(map.get(&b'Q').unwrap().is_none());

        // Try replacing None with invalid entry (with mismatched ID)
        let e = map.change_state(&b'P', |state| (Some(ch("Geheimnisse")), (state, "Hi")));
        assert!(matches!(e, Err(Error::Internal(_))));
        assert!(matches!(map.get(&b'P'), Ok(None)));

        // Try replacing Some with invalid entry (mismatched ID)
        let e = map.change_state(&b'G', |state| (Some(ch("Wobbledy")), (state, "Hi")));
        assert!(matches!(e, Err(Error::Internal(_))));
        assert!(matches!(map.get(&b'G'), Err(Error::Internal(_))));
    }

    #[test]
    fn reparameterise_via_netdir() {
        let map = new_test_channel_map();

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

        assert!(map.replace(b't', ch("track")).unwrap().is_none());

        let netdir = tor_netdir::testnet::construct_netdir()
            .unwrap_if_sufficient()
            .unwrap();
        let netdir = Arc::new(netdir);

        let with_ch = |f: &dyn Fn(&mut FakeChannel)| {
            let mut inner = map.inner.lock().unwrap();
            let ch = inner.channels.get_mut(&b't').unwrap().unwrap_open();
            f(ch);
        };

        eprintln!("-- process a default netdir, which should send an update --");
        map.reconfigure_general(None, None, netdir.clone()).unwrap();
        with_ch(&|ch| {
            assert_eq!(
                format!("{:?}", ch.params_update.take().unwrap()),
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
        with_ch(&|ch| assert_eq!(ch.params_update, None));
    }

    #[test]
    fn expire_channels() {
        let map = new_test_channel_map();

        // Channel that has been unused beyond max duration allowed is expired
        map.replace(
            b'w',
            ch_with_details("wello", Duration::from_secs(180), Some(181)),
        )
        .unwrap();

        // Minimum value of max unused duration is 180 seconds
        assert_eq!(180, map.expire_channels().as_secs());
        assert!(map.get(&b'w').unwrap().is_none());

        let map = new_test_channel_map();

        // Channel that has been unused for shorter than max unused duration
        map.replace(
            b'w',
            ch_with_details("wello", Duration::from_secs(180), Some(120)),
        )
        .unwrap();

        map.replace(
            b'y',
            ch_with_details("yello", Duration::from_secs(180), Some(170)),
        )
        .unwrap();

        // Channel that has been unused beyond max duration allowed is expired
        map.replace(
            b'g',
            ch_with_details("gello", Duration::from_secs(180), Some(181)),
        )
        .unwrap();

        // Closed channel should be retained
        map.replace(b'h', closed("hello")).unwrap();

        // Return duration until next channel expires
        assert_eq!(10, map.expire_channels().as_secs());
        assert!(map.get(&b'w').unwrap().is_some());
        assert!(map.get(&b'y').unwrap().is_some());
        assert!(map.get(&b'h').unwrap().is_some());
        assert!(map.get(&b'g').unwrap().is_none());
    }
}
