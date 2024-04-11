#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// Glossary:
//     Primary guard
//     Sample
//     confirmed
//     filtered

use futures::channel::mpsc;
use futures::task::SpawnExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};
#[cfg(feature = "bridge-client")]
use tor_error::internal;
use tor_linkspec::{OwnedChanTarget, OwnedCircTarget, RelayId, RelayIdSet};
use tor_netdir::NetDirProvider;
use tor_proto::ClockSkew;
use tor_units::BoundedInt32;
use tracing::{debug, info, trace, warn};

use tor_config::impl_standard_builder;
use tor_config::ReconfigureError;
use tor_config::{define_list_builder_accessors, define_list_builder_helper};
use tor_netdir::{params::NetParameters, NetDir, Relay};
use tor_persist::{DynStorageHandle, StateMgr};
use tor_rtcompat::Runtime;

#[cfg(feature = "bridge-client")]
pub mod bridge;
mod config;
mod daemon;
mod dirstatus;
mod err;
mod events;
pub mod fallback;
mod filter;
mod guard;
mod ids;
mod pending;
mod sample;
mod skew;
mod util;
#[cfg(feature = "vanguards")]
pub mod vanguards;

#[cfg(not(feature = "bridge-client"))]
#[path = "bridge_disabled.rs"]
pub mod bridge;

#[cfg(any(test, feature = "testing"))]
pub use config::testing::TestConfig;

#[cfg(test)]
use tor_async_utils::oneshot;

pub use config::GuardMgrConfig;
pub use err::{GuardMgrConfigError, GuardMgrError, PickGuardError};
pub use events::ClockSkewEvents;
pub use filter::GuardFilter;
pub use ids::FirstHopId;
pub use pending::{GuardMonitor, GuardStatus, GuardUsable};
pub use skew::SkewEstimate;

#[cfg(feature = "vanguards")]
#[cfg_attr(docsrs, doc(cfg(feature = "vanguards")))]
pub use vanguards::VanguardMgrError;

use pending::{PendingRequest, RequestId};
use sample::{GuardSet, Universe, UniverseRef};

use crate::ids::{FirstHopIdInner, GuardId};

/// A "guard manager" that selects and remembers a persistent set of
/// guard nodes.
///
/// This is a "handle"; clones of it share state.
#[derive(Clone)]
pub struct GuardMgr<R: Runtime> {
    /// An asynchronous runtime object.
    ///
    /// GuardMgr uses this runtime for timing, timeouts, and spawning
    /// tasks.
    runtime: R,

    /// Internal state for the guard manager.
    inner: Arc<Mutex<GuardMgrInner>>,
}

/// Helper type that holds the data used by a [`GuardMgr`].
///
/// This would just be a [`GuardMgr`], except that it needs to sit inside
/// a `Mutex` and get accessed by daemon tasks.
struct GuardMgrInner {
    /// Last time when marked all of our primary guards as retriable.
    ///
    /// We keep track of this time so that we can rate-limit
    /// these attempts.
    last_primary_retry_time: Instant,

    /// Persistent guard manager state.
    ///
    /// This object remembers one or more persistent set of guards that we can
    /// use, along with their relative priorities and statuses.
    guards: GuardSets,

    /// The current filter that we're using to decide which guards are
    /// supported.
    //
    // TODO: This field is duplicated in the current active [`GuardSet`]; we
    // should fix that.
    filter: GuardFilter,

    /// Configuration values derived from the consensus parameters.
    ///
    /// This is updated whenever the consensus parameters change.
    params: GuardParams,

    /// A mpsc channel, used to tell the task running in
    /// [`daemon::report_status_events`] about a new event to monitor.
    ///
    /// This uses an `UnboundedSender` so that we don't have to await
    /// while sending the message, which in turn allows the GuardMgr
    /// API to be simpler.  The risk, however, is that there's no
    /// backpressure in the event that the task running
    /// [`daemon::report_status_events`] fails to read from this
    /// channel.
    ctrl: mpsc::UnboundedSender<daemon::Msg>,

    /// Information about guards that we've given out, but where we have
    /// not yet heard whether the guard was successful.
    ///
    /// Upon leaning whether the guard was successful, the pending
    /// requests in this map may be either moved to `waiting`, or
    /// discarded.
    ///
    /// There can be multiple pending requests corresponding to the
    /// same guard.
    pending: HashMap<RequestId, PendingRequest>,

    /// A list of pending requests for which we have heard that the
    /// guard was successful, but we have not yet decided whether the
    /// circuit may be used.
    ///
    /// There can be multiple waiting requests corresponding to the
    /// same guard.
    waiting: Vec<PendingRequest>,

    /// A list of fallback directories used to access the directory system
    /// when no other directory information is yet known.
    fallbacks: fallback::FallbackState,

    /// Location in which to store persistent state.
    storage: DynStorageHandle<GuardSets>,

    /// A sender object to publish changes in our estimated clock skew.
    send_skew: postage::watch::Sender<Option<SkewEstimate>>,

    /// A receiver object to hand out to observers who want to know about
    /// changes in our estimated clock skew.
    recv_skew: events::ClockSkewEvents,

    /// A netdir provider that we can use for adding new guards when
    /// insufficient guards are available.
    ///
    /// This has to be an Option so it can be initialized from None: at the
    /// time a GuardMgr is created, there is no NetDirProvider for it to use.
    netdir_provider: Option<Weak<dyn NetDirProvider>>,

    /// A netdir provider that we can use for discovering bridge descriptors.
    ///
    /// This has to be an Option so it can be initialized from None: at the time
    /// a GuardMgr is created, there is no BridgeDescProvider for it to use.
    #[cfg(feature = "bridge-client")]
    bridge_desc_provider: Option<Weak<dyn bridge::BridgeDescProvider>>,

    /// A list of the bridges that we are configured to use, or "None" if we are
    /// not configured to use bridges.
    #[cfg(feature = "bridge-client")]
    configured_bridges: Option<Arc<[bridge::BridgeConfig]>>,
}

/// A selector that tells us which [`GuardSet`] of several is currently in use.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, strum::EnumIter)]
enum GuardSetSelector {
    /// The default guard set is currently in use: that's the one that we use
    /// when we have no filter installed, or the filter permits most of the
    /// guards on the network.
    #[default]
    Default,
    /// A "restrictive" guard set is currently in use: that's the one that we
    /// use when we have a filter that excludes a large fraction of the guards
    /// on the network.
    Restricted,
    /// The "bridges" guard set is currently in use: we are selecting our guards
    /// from among the universe of configured bridges.
    #[cfg(feature = "bridge-client")]
    Bridges,
}

/// Describes the [`Universe`] that a guard sample should take its guards from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniverseType {
    /// Take information from the network directory.
    NetDir,
    /// Take information from the configured bridges.
    #[cfg(feature = "bridge-client")]
    BridgeSet,
}

impl GuardSetSelector {
    /// Return a description of which [`Universe`] this guard sample should take
    /// its guards from.
    fn universe_type(&self) -> UniverseType {
        match self {
            GuardSetSelector::Default | GuardSetSelector::Restricted => UniverseType::NetDir,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => UniverseType::BridgeSet,
        }
    }
}

/// Persistent state for a guard manager, as serialized to disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GuardSets {
    /// Which set of guards is currently in use?
    #[serde(skip)]
    active_set: GuardSetSelector,

    /// The default set of guards to use.
    ///
    /// We use this one when there is no filter, or the filter permits most of the
    /// guards on the network.
    default: GuardSet,

    /// A guard set to use when we have a restrictive filter.
    #[serde(default)]
    restricted: GuardSet,

    /// A guard set sampled from our configured bridges.
    #[serde(default)]
    #[cfg(feature = "bridge-client")]
    bridges: GuardSet,

    /// Unrecognized fields, including (possibly) other guard sets.
    #[serde(flatten)]
    remaining: HashMap<String, tor_persist::JsonValue>,
}

/// The key (filename) we use for storing our persistent guard state in the
/// `StateMgr`.
///
/// We used to store this in a different format in a filename called
/// "default_guards" (before Arti 0.1.0).
const STORAGE_KEY: &str = "guards";

/// A description of which circuits to retire because of a configuration change.
///
/// TODO(nickm): Eventually we will want to add a "Some" here, to support
/// removing only those circuits that correspond to no-longer-usable guards.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
#[non_exhaustive]
pub enum RetireCircuits {
    /// There's no need to retire any circuits.
    None,
    /// All circuits should be retired.
    All,
}

impl<R: Runtime> GuardMgr<R> {
    /// Create a new "empty" guard manager and launch its background tasks.
    ///
    /// It won't be able to hand out any guards until a [`NetDirProvider`] has
    /// been installed.
    pub fn new<S>(
        runtime: R,
        state_mgr: S,
        config: &impl GuardMgrConfig,
    ) -> Result<Self, GuardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        let (ctrl, rcv) = mpsc::unbounded();
        let storage: DynStorageHandle<GuardSets> = state_mgr.create_handle(STORAGE_KEY);
        // TODO(nickm): We should do something about the old state in
        // `default_guards`.  Probably it would be best to delete it.  We could
        // try to migrate it instead, but that's beyond the stability guarantee
        // that we're getting at this stage of our (pre-0.1) development.
        let state = storage.load()?.unwrap_or_default();

        let (send_skew, recv_skew) = postage::watch::channel();
        let recv_skew = ClockSkewEvents { inner: recv_skew };

        let inner = Arc::new(Mutex::new(GuardMgrInner {
            guards: state,
            filter: GuardFilter::unfiltered(),
            last_primary_retry_time: runtime.now(),
            params: GuardParams::default(),
            ctrl,
            pending: HashMap::new(),
            waiting: Vec::new(),
            fallbacks: config.fallbacks().into(),
            storage,
            send_skew,
            recv_skew,
            netdir_provider: None,
            #[cfg(feature = "bridge-client")]
            bridge_desc_provider: None,
            #[cfg(feature = "bridge-client")]
            configured_bridges: None,
        }));
        #[cfg(feature = "bridge-client")]
        {
            let mut inner = inner.lock().expect("lock poisoned");
            // TODO(nickm): This calls `GuardMgrInner::update`. Will we mind doing so before any
            // providers are configured? I think not, but we should make sure.
            let _: RetireCircuits =
                inner.replace_bridge_config(config, runtime.wallclock(), runtime.now())?;
        }
        {
            let weak_inner = Arc::downgrade(&inner);
            let rt_clone = runtime.clone();
            runtime
                .spawn(daemon::report_status_events(rt_clone, weak_inner, rcv))
                .map_err(|e| GuardMgrError::from_spawn("guard status event reporter", e))?;
        }
        {
            let rt_clone = runtime.clone();
            let weak_inner = Arc::downgrade(&inner);
            runtime
                .spawn(daemon::run_periodic(rt_clone, weak_inner))
                .map_err(|e| GuardMgrError::from_spawn("periodic guard updater", e))?;
        }
        Ok(GuardMgr { runtime, inner })
    }

    /// Install a [`NetDirProvider`] for use by this guard manager.
    ///
    /// It will be used to keep the guards up-to-date with changes from the
    /// network directory, and to find new guards when no NetDir is provided to
    /// select_guard().
    ///
    /// TODO: we should eventually return some kind of a task handle from this
    /// task, even though it is not strictly speaking periodic.
    ///
    /// The guardmgr retains only a `Weak` reference to `provider`,
    /// `install_netdir_provider` downgrades it on entry,
    // TODO add ref to document when https://gitlab.torproject.org/tpo/core/arti/-/issues/624
    // is fixed.  Also, maybe take an owned `Weak` to start with.
    //
    /// # Panics
    ///
    /// Panics if a [`NetDirProvider`] is already installed.
    pub fn install_netdir_provider(
        &self,
        provider: &Arc<dyn NetDirProvider>,
    ) -> Result<(), GuardMgrError> {
        let weak_provider = Arc::downgrade(provider);
        {
            let mut inner = self.inner.lock().expect("Poisoned lock");
            assert!(inner.netdir_provider.is_none());
            inner.netdir_provider = Some(weak_provider.clone());
        }
        let weak_inner = Arc::downgrade(&self.inner);
        let rt_clone = self.runtime.clone();
        self.runtime
            .spawn(daemon::keep_netdir_updated(
                rt_clone,
                weak_inner,
                weak_provider,
            ))
            .map_err(|e| GuardMgrError::from_spawn("periodic guard netdir updater", e))?;
        Ok(())
    }

    /// Configure a new [`bridge::BridgeDescProvider`] for this [`GuardMgr`].
    ///
    /// It will be used to learn about changes in the set of available bridge
    /// descriptors; we'll inform it whenever our desired set of bridge
    /// descriptors changes.
    ///
    /// TODO: Same todo as in `install_netdir_provider` about task handles.
    ///
    /// # Panics
    ///
    /// Panics if a [`bridge::BridgeDescProvider`] is already installed.
    #[cfg(feature = "bridge-client")]
    pub fn install_bridge_desc_provider(
        &self,
        provider: &Arc<dyn bridge::BridgeDescProvider>,
    ) -> Result<(), GuardMgrError> {
        let weak_provider = Arc::downgrade(provider);
        {
            let mut inner = self.inner.lock().expect("Poisoned lock");
            assert!(inner.bridge_desc_provider.is_none());
            inner.bridge_desc_provider = Some(weak_provider.clone());
        }

        let weak_inner = Arc::downgrade(&self.inner);
        let rt_clone = self.runtime.clone();
        self.runtime
            .spawn(daemon::keep_bridge_descs_updated(
                rt_clone,
                weak_inner,
                weak_provider,
            ))
            .map_err(|e| GuardMgrError::from_spawn("periodic guard netdir updater", e))?;

        Ok(())
    }

    /// Flush our current guard state to the state manager, if there
    /// is any unsaved state.
    pub fn store_persistent_state(&self) -> Result<(), GuardMgrError> {
        let inner = self.inner.lock().expect("Poisoned lock");
        trace!("Flushing guard state to disk.");
        inner.storage.store(&inner.guards)?;
        Ok(())
    }

    /// Reload state from the state manager.
    ///
    /// We only call this method if we _don't_ have the lock on the state
    /// files.  If we have the lock, we only want to save.
    pub fn reload_persistent_state(&self) -> Result<(), GuardMgrError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        if let Some(new_guards) = inner.storage.load()? {
            inner.replace_guards_with(new_guards, self.runtime.wallclock(), self.runtime.now());
        }
        Ok(())
    }

    /// Switch from having an unowned persistent state to having an owned one.
    ///
    /// Requires that we hold the lock on the state files.
    pub fn upgrade_to_owned_persistent_state(&self) -> Result<(), GuardMgrError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        debug_assert!(inner.storage.can_store());
        let new_guards = inner.storage.load()?.unwrap_or_default();
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        inner.replace_guards_with(new_guards, wallclock, now);
        Ok(())
    }

    /// Return true if `netdir` has enough information to safely become our new netdir.
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        if inner.guards.active_set.universe_type() != UniverseType::NetDir {
            // If we aren't using the netdir, this isn't something we want to look at.
            return true;
        }
        inner
            .guards
            .active_guards_mut()
            .n_primary_without_id_info_in(netdir)
            == 0
    }

    /// Mark every guard as potentially retriable, regardless of how recently we
    /// failed to connect to it.
    pub fn mark_all_guards_retriable(&self) {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.guards.active_guards_mut().mark_all_guards_retriable();
    }

    /// Configure this guardmgr to use a fixed [`NetDir`] instead of a provider.
    ///
    /// This function is for testing only, and is exclusive with
    /// `install_netdir_provider`.
    ///
    /// # Panics
    ///
    /// Panics if any [`NetDirProvider`] has already been installed.
    #[cfg(any(test, feature = "testing"))]
    pub fn install_test_netdir(&self, netdir: &NetDir) {
        use tor_netdir::testprovider::TestNetDirProvider;
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        let netdir_provider: Arc<dyn NetDirProvider> =
            Arc::new(TestNetDirProvider::from(netdir.clone()));
        self.install_netdir_provider(&netdir_provider)
            .expect("Couldn't install testing network provider");

        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.update(wallclock, now);
    }

    /// Replace the configuration in this `GuardMgr` with `config`.
    pub fn reconfigure(
        &self,
        config: &impl GuardMgrConfig,
    ) -> Result<RetireCircuits, ReconfigureError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        // Change the set of configured fallbacks.
        {
            let mut fallbacks: fallback::FallbackState = config.fallbacks().into();
            std::mem::swap(&mut inner.fallbacks, &mut fallbacks);
            inner.fallbacks.take_status_from(fallbacks);
        }
        // If we are built to use bridges, change the bridge configuration.
        #[cfg(feature = "bridge-client")]
        {
            let wallclock = self.runtime.wallclock();
            let now = self.runtime.now();
            Ok(inner.replace_bridge_config(config, wallclock, now)?)
        }
        // If we are built to use bridges, change the bridge configuration.
        #[cfg(not(feature = "bridge-client"))]
        {
            Ok(RetireCircuits::None)
        }
    }

    /// Replace the current [`GuardFilter`] used by this `GuardMgr`.
    // TODO should this be part of the config?
    pub fn set_filter(&self, filter: GuardFilter) {
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.set_filter(filter, wallclock, now);
    }

    /// Select a guard for a given [`GuardUsage`].
    ///
    /// On success, we return a [`FirstHop`] object to identify which
    /// guard we have picked, a [`GuardMonitor`] object that the
    /// caller can use to report whether its attempt to use the guard
    /// succeeded or failed, and a [`GuardUsable`] future that the
    /// caller can use to decide whether a circuit built through the
    /// guard is actually safe to use.
    ///
    /// That last point is important: It's okay to build a circuit
    /// through the guard returned by this function, but you can't
    /// actually use it for traffic unless the [`GuardUsable`] future
    /// yields "true".
    pub fn select_guard(
        &self,
        usage: GuardUsage,
    ) -> Result<(FirstHop, GuardMonitor, GuardUsable), PickGuardError> {
        let now = self.runtime.now();
        let wallclock = self.runtime.wallclock();

        let mut inner = self.inner.lock().expect("Poisoned lock");

        // (I am not 100% sure that we need to consider_all_retries here, but
        // it should _probably_ not hurt.)
        inner.guards.active_guards_mut().consider_all_retries(now);

        let (origin, guard) = inner.select_guard_with_expand(&usage, now, wallclock)?;
        trace!(?guard, ?usage, "Guard selected");

        let (usable, usable_sender) = if origin.usable_immediately() {
            (GuardUsable::new_usable_immediately(), None)
        } else {
            let (u, snd) = GuardUsable::new_uncertain();
            (u, Some(snd))
        };
        let request_id = pending::RequestId::next();
        let ctrl = inner.ctrl.clone();
        let monitor = GuardMonitor::new(request_id, ctrl);

        // Note that the network can be down even if all the primary guards
        // are not yet marked as unreachable.  But according to guard-spec we
        // don't want to acknowledge the net as down before that point, since
        // we don't mark all the primary guards as retriable unless
        // we've been forced to non-primary guards.
        let net_has_been_down =
            if let Some(duration) = tor_proto::time_since_last_incoming_traffic() {
                inner
                    .guards
                    .active_guards_mut()
                    .all_primary_guards_are_unreachable()
                    && duration >= inner.params.internet_down_timeout
            } else {
                // TODO: Is this the correct behavior in this case?
                false
            };

        let pending_request = pending::PendingRequest::new(
            guard.first_hop_id(),
            usage,
            usable_sender,
            net_has_been_down,
        );
        inner.pending.insert(request_id, pending_request);

        match &guard.sample {
            Some(sample) => {
                let guard_id = GuardId::from_relay_ids(&guard);
                inner
                    .guards
                    .guards_mut(sample)
                    .record_attempt(&guard_id, now);
            }
            None => {
                // We don't record attempts for fallbacks; we only care when
                // they have failed.
            }
        }

        Ok((guard, monitor, usable))
    }

    /// Record that _after_ we built a circuit with a guard, something described
    /// in `external_failure` went wrong with it.
    pub fn note_external_failure<T>(&self, identity: &T, external_failure: ExternalActivity)
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        let now = self.runtime.now();
        let mut inner = self.inner.lock().expect("Poisoned lock");
        let ids = inner.lookup_ids(identity);
        for id in ids {
            match &id.0 {
                FirstHopIdInner::Guard(sample, id) => {
                    inner
                        .guards
                        .guards_mut(sample)
                        .record_failure(id, Some(external_failure), now);
                }
                FirstHopIdInner::Fallback(id) => {
                    if external_failure == ExternalActivity::DirCache {
                        inner.fallbacks.note_failure(id, now);
                    }
                }
            }
        }
    }

    /// Record that _after_ we built a circuit with a guard, some activity
    /// described in `external_activity` was successful with it.
    pub fn note_external_success<T>(&self, identity: &T, external_activity: ExternalActivity)
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        let mut inner = self.inner.lock().expect("Poisoned lock");

        inner.record_external_success(identity, external_activity, self.runtime.wallclock());
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub fn skew_events(&self) -> ClockSkewEvents {
        let inner = self.inner.lock().expect("Poisoned lock");
        inner.recv_skew.clone()
    }

    /// Ensure that the message queue is flushed before proceeding to
    /// the next step.  Used for testing.
    #[cfg(test)]
    async fn flush_msg_queue(&self) {
        let (snd, rcv) = oneshot::channel();
        let pingmsg = daemon::Msg::Ping(snd);
        {
            let inner = self.inner.lock().expect("Poisoned lock");
            inner
                .ctrl
                .unbounded_send(pingmsg)
                .expect("Guard observer task exited prematurely.");
        }
        let _ = rcv.await;
    }
}

/// An activity that can succeed or fail, and whose success or failure can be
/// attributed to a guard.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExternalActivity {
    /// The activity of using the guard as a directory cache.
    DirCache,
}

impl GuardSets {
    /// Return a reference to the currently active set of guards.
    ///
    /// (That's easy enough for now, since there is never more than one set of
    /// guards.  But eventually that will change, as we add support for more
    /// complex filter types, and for bridge relays. Those will use separate
    /// `GuardSet` instances, and this accessor will choose the right one.)
    fn active_guards(&self) -> &GuardSet {
        self.guards(&self.active_set)
    }

    /// Return the set of guards corresponding to the provided selector.
    fn guards(&self, selector: &GuardSetSelector) -> &GuardSet {
        match selector {
            GuardSetSelector::Default => &self.default,
            GuardSetSelector::Restricted => &self.restricted,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => &self.bridges,
        }
    }

    /// Return a mutable reference to the currently active set of guards.
    fn active_guards_mut(&mut self) -> &mut GuardSet {
        self.guards_mut(&self.active_set.clone())
    }

    /// Return a mutable reference to the set of guards corresponding to the
    /// provided selector.
    fn guards_mut(&mut self, selector: &GuardSetSelector) -> &mut GuardSet {
        match selector {
            GuardSetSelector::Default => &mut self.default,
            GuardSetSelector::Restricted => &mut self.restricted,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => &mut self.bridges,
        }
    }

    /// Update all non-persistent state for the guards in this object with the
    /// state in `other`.
    fn copy_status_from(&mut self, mut other: GuardSets) {
        use strum::IntoEnumIterator;
        for sample in GuardSetSelector::iter() {
            self.guards_mut(&sample)
                .copy_ephemeral_status_into_newly_loaded_state(std::mem::take(
                    other.guards_mut(&sample),
                ));
        }
        self.active_set = other.active_set;
    }
}

impl GuardMgrInner {
    /// Look up the latest [`NetDir`] (if there is one) from our
    /// [`NetDirProvider`] (if we have one).
    fn timely_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir_provider
            .as_ref()
            .and_then(Weak::upgrade)
            .and_then(|np| np.timely_netdir().ok())
    }

    /// Look up the latest [`BridgeDescList`](bridge::BridgeDescList) (if there
    /// is one) from our [`BridgeDescProvider`](bridge::BridgeDescProvider) (if
    /// we have one).
    #[cfg(feature = "bridge-client")]
    fn latest_bridge_desc_list(&self) -> Option<Arc<bridge::BridgeDescList>> {
        self.bridge_desc_provider
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|bp| bp.bridges())
    }

    /// Run a function that takes `&mut self` and an optional NetDir.
    ///
    /// We try to use the netdir from our [`NetDirProvider`] (if we have one).
    /// Therefore, although its _parameters_ are suitable for every
    /// [`GuardSet`], its _contents_ might not be. For those, call
    /// [`with_opt_universe`](Self::with_opt_universe) instead.
    //
    // This function exists to handle the lifetime mess where sometimes the
    // resulting NetDir will borrow from `netdir`, and sometimes it will borrow
    // from an Arc returned by `self.latest_netdir()`.
    fn with_opt_netdir<F, T>(&mut self, func: F) -> T
    where
        F: FnOnce(&mut Self, Option<&NetDir>) -> T,
    {
        if let Some(nd) = self.timely_netdir() {
            func(self, Some(nd.as_ref()))
        } else {
            func(self, None)
        }
    }

    /// Return the latest `BridgeSet` based on our `BridgeDescProvider` and our
    /// configured bridges.
    ///
    /// Returns `None` if we are not configured to use bridges.
    #[cfg(feature = "bridge-client")]
    fn latest_bridge_set(&self) -> Option<bridge::BridgeSet> {
        let bridge_config = self.configured_bridges.as_ref()?.clone();
        let bridge_descs = self.latest_bridge_desc_list();
        Some(bridge::BridgeSet::new(bridge_config, bridge_descs))
    }

    /// Run a function that takes `&mut self` and an optional [`UniverseRef`].
    ///
    /// We try to get a universe from the appropriate source for the current
    /// active guard set.
    fn with_opt_universe<F, T>(&mut self, func: F) -> T
    where
        F: FnOnce(&mut Self, Option<&UniverseRef>) -> T,
    {
        // TODO: it might be nice to make `func` take an GuardSet and a set of
        // parameters, so we can't get the active set wrong. Doing that will
        // require a fair amount of refactoring so that the borrow checker is
        // happy, however.
        match self.guards.active_set.universe_type() {
            UniverseType::NetDir => {
                if let Some(nd) = self.timely_netdir() {
                    func(self, Some(&UniverseRef::NetDir(nd)))
                } else {
                    func(self, None)
                }
            }
            #[cfg(feature = "bridge-client")]
            UniverseType::BridgeSet => func(
                self,
                self.latest_bridge_set()
                    .map(UniverseRef::BridgeSet)
                    .as_ref(),
            ),
        }
    }

    /// Update the status of all guards in the active set, based on the passage
    /// of time, our configuration, and the relevant Universe for our active
    /// set.
    fn update(&mut self, wallclock: SystemTime, now: Instant) {
        self.with_opt_netdir(|this, netdir| {
            // Here we update our parameters from the latest NetDir, and check
            // whether we need to change to a (non)-restrictive GuardSet based
            // on those parameters and our configured filter.
            //
            // This uses a NetDir unconditionally, since we always want to take
            // the network parameters our parameters from the consensus even if
            // the guards themselves are from a BridgeSet.
            this.update_active_set_params_and_filter(netdir);
        });
        self.with_opt_universe(|this, univ| {
            // Now we update the set of guards themselves based on the
            // Universe, which is either the latest NetDir, or the latest
            // BridgeSet—depending on what the GuardSet wants.
            Self::update_guardset_internal(
                &this.params,
                wallclock,
                this.guards.active_set.universe_type(),
                this.guards.active_guards_mut(),
                univ,
            );
            #[cfg(feature = "bridge-client")]
            this.update_desired_descriptors(now);
            #[cfg(not(feature = "bridge-client"))]
            let _ = now;
        });
    }

    /// Replace our bridge configuration with the one from `new_config`.
    #[cfg(feature = "bridge-client")]
    fn replace_bridge_config(
        &mut self,
        new_config: &impl GuardMgrConfig,
        wallclock: SystemTime,
        now: Instant,
    ) -> Result<RetireCircuits, GuardMgrConfigError> {
        match (&self.configured_bridges, new_config.bridges_enabled()) {
            (None, false) => {
                assert_ne!(
                    self.guards.active_set.universe_type(),
                    UniverseType::BridgeSet
                );
                return Ok(RetireCircuits::None); // nothing to do
            }
            (_, true) if !self.storage.can_store() => {
                // TODO: Ideally we would try to upgrade, obtaining an exclusive lock,
                // but `StorageHandle` currently lacks a method for that.
                return Err(GuardMgrConfigError::NoLock("bridges configured".into()));
            }
            (Some(current_bridges), true) if new_config.bridges() == current_bridges.as_ref() => {
                assert_eq!(
                    self.guards.active_set.universe_type(),
                    UniverseType::BridgeSet
                );
                return Ok(RetireCircuits::None); // nothing to do.
            }
            (_, true) => {
                self.configured_bridges = Some(new_config.bridges().into());
                self.guards.active_set = GuardSetSelector::Bridges;
            }
            (_, false) => {
                self.configured_bridges = None;
                self.guards.active_set = GuardSetSelector::Default;
            }
        }

        // If we have gotten here, we have changed the set of bridges, changed
        // which set is active, or changed them both.  We need to make sure that
        // our `GuardSet` object is up-to-date with our configuration.
        self.update(wallclock, now);

        // We also need to tell the caller that its circuits are no good any
        // more.
        //
        // TODO(nickm): Someday we can do this more judiciously by retuning
        // "Some" in the case where we're still using bridges but our new bridge
        // set contains different elements; see comment on RetireCircuits.
        //
        // TODO(nickm): We could also safely return RetireCircuits::None if we
        // are using bridges, and our new bridge list is a superset of the older
        // one.
        Ok(RetireCircuits::All)
    }

    /// Update our parameters, our selection (based on network parameters and
    /// configuration), and make sure the active GuardSet has the right
    /// configuration itself.
    ///
    /// We should call this whenever the NetDir's parameters change, or whenever
    /// our filter changes.  We do not need to call it for new elements arriving
    /// in our Universe, since those do not affect anything here.
    ///
    /// We should also call this whenever a new GuardSet becomes active for any
    /// reason _other_ than just having called this function.
    ///
    /// (This function is only invoked from `update`, which should be called
    /// under the above circumstances.)
    fn update_active_set_params_and_filter(&mut self, netdir: Option<&NetDir>) {
        // Set the parameters.  These always come from the NetDir, even if this
        // is a bridge set.
        if let Some(netdir) = netdir {
            match GuardParams::try_from(netdir.params()) {
                Ok(params) => self.params = params,
                Err(e) => warn!("Unusable guard parameters from consensus: {}", e),
            }

            self.select_guard_set_based_on_filter(netdir);
        }

        // Change the filter, if it doesn't match what the guards have.
        //
        // TODO(nickm): We could use a "dirty" flag or something to decide
        // whether we need to call set_filter, if this comparison starts to show
        // up in profiles.
        if self.guards.active_guards().filter() != &self.filter {
            let restrictive = self.guards.active_set == GuardSetSelector::Restricted;
            self.guards
                .active_guards_mut()
                .set_filter(self.filter.clone(), restrictive);
        }
    }

    /// Update the status of every guard in `active_guards`, and expand it as
    /// needed.
    ///
    /// This function doesn't take `&self`, to make sure that we are only
    /// affecting a single `GuardSet`, and to avoid confusing the borrow
    /// checker.
    ///
    /// We should call this whenever the contents of the universe have changed.
    ///
    /// We should also call this whenever a new GuardSet becomes active.
    fn update_guardset_internal<U: Universe>(
        params: &GuardParams,
        now: SystemTime,
        universe_type: UniverseType,
        active_guards: &mut GuardSet,
        universe: Option<&U>,
    ) -> ExtendedStatus {
        // Expire guards.  Do that early, in case doing so makes it clear that
        // we need to grab more guards or mark others as primary.
        active_guards.expire_old_guards(params, now);

        let extended = if let Some(universe) = universe {
            // TODO: This check here may be completely unnecessary. I inserted
            // it back in 5ac0fcb7ef603e0d14 because I was originally concerned
            // it might be undesirable to list a primary guard as "missing dir
            // info" (and therefore unusable) if we were expecting to get its
            // microdescriptor "very soon."
            //
            // But due to the other check in `netdir_is_sufficient`, we
            // shouldn't be installing a netdir until it has microdescs for all
            // of the (non-bridge) primary guards that it lists. - nickm
            if active_guards.n_primary_without_id_info_in(universe) > 0
                && universe_type == UniverseType::NetDir
            {
                // We are missing the information from a NetDir needed to see
                // whether our primary guards are listed, so we shouldn't update
                // our guard status.
                //
                // We don't want to do this check if we are using bridges, since
                // a missing bridge descriptor is not guaranteed to temporary
                // problem in the same way that a missing microdescriptor is.
                // (When a bridge desc is missing, the bridge could be down or
                // unreachable, and nobody else can help us. But if a microdesc
                // is missing, we just need to find a cache that has it.)
                return ExtendedStatus::No;
            }
            active_guards.update_status_from_dir(universe);
            active_guards.extend_sample_as_needed(now, params, universe)
        } else {
            ExtendedStatus::No
        };

        active_guards.select_primary_guards(params);

        extended
    }

    /// If using bridges, tell the BridgeDescProvider which descriptors we want.
    /// We need to check this *after* we select our primary guards.
    #[cfg(feature = "bridge-client")]
    fn update_desired_descriptors(&mut self, now: Instant) {
        if self.guards.active_set.universe_type() != UniverseType::BridgeSet {
            return;
        }

        let provider = self.bridge_desc_provider.as_ref().and_then(Weak::upgrade);
        let bridge_set = self.latest_bridge_set();
        if let (Some(provider), Some(bridge_set)) = (provider, bridge_set) {
            let desired: Vec<_> = self
                .guards
                .active_guards()
                .descriptors_to_request(now, &self.params)
                .into_iter()
                .flat_map(|guard| bridge_set.bridge_by_guard(guard))
                .cloned()
                .collect();

            provider.set_bridges(&desired);
        }
    }

    /// Replace the active guard state with `new_state`, preserving
    /// non-persistent state for any guards that are retained.
    fn replace_guards_with(
        &mut self,
        mut new_guards: GuardSets,
        wallclock: SystemTime,
        now: Instant,
    ) {
        std::mem::swap(&mut self.guards, &mut new_guards);
        self.guards.copy_status_from(new_guards);
        self.update(wallclock, now);
    }

    /// Update which guard set is active based on the current filter and the
    /// provided netdir.
    ///
    /// After calling this function, the new guard set's filter may be
    /// out-of-date: be sure to call `set_filter` as appropriate.
    fn select_guard_set_based_on_filter(&mut self, netdir: &NetDir) {
        // In general, we'd like to use the restricted set if we're under the
        // threshold, and the default set if we're over the threshold.  But if
        // we're sitting close to the threshold, we want to avoid flapping back
        // and forth, so we only change when we're more than 5% "off" from
        // whatever our current setting is.
        //
        // (See guard-spec section 2 for more information.)
        let offset = match self.guards.active_set {
            GuardSetSelector::Default => -0.05,
            GuardSetSelector::Restricted => 0.05,
            // If we're using bridges, then we don't switch between the other guard sets based on on the filter at all.
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => return,
        };
        let frac_permitted = self.filter.frac_bw_permitted(netdir);
        let threshold = self.params.filter_threshold + offset;
        let new_choice = if frac_permitted < threshold {
            GuardSetSelector::Restricted
        } else {
            GuardSetSelector::Default
        };

        if new_choice != self.guards.active_set {
            info!(
                "Guard selection changed; we are now using the {:?} guard set",
                &new_choice
            );

            self.guards.active_set = new_choice;

            if frac_permitted < self.params.extreme_threshold {
                warn!(
                      "The number of guards permitted is smaller than the recommended minimum of {:.0}%.",
                      self.params.extreme_threshold * 100.0,
                );
            }
        }
    }

    /// Mark all of our primary guards as retriable, if we haven't done
    /// so since long enough before `now`.
    ///
    /// We want to call this function whenever a guard attempt succeeds,
    /// if the internet seemed to be down when the guard attempt was
    /// first launched.
    fn maybe_retry_primary_guards(&mut self, now: Instant) {
        // We don't actually want to mark our primary guards as
        // retriable more than once per internet_down_timeout: after
        // the first time, we would just be noticing the same "coming
        // back online" event more than once.
        let interval = self.params.internet_down_timeout;
        if self.last_primary_retry_time + interval <= now {
            debug!("Successfully reached a guard after a while off the internet; marking all primary guards retriable.");
            self.guards
                .active_guards_mut()
                .mark_primary_guards_retriable();
            self.last_primary_retry_time = now;
        }
    }

    /// Replace the current GuardFilter with `filter`.
    fn set_filter(&mut self, filter: GuardFilter, wallclock: SystemTime, now: Instant) {
        self.filter = filter;
        self.update(wallclock, now);
    }

    /// Called when the circuit manager reports (via [`GuardMonitor`]) that
    /// a guard succeeded or failed.
    ///
    /// Changes the guard's status as appropriate, and updates the pending
    /// request as needed.
    #[allow(clippy::cognitive_complexity)]
    pub(crate) fn handle_msg(
        &mut self,
        request_id: RequestId,
        status: GuardStatus,
        skew: Option<ClockSkew>,
        runtime: &impl tor_rtcompat::SleepProvider,
    ) {
        if let Some(mut pending) = self.pending.remove(&request_id) {
            // If there was a pending request matching this RequestId, great!
            let guard_id = pending.guard_id();
            trace!(?guard_id, ?status, "Received report of guard status");

            // First, handle the skew report (if any)
            if let Some(skew) = skew {
                let now = runtime.now();
                let observation = skew::SkewObservation { skew, when: now };

                match &guard_id.0 {
                    FirstHopIdInner::Guard(_, id) => {
                        self.guards.active_guards_mut().record_skew(id, observation);
                    }
                    FirstHopIdInner::Fallback(id) => {
                        self.fallbacks.note_skew(id, observation);
                    }
                }
                // TODO: We call this whenever we receive an observed clock
                // skew. That's not the perfect timing for two reasons.  First
                // off, it might be too frequent: it does an O(n) calculation,
                // which isn't ideal.  Second, it might be too infrequent: after
                // an hour has passed, a given observation won't be up-to-date
                // any more, and we might want to recalculate the skew
                // accordingly.
                self.update_skew(now);
            }

            match (status, &guard_id.0) {
                (GuardStatus::Failure, FirstHopIdInner::Fallback(id)) => {
                    // We used a fallback, and we weren't able to build a circuit through it.
                    self.fallbacks.note_failure(id, runtime.now());
                }
                (_, FirstHopIdInner::Fallback(_)) => {
                    // We don't record any other kind of circuit activity if we
                    // took the entry from the fallback list.
                }
                (GuardStatus::Success, FirstHopIdInner::Guard(sample, id)) => {
                    // If we had gone too long without any net activity when we
                    // gave out this guard, and now we're seeing a circuit
                    // succeed, tell the primary guards that they might be
                    // retriable.
                    if pending.net_has_been_down() {
                        self.maybe_retry_primary_guards(runtime.now());
                    }

                    // The guard succeeded.  Tell the GuardSet.
                    self.guards.guards_mut(sample).record_success(
                        id,
                        &self.params,
                        None,
                        runtime.wallclock(),
                    );
                    // Either tell the request whether the guard is
                    // usable, or schedule it as a "waiting" request.
                    if let Some(usable) = self.guard_usability_status(&pending, runtime.now()) {
                        trace!(?guard_id, usable, "Known usability status");
                        pending.reply(usable);
                    } else {
                        // This is the one case where we can't use the
                        // guard yet.
                        trace!(?guard_id, "Not able to answer right now");
                        pending.mark_waiting(runtime.now());
                        self.waiting.push(pending);
                    }
                }
                (GuardStatus::Failure, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards
                        .guards_mut(sample)
                        .record_failure(id, None, runtime.now());
                    pending.reply(false);
                }
                (GuardStatus::AttemptAbandoned, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards.guards_mut(sample).record_attempt_abandoned(id);
                    pending.reply(false);
                }
                (GuardStatus::Indeterminate, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards
                        .guards_mut(sample)
                        .record_indeterminate_result(id);
                    pending.reply(false);
                }
            };
        } else {
            warn!(
                "Got a status {:?} for a request {:?} that wasn't pending",
                status, request_id
            );
        }

        // We might need to update the primary guards based on changes in the
        // status of guards above.
        self.guards
            .active_guards_mut()
            .select_primary_guards(&self.params);

        // Some waiting request may just have become ready (usable or
        // not); we need to give them the information they're waiting
        // for.
        self.expire_and_answer_pending_requests(runtime.now());
    }

    /// Helper to implement `GuardMgr::note_external_success()`.
    ///
    /// (This has to be a separate function so that we can borrow params while
    /// we have `mut self` borrowed.)
    fn record_external_success<T>(
        &mut self,
        identity: &T,
        external_activity: ExternalActivity,
        now: SystemTime,
    ) where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        for id in self.lookup_ids(identity) {
            match &id.0 {
                FirstHopIdInner::Guard(sample, id) => {
                    self.guards.guards_mut(sample).record_success(
                        id,
                        &self.params,
                        Some(external_activity),
                        now,
                    );
                }
                FirstHopIdInner::Fallback(id) => {
                    if external_activity == ExternalActivity::DirCache {
                        self.fallbacks.note_success(id);
                    }
                }
            }
        }
    }

    /// Return an iterator over all of the clock skew observations we've made
    /// for guards or fallbacks.
    fn skew_observations(&self) -> impl Iterator<Item = &skew::SkewObservation> {
        self.fallbacks
            .skew_observations()
            .chain(self.guards.active_guards().skew_observations())
    }

    /// Recalculate our estimated clock skew, and publish it to anybody who
    /// cares.
    fn update_skew(&mut self, now: Instant) {
        let estimate = skew::SkewEstimate::estimate_skew(self.skew_observations(), now);
        // TODO: we might want to do this only conditionally, when the skew
        // estimate changes.
        *self.send_skew.borrow_mut() = estimate;
    }

    /// If the circuit built because of a given [`PendingRequest`] may
    /// now be used (or discarded), return `Some(true)` or
    /// `Some(false)` respectively.
    ///
    /// Return None if we can't yet give an answer about whether such
    /// a circuit is usable.
    fn guard_usability_status(&self, pending: &PendingRequest, now: Instant) -> Option<bool> {
        match &pending.guard_id().0 {
            FirstHopIdInner::Guard(sample, id) => self.guards.guards(sample).circ_usability_status(
                id,
                pending.usage(),
                &self.params,
                now,
            ),
            // Fallback circuits are usable immediately, since we don't have to wait to
            // see whether any _other_ circuit succeeds or fails.
            FirstHopIdInner::Fallback(_) => Some(true),
        }
    }

    /// For requests that have been "waiting" for an answer for too long,
    /// expire them and tell the circuit manager that their circuits
    /// are unusable.
    fn expire_and_answer_pending_requests(&mut self, now: Instant) {
        // A bit ugly: we use a separate Vec here to avoid borrowing issues,
        // and put it back when we're done.
        let mut waiting = Vec::new();
        std::mem::swap(&mut waiting, &mut self.waiting);

        waiting.retain_mut(|pending| {
            let expired = pending
                .waiting_since()
                .and_then(|w| now.checked_duration_since(w))
                .map(|d| d >= self.params.np_idle_timeout)
                == Some(true);
            if expired {
                trace!(?pending, "Pending request expired");
                pending.reply(false);
                return false;
            }

            // TODO-SPEC: guard_usability_status isn't what the spec says.  It
            // says instead that we should look at _circuit_ status, saying:
            //  "   Definition: In the algorithm above, C2 "blocks" C1 if:
            // * C2 obeys all the restrictions that C1 had to obey, AND
            // * C2 has higher priority than C1, AND
            // * Either C2 is <complete>, or C2 is <waiting_for_better_guard>,
            // or C2 has been <usable_if_no_better_guard> for no more than
            // {NONPRIMARY_GUARD_CONNECT_TIMEOUT} seconds."
            //
            // See comments in sample::GuardSet::circ_usability_status.

            if let Some(answer) = self.guard_usability_status(pending, now) {
                trace!(?pending, answer, "Pending request now ready");
                pending.reply(answer);
                return false;
            }
            true
        });

        // Put the waiting list back.
        std::mem::swap(&mut waiting, &mut self.waiting);
    }

    /// Return every currently extant FirstHopId for a guard or fallback
    /// directory matching (or possibly matching) the provided keys.
    ///
    /// An identity is _possibly matching_ if it contains some of the IDs in the
    /// provided identity, and it has no _contradictory_ identities, but it does
    /// not necessarily contain _all_ of those identities.
    ///
    /// # TODO
    ///
    /// This function should probably not exist; it's only used so that dirmgr
    /// can report successes or failures, since by the time it observes them it
    /// doesn't know whether its circuit came from a guard or a fallback.  To
    /// solve that, we'll need CircMgr to record and report which one it was
    /// using, which will take some more plumbing.
    ///
    /// TODO relay: we will have to make the change above when we implement
    /// relays; otherwise, it would be possible for an attacker to exploit it to
    /// mislead us about our guard status.
    fn lookup_ids<T>(&self, identity: &T) -> Vec<FirstHopId>
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        use strum::IntoEnumIterator;
        let mut vec = Vec::with_capacity(2);

        let id = ids::GuardId::from_relay_ids(identity);
        for sample in GuardSetSelector::iter() {
            let guard_id = match self.guards.guards(&sample).contains(&id) {
                Ok(true) => &id,
                Err(other) => other,
                Ok(false) => continue,
            };
            vec.push(FirstHopId(FirstHopIdInner::Guard(sample, guard_id.clone())));
        }

        let id = ids::FallbackId::from_relay_ids(identity);
        if self.fallbacks.contains(&id) {
            vec.push(id.into());
        }

        vec
    }

    /// Run any periodic events that update guard status, and return a
    /// duration after which periodic events should next be run.
    pub(crate) fn run_periodic_events(&mut self, wallclock: SystemTime, now: Instant) -> Duration {
        self.update(wallclock, now);
        self.expire_and_answer_pending_requests(now);
        Duration::from_secs(1) // TODO: Too aggressive.
    }

    /// Try to select a guard, expanding the sample if the first attempt fails.
    fn select_guard_with_expand(
        &mut self,
        usage: &GuardUsage,
        now: Instant,
        wallclock: SystemTime,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        // Try to find a guard.
        let first_error = match self.select_guard_once(usage, now) {
            Ok(res1) => return Ok(res1),
            Err(e) => {
                trace!("Couldn't select guard on first attempt: {}", e);
                e
            }
        };

        // That didn't work. If we have a netdir, expand the sample and try again.
        let res = self.with_opt_universe(|this, univ| {
            let univ = univ?;
            trace!("No guards available, trying to extend the sample.");
            // Make sure that the status on all of our guards are accurate, and
            // expand the sample if we can.
            //
            // Our parameters and configuration did not change, so we do not
            // need to call update() or update_active_set_and_filter(). This
            // call is sufficient to  extend the sample and recompute primary
            // guards.
            let extended = Self::update_guardset_internal(
                &this.params,
                wallclock,
                this.guards.active_set.universe_type(),
                this.guards.active_guards_mut(),
                Some(univ),
            );
            if extended == ExtendedStatus::Yes {
                match this.select_guard_once(usage, now) {
                    Ok(res) => return Some(res),
                    Err(e) => {
                        trace!("Couldn't select guard after update: {}", e);
                    }
                }
            }
            None
        });
        if let Some(res) = res {
            return Ok(res);
        }

        // Okay, that didn't work either.  If we were asked for a directory
        // guard, and we aren't using bridges, then we may be able to use a
        // fallback.
        if usage.kind == GuardUsageKind::OneHopDirectory
            && self.guards.active_set.universe_type() == UniverseType::NetDir
        {
            return self.select_fallback(now);
        }

        // Couldn't extend the sample or use a fallback; return the original error.
        Err(first_error)
    }

    /// Helper: try to pick a single guard, without retrying on failure.
    fn select_guard_once(
        &self,
        usage: &GuardUsage,
        now: Instant,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        let active_set = &self.guards.active_set;
        #[cfg_attr(not(feature = "bridge-client"), allow(unused_mut))]
        let (list_kind, mut first_hop) =
            self.guards
                .guards(active_set)
                .pick_guard(active_set, usage, &self.params, now)?;
        #[cfg(feature = "bridge-client")]
        if self.guards.active_set.universe_type() == UniverseType::BridgeSet {
            // See if we can promote first_hop to a viable CircTarget.
            let bridges = self.latest_bridge_set().ok_or_else(|| {
                PickGuardError::Internal(internal!(
                    "No bridge set available, even though this is the Bridges sample"
                ))
            })?;
            first_hop.lookup_bridge_circ_target(&bridges);

            if usage.kind == GuardUsageKind::Data && !first_hop.contains_circ_target() {
                return Err(PickGuardError::Internal(internal!(
                    "Tried to return a non-circtarget guard with Data usage!"
                )));
            }
        }
        Ok((list_kind, first_hop))
    }

    /// Helper: Select a fallback directory.
    ///
    /// Called when we have no guard information to use. Return values are as
    /// for [`GuardMgr::select_guard()`]
    fn select_fallback(
        &self,
        now: Instant,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        let filt = self.guards.active_guards().filter();

        let fallback = self
            .fallbacks
            .choose(&mut rand::thread_rng(), now, filt)?
            .as_guard();
        let fallback = filt.modify_hop(fallback)?;
        Ok((sample::ListKind::Fallback, fallback))
    }
}

/// A possible outcome of trying to extend a guard sample.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ExtendedStatus {
    /// The guard sample was extended. (At least one guard was added to it.)
    Yes,
    /// The guard sample was not extended.
    No,
}

/// A set of parameters, derived from the consensus document, controlling
/// the behavior of a guard manager.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
struct GuardParams {
    /// How long should a sampled, un-confirmed guard be kept in the sample before it expires?
    lifetime_unconfirmed: Duration,
    /// How long should a confirmed guard be kept in the sample before
    /// it expires?
    lifetime_confirmed: Duration,
    /// How long may  a guard be unlisted before we remove it from the sample?
    lifetime_unlisted: Duration,
    /// Largest number of guards we're willing to add to the sample.
    max_sample_size: usize,
    /// Largest fraction of the network's guard bandwidth that we're
    /// willing to add to the sample.
    max_sample_bw_fraction: f64,
    /// Smallest number of guards that we're willing to have in the
    /// sample, after applying a [`GuardFilter`].
    min_filtered_sample_size: usize,
    /// How many guards are considered "Primary"?
    n_primary: usize,
    /// When making a regular circuit, how many primary guards should we
    /// be willing to try?
    data_parallelism: usize,
    /// When making a one-hop directory circuit, how many primary
    /// guards should we be willing to try?
    dir_parallelism: usize,
    /// For how long does a pending attempt to connect to a guard
    /// block an attempt to use a less-favored non-primary guard?
    np_connect_timeout: Duration,
    /// How long do we allow a circuit to a successful but unfavored
    /// non-primary guard to sit around before deciding not to use it?
    np_idle_timeout: Duration,
    /// After how much time without successful activity does a
    /// successful circuit indicate that we should retry our primary
    /// guards?
    internet_down_timeout: Duration,
    /// What fraction of the guards can be can be filtered out before we
    /// decide that our filter is "very restrictive"?
    filter_threshold: f64,
    /// What fraction of the guards determine that our filter is "very
    /// restrictive"?
    extreme_threshold: f64,
}

impl Default for GuardParams {
    fn default() -> Self {
        let one_day = Duration::from_secs(86400);
        GuardParams {
            lifetime_unconfirmed: one_day * 120,
            lifetime_confirmed: one_day * 60,
            lifetime_unlisted: one_day * 20,
            max_sample_size: 60,
            max_sample_bw_fraction: 0.2,
            min_filtered_sample_size: 20,
            n_primary: 3,
            data_parallelism: 1,
            dir_parallelism: 3,
            np_connect_timeout: Duration::from_secs(15),
            np_idle_timeout: Duration::from_secs(600),
            internet_down_timeout: Duration::from_secs(600),
            filter_threshold: 0.2,
            extreme_threshold: 0.01,
        }
    }
}

impl TryFrom<&NetParameters> for GuardParams {
    type Error = tor_units::Error;
    fn try_from(p: &NetParameters) -> Result<GuardParams, Self::Error> {
        Ok(GuardParams {
            lifetime_unconfirmed: p.guard_lifetime_unconfirmed.try_into()?,
            lifetime_confirmed: p.guard_lifetime_confirmed.try_into()?,
            lifetime_unlisted: p.guard_remove_unlisted_after.try_into()?,
            max_sample_size: p.guard_max_sample_size.try_into()?,
            max_sample_bw_fraction: p.guard_max_sample_threshold.as_fraction(),
            min_filtered_sample_size: p.guard_filtered_min_sample_size.try_into()?,
            n_primary: p.guard_n_primary.try_into()?,
            data_parallelism: p.guard_use_parallelism.try_into()?,
            dir_parallelism: p.guard_dir_use_parallelism.try_into()?,
            np_connect_timeout: p.guard_nonprimary_connect_timeout.try_into()?,
            np_idle_timeout: p.guard_nonprimary_idle_timeout.try_into()?,
            internet_down_timeout: p.guard_internet_likely_down.try_into()?,
            filter_threshold: p.guard_meaningful_restriction.as_fraction(),
            extreme_threshold: p.guard_extreme_restriction.as_fraction(),
        })
    }
}

/// Representation of a guard or fallback, as returned by [`GuardMgr::select_guard()`].
#[derive(Debug, Clone)]
pub struct FirstHop {
    /// The sample from which this guard was taken, or `None` if this is a fallback.
    sample: Option<GuardSetSelector>,
    /// Information about connecting to (or through) this guard.
    inner: FirstHopInner,
}
/// The enumeration inside a FirstHop that holds information about how to
/// connect to (and possibly through) a guard or fallback.
#[derive(Debug, Clone)]
enum FirstHopInner {
    /// We have enough information to connect to a guard.
    Chan(OwnedChanTarget),
    /// We have enough information to connect to a guards _and_ to build
    /// multihop circuits through it.
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    Circ(OwnedCircTarget),
}

impl FirstHop {
    /// Return a new [`FirstHopId`] for this `FirstHop`.
    fn first_hop_id(&self) -> FirstHopId {
        match &self.sample {
            Some(sample) => {
                let guard_id = GuardId::from_relay_ids(self);
                FirstHopId::in_sample(sample.clone(), guard_id)
            }
            None => {
                let fallback_id = crate::ids::FallbackId::from_relay_ids(self);
                FirstHopId::from(fallback_id)
            }
        }
    }

    /// Look up this guard in `netdir`.
    pub fn get_relay<'a>(&self, netdir: &'a NetDir) -> Option<Relay<'a>> {
        match &self.sample {
            #[cfg(feature = "bridge-client")]
            // Always return "None" for anything that isn't in the netdir.
            Some(s) if s.universe_type() == UniverseType::BridgeSet => None,
            // Otherwise ask the netdir.
            _ => netdir.by_ids(self),
        }
    }

    /// If possible, return a view of this object that can be used to build a circuit.
    pub fn as_circ_target(&self) -> Option<&OwnedCircTarget> {
        match &self.inner {
            FirstHopInner::Chan(_) => None,
            FirstHopInner::Circ(ct) => Some(ct),
        }
    }

    /// Return a view of this as an OwnedChanTarget.
    fn chan_target_mut(&mut self) -> &mut OwnedChanTarget {
        match &mut self.inner {
            FirstHopInner::Chan(ct) => ct,
            FirstHopInner::Circ(ct) => ct.chan_target_mut(),
        }
    }

    /// If possible and appropriate, find a circuit target in `bridges` for this
    /// `FirstHop`, and make this `FirstHop` a viable circuit target.
    ///
    /// (By default, any `FirstHop` that a `GuardSet` returns will have enough
    /// information to be a `ChanTarget`, but it will be lacking the additional
    /// network information in `CircTarget`[^1] necessary for us to build a
    /// multi-hop circuit through it.  If this FirstHop is a regular non-bridge
    /// `Relay`, then the `CircMgr` will later look up that circuit information
    /// itself from the network directory. But if this `FirstHop` *is* a bridge,
    /// then we need to find that information in the `BridgeSet`, since the
    /// CircMgr does not keep track of the `BridgeSet`.)
    ///
    /// [^1]: For example, supported protocol versions and ntor keys.
    #[cfg(feature = "bridge-client")]
    fn lookup_bridge_circ_target(&mut self, bridges: &bridge::BridgeSet) {
        use crate::sample::CandidateStatus::Present;
        if self.sample.as_ref().map(|s| s.universe_type()) == Some(UniverseType::BridgeSet)
            && matches!(self.inner, FirstHopInner::Chan(_))
        {
            if let Present(bridge_relay) = bridges.bridge_relay_by_guard(self) {
                if let Some(circ_target) = bridge_relay.as_relay_with_desc() {
                    self.inner =
                        FirstHopInner::Circ(OwnedCircTarget::from_circ_target(&circ_target));
                }
            }
        }
    }

    /// Return true if this `FirstHop` contains circuit target information.
    ///
    /// This is true if `lookup_bridge_circ_target()` has been called, and it
    /// successfully found the circuit target information.
    #[cfg(feature = "bridge-client")]
    fn contains_circ_target(&self) -> bool {
        matches!(self.inner, FirstHopInner::Circ(_))
    }
}

// This is somewhat redundant with the implementations in crate::guard::Guard.
impl tor_linkspec::HasAddrs for FirstHop {
    fn addrs(&self) -> &[SocketAddr] {
        match &self.inner {
            FirstHopInner::Chan(ct) => ct.addrs(),
            FirstHopInner::Circ(ct) => ct.addrs(),
        }
    }
}
impl tor_linkspec::HasRelayIds for FirstHop {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match &self.inner {
            FirstHopInner::Chan(ct) => ct.identity(key_type),
            FirstHopInner::Circ(ct) => ct.identity(key_type),
        }
    }
}
impl tor_linkspec::HasChanMethod for FirstHop {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        match &self.inner {
            FirstHopInner::Chan(ct) => ct.chan_method(),
            FirstHopInner::Circ(ct) => ct.chan_method(),
        }
    }
}
impl tor_linkspec::ChanTarget for FirstHop {}

/// The purpose for which we plan to use a guard.
///
/// This can affect the guard selection algorithm.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuardUsageKind {
    /// We want to use this guard for a data circuit.
    ///
    /// (This encompasses everything except the `OneHopDirectory` case.)
    #[default]
    Data,
    /// We want to use this guard for a one-hop, non-anonymous
    /// directory request.
    ///
    /// (Our algorithm allows more parallelism for the guards that we use
    /// for these circuits.)
    OneHopDirectory,
}

/// A set of parameters describing how a single guard should be selected.
///
/// Used as an argument to [`GuardMgr::select_guard`].
#[derive(Clone, Debug, derive_builder::Builder)]
#[builder(build_fn(error = "tor_config::ConfigBuildError"))]
pub struct GuardUsage {
    /// The purpose for which this guard will be used.
    #[builder(default)]
    kind: GuardUsageKind,
    /// A list of restrictions on which guard may be used.
    ///
    /// The default is the empty list.
    #[builder(sub_builder, setter(custom))]
    restrictions: GuardRestrictionList,
}

impl_standard_builder! { GuardUsage: !Deserialize }

/// List of socket restrictions, as configured
pub type GuardRestrictionList = Vec<GuardRestriction>;

define_list_builder_helper! {
    pub struct GuardRestrictionListBuilder {
        restrictions: [GuardRestriction],
    }
    built: GuardRestrictionList = restrictions;
    default = vec![];
    item_build: |restriction| Ok(restriction.clone());
}

define_list_builder_accessors! {
    struct GuardUsageBuilder {
        pub restrictions: [GuardRestriction],
    }
}

impl GuardUsageBuilder {
    /// Create a new empty [`GuardUsageBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// A restriction that applies to a single request for a guard.
///
/// Restrictions differ from filters (see [`GuardFilter`]) in that
/// they apply to single requests, not to our entire set of guards.
/// They're suitable for things like making sure that we don't start
/// and end a circuit at the same relay, or requiring a specific
/// subprotocol version for certain kinds of requests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GuardRestriction {
    /// Don't pick a guard with the provided identity.
    AvoidId(RelayId),
    /// Don't pick a guard with any of the provided Ed25519 identities.
    AvoidAllIds(RelayIdSet),
}

/// The kind of vanguards to use.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)] //
#[derive(derive_more::Display)] //
#[serde(rename_all = "lowercase")]
#[cfg(feature = "vanguards")]
#[non_exhaustive]
pub enum VanguardMode {
    /// "Lite" vanguards.
    #[default]
    #[display(fmt = "lite")]
    Lite = 1,
    /// "Full" vanguards.
    #[display(fmt = "full")]
    Full = 2,
    /// Vanguards are disabled.
    #[display(fmt = "disabled")]
    Disabled = 0,
}

#[cfg(feature = "vanguards")]
impl VanguardMode {
    /// Build a `VanguardMode` from a [`NetParameters`] parameter.
    ///
    /// Used for converting [`vanguards_enabled`](NetParameters::vanguards_enabled)
    /// or [`vanguards_hs_service`](NetParameters::vanguards_hs_service)
    /// to the corresponding `VanguardMode`.
    #[allow(dead_code)] // TODO HS-VANGUARDS
    pub(crate) fn from_net_parameter(val: BoundedInt32<0, 2>) -> Self {
        match val.get() {
            0 => VanguardMode::Disabled,
            1 => VanguardMode::Lite,
            2 => VanguardMode::Full,
            _ => unreachable!("BoundedInt32 was not bounded?!"),
        }
    }
}

/// The kind of vanguards to use.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)] //
#[derive(derive_more::Display)] //
#[serde(rename_all = "lowercase")]
#[cfg(not(feature = "vanguards"))]
#[non_exhaustive]
pub enum VanguardMode {
    /// Vanguards are disabled.
    #[default]
    #[display(fmt = "disabled")]
    Disabled = 0,
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
    use tor_linkspec::{HasAddrs, HasRelayIds};
    use tor_persist::TestingStateMgr;
    use tor_rtcompat::test_with_all_runtimes;

    #[test]
    fn guard_param_defaults() {
        let p1 = GuardParams::default();
        let p2: GuardParams = (&NetParameters::default()).try_into().unwrap();
        assert_eq!(p1, p2);
    }

    fn init<R: Runtime>(rt: R) -> (GuardMgr<R>, TestingStateMgr, NetDir) {
        use tor_netdir::{testnet, MdReceiver, PartialNetDir};
        let statemgr = TestingStateMgr::new();
        let have_lock = statemgr.try_lock().unwrap();
        assert!(have_lock.held());
        let guardmgr = GuardMgr::new(rt, statemgr.clone(), &TestConfig::default()).unwrap();
        let (con, mds) = testnet::construct_network().unwrap();
        let param_overrides = vec![
            // We make the sample size smaller than usual to compensate for the
            // small testing network.  (Otherwise, we'd sample the whole network,
            // and not be able to observe guards in the tests.)
            "guard-min-filtered-sample-size=5",
            // We choose only two primary guards, to make the tests easier to write.
            "guard-n-primary-guards=2",
            // We define any restriction that allows 75% or fewer of relays as "meaningful",
            // so that we can test the "restrictive" guard sample behavior, and to avoid
            "guard-meaningful-restriction-percent=75",
        ];
        let param_overrides: String =
            itertools::Itertools::intersperse(param_overrides.into_iter(), " ").collect();
        let override_p = param_overrides.parse().unwrap();
        let mut netdir = PartialNetDir::new(con, Some(&override_p));
        for md in mds {
            netdir.add_microdesc(md);
        }
        let netdir = netdir.unwrap_if_sufficient().unwrap();

        (guardmgr, statemgr, netdir)
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn simple_case() {
        test_with_all_runtimes!(|rt| async move {
            let (guardmgr, statemgr, netdir) = init(rt.clone());
            let usage = GuardUsage::default();
            guardmgr.install_test_netdir(&netdir);

            let (id, mon, usable) = guardmgr.select_guard(usage).unwrap();
            // Report that the circuit succeeded.
            mon.succeeded();

            // May we use the circuit?
            let usable = usable.await.unwrap();
            assert!(usable);

            // Save the state...
            guardmgr.flush_msg_queue().await;
            guardmgr.store_persistent_state().unwrap();
            drop(guardmgr);

            // Try reloading from the state...
            let guardmgr2 =
                GuardMgr::new(rt.clone(), statemgr.clone(), &TestConfig::default()).unwrap();
            guardmgr2.install_test_netdir(&netdir);

            // Since the guard was confirmed, we should get the same one this time!
            let usage = GuardUsage::default();
            let (id2, _mon, _usable) = guardmgr2.select_guard(usage).unwrap();
            assert!(id2.same_relay_ids(&id));
        });
    }

    #[test]
    fn simple_waiting() {
        // TODO(nickm): This test fails in rare cases; I suspect a
        // race condition somewhere.
        //
        // I've doubled up on the queue flushing in order to try to make the
        // race less likely, but we should investigate.
        test_with_all_runtimes!(|rt| async move {
            let (guardmgr, _statemgr, netdir) = init(rt);
            let u = GuardUsage::default();
            guardmgr.install_test_netdir(&netdir);

            // We'll have the first two guard fail, which should make us
            // try a non-primary guard.
            let (id1, mon, _usable) = guardmgr.select_guard(u.clone()).unwrap();
            mon.failed();
            guardmgr.flush_msg_queue().await; // avoid race
            guardmgr.flush_msg_queue().await; // avoid race
            let (id2, mon, _usable) = guardmgr.select_guard(u.clone()).unwrap();
            mon.failed();
            guardmgr.flush_msg_queue().await; // avoid race
            guardmgr.flush_msg_queue().await; // avoid race

            assert!(!id1.same_relay_ids(&id2));

            // Now we should get two sampled guards. They should be different.
            let (id3, mon3, usable3) = guardmgr.select_guard(u.clone()).unwrap();
            let (id4, mon4, usable4) = guardmgr.select_guard(u.clone()).unwrap();
            assert!(!id3.same_relay_ids(&id4));

            let (u3, u4) = futures::join!(
                async {
                    mon3.failed();
                    guardmgr.flush_msg_queue().await; // avoid race
                    usable3.await.unwrap()
                },
                async {
                    mon4.succeeded();
                    usable4.await.unwrap()
                }
            );

            assert_eq!((u3, u4), (false, true));
        });
    }

    #[test]
    fn filtering_basics() {
        test_with_all_runtimes!(|rt| async move {
            let (guardmgr, _statemgr, netdir) = init(rt);
            let u = GuardUsage::default();
            let filter = {
                let mut f = GuardFilter::default();
                // All the addresses in the test network are {0,1,2,3,4}.0.0.3:9001.
                // Limit to only 2.0.0.0/8
                f.push_reachable_addresses(vec!["2.0.0.0/8:9001".parse().unwrap()]);
                f
            };
            guardmgr.set_filter(filter);
            guardmgr.install_test_netdir(&netdir);
            let (guard, _mon, _usable) = guardmgr.select_guard(u).unwrap();
            // Make sure that the filter worked.
            let addr = guard.addrs()[0];
            assert_eq!(addr, "2.0.0.3:9001".parse().unwrap());
        });
    }

    #[test]
    fn external_status() {
        test_with_all_runtimes!(|rt| async move {
            let (guardmgr, _statemgr, netdir) = init(rt);
            let data_usage = GuardUsage::default();
            let dir_usage = GuardUsageBuilder::new()
                .kind(GuardUsageKind::OneHopDirectory)
                .build()
                .unwrap();
            guardmgr.install_test_netdir(&netdir);
            {
                // Override this parameter, so that we can get deterministic results below.
                let mut inner = guardmgr.inner.lock().unwrap();
                inner.params.dir_parallelism = 1;
            }

            let (guard, mon, _usable) = guardmgr.select_guard(data_usage.clone()).unwrap();
            mon.succeeded();

            // Record that this guard gave us a bad directory object.
            guardmgr.note_external_failure(&guard, ExternalActivity::DirCache);

            // We ask for another guard, for data usage.  We should get the same
            // one as last time, since the director failure doesn't mean this
            // guard is useless as a primary guard.
            let (g2, mon, _usable) = guardmgr.select_guard(data_usage).unwrap();
            assert_eq!(g2.ed_identity(), guard.ed_identity());
            mon.succeeded();

            // But if we ask for a guard for directory usage, we should get a
            // different one, since the last guard we gave out failed.
            let (g3, mon, _usable) = guardmgr.select_guard(dir_usage.clone()).unwrap();
            assert_ne!(g3.ed_identity(), guard.ed_identity());
            mon.succeeded();

            // Now record a success for for directory usage.
            guardmgr.note_external_success(&guard, ExternalActivity::DirCache);

            // Now that the guard is working as a cache, asking for it should get us the same guard.
            let (g4, _mon, _usable) = guardmgr.select_guard(dir_usage).unwrap();
            assert_eq!(g4.ed_identity(), guard.ed_identity());
        });
    }

    #[cfg(feature = "vanguards")]
    #[test]
    fn vanguard_mode_ord() {
        assert!(VanguardMode::Disabled < VanguardMode::Lite);
        assert!(VanguardMode::Disabled < VanguardMode::Full);
        assert!(VanguardMode::Lite < VanguardMode::Full);
    }
}
