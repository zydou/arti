//! `tor-guardmgr`: guard node selection for Tor network clients.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! "Guard nodes" are mechanism that Tor clients uses to limit the
//! impact of hostile relays. Approximately: each client chooses a
//! small set of relays to use as its "guards".  Later, when the
//! client picks its paths through network, rather than choosing a
//! different first hop randomly for every path, it chooses the best
//! "guard" as the first hop.
//!
//! This crate provides [`GuardMgr`], an object that manages a set of
//! guard nodes, and helps the `tor-circmgr` crate know when to use
//! them.
//!
//! Guard nodes are persistent across multiple process invocations.
//!
//! More Arti users won't need to use this crate directly.
//!
//! # Motivation
//!
//! What's the point?  By restricting their first hops to a small set,
//! clients increase their odds against traffic-correlation attacks.
//! Since we assume that an adversary who controls both ends of a
//! circuit can correlate its traffic, choosing many circuits with
//! random entry points will eventually cause a client to eventually
//! pick an attacker-controlled circuit, with probability approaching
//! 1 over time.  If entry nodes are restricted to a small set,
//! however, then the client has a chance of never picking an
//! attacker-controlled circuit.
//!
//! (The actual argument is a little more complicated here, and it
//! relies on the assumption that, since the attacker knows
//! statistics, exposing _any_ of your traffic is nearly as bad as
//! exposing _all_ of your traffic.)
//!
//! # Complications
//!
//! The real algorithm for selecting and using guards can get more
//! complicated because of a variety of factors.
//!
//! - In reality, we can't just "pick a few guards at random" and use
//!   them forever: relays can appear and disappear, relays can go
//!   offline and come back online, and so on.  What's more, keeping
//!   guards for too long can make targeted attacks against those
//!   guards more attractive.
//!
//! - Further, we may have particular restrictions on where we can
//!   connect. (For example, we might be restricted to ports 80 and
//!   443, but only when we're on a commuter train's wifi network.)
//!
//! - We need to resist attacks from local networks that block all but a
//!   small set of guard relays, to force us to choose those.
//!
//! - We need to give good, reliable performance while using the
//!   guards that we prefer.
//!
//! These needs complicate our API somewhat.  Instead of simply asking
//! the `GuardMgr` for a guard, the circuit-management code needs to
//! be able to tell the `GuardMgr` that a given guard has failed (or
//! succeeded), and that it needs a different guard in the future (or
//! not).
//!
//! Further, the `GuardMgr` code needs to be able to hand out
//! _provisional guards_, in effect saying "You can try building a
//! circuit with this guard, but please don't actually _use_ that
//! circuit unless I tell you it's safe."
//!
//! For details on the exact algorithm, see `guard-spec.txt` (link
//! below) and comments and internal documentation in this crate.
//!
//! # Limitations
//!
//! * Only one guard selection is currently supported: we don't allow a
//!   "filtered" or a "bridges" selection.
//!
//! * Our circuit blocking algorithm is simplified from the one that Tor uses.
//!   See comments in `GuardSet::circ_usability_status` for more information.
//!   See also [proposal 337](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/337-simpler-guard-usability.md).
//!
//! # References
//!
//! Guard nodes were first proposes (as "helper nodes") in "Defending
//! Anonymous Communications Against Passive Logging Attacks" by
//! Matthew Wright, Micah Adler, Brian N. Levine, and Clay Shields in
//! the Proceedings of the 2003 IEEE Symposium on Security and
//! Privacy.  (See <https://www.freehaven.net/anonbib/#wright03>)
//!
//! Tor's current guard selection algorithm is described in Tor's
//! [`guard-spec.txt`](https://gitlab.torproject.org/tpo/core/torspec/-/raw/main/guard-spec.txt)
//! document.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

// Glossary:
//     Primary guard
//     Sample
//     confirmed
//     filtered

use educe::Educe;
use futures::channel::mpsc;
use futures::task::SpawnExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tor_proto::ClockSkew;
use tracing::{debug, info, trace, warn};

use tor_llcrypto::pk;
use tor_netdir::{params::NetParameters, NetDir, Relay};
use tor_persist::{DynStorageHandle, StateMgr};
use tor_rtcompat::Runtime;

mod daemon;
mod dirstatus;
mod err;
pub mod fallback;
mod filter;
mod guard;
mod ids;
mod pending;
mod sample;
mod skew;
mod util;

pub use err::{GuardMgrError, PickGuardError};
pub use filter::GuardFilter;
pub use ids::FirstHopId;
pub use pending::{GuardMonitor, GuardStatus, GuardUsable};
pub use skew::SkewEstimate;

use pending::{PendingRequest, RequestId};
use sample::GuardSet;

use crate::ids::FirstHopIdInner;

/// A "guard manager" that selects and remembers a persistent set of
/// guard nodes.
///
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
    // TODO: reconfigure when the configuration changes.
    fallbacks: fallback::FallbackState,

    /// Location in which to store persistent state.
    storage: DynStorageHandle<GuardSets>,
}

/// Persistent state for a guard manager, as serialized to disk.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GuardSets {
    /// The default set of guards to use.
    ///
    /// Right now, this is the _only_ `GuardSet` for each `GuardMgr`, but we
    /// expect that to change: our algorithm specifies that there can
    /// be multiple named guard sets, and we can swap between them
    /// depending on the user's selected [`GuardFilter`].
    default: GuardSet,

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

impl<R: Runtime> GuardMgr<R> {
    /// Create a new "empty" guard manager and launch its background tasks.
    ///
    /// It won't be able to hand out any guards until
    /// [`GuardMgr::update_network`] has been called.
    pub fn new<S>(
        runtime: R,
        state_mgr: S,
        fallbacks: fallback::FallbackList,
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
        let inner = Arc::new(Mutex::new(GuardMgrInner {
            guards: state,
            last_primary_retry_time: runtime.now(),
            params: GuardParams::default(),
            ctrl,
            pending: HashMap::new(),
            waiting: Vec::new(),
            fallbacks: fallbacks.into(),
            storage,
        }));
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
            let now = self.runtime.wallclock();
            inner.replace_guards_with(new_guards, now);
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
        let now = self.runtime.wallclock();
        inner.replace_guards_with(new_guards, now);
        Ok(())
    }

    /// Return true if `netdir` has enough information to safely become our new netdir.
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner
            .guards
            .active_guards_mut()
            .missing_primary_microdescriptors(netdir)
            == 0
    }

    /// Mark every guard as potentially retriable, regardless of how recently we
    /// failed to connect to it.
    pub fn mark_all_guards_retriable(&self) {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.guards.active_guards_mut().mark_all_guards_retriable();
    }

    /// Update the state of this [`GuardMgr`] based on a new or modified
    /// [`NetDir`] object.
    ///
    /// This method can add new guards, or notice that existing guards
    /// have become unusable.  It needs a `NetDir` so it can identify
    /// potential candidate guards.
    ///
    /// Call this method whenever the `NetDir` changes.
    pub fn update_network(&self, netdir: &NetDir) {
        trace!("Updating guard state from network directory");
        let now = self.runtime.wallclock();

        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.update(now, Some(netdir));
    }

    /// Replace the fallback list held by this GuardMgr with `new_list`.
    pub fn replace_fallback_list(&self, list: fallback::FallbackList) {
        let mut fallbacks: fallback::FallbackState = list.into();
        let mut inner = self.inner.lock().expect("Poisoned lock");
        std::mem::swap(&mut inner.fallbacks, &mut fallbacks);
        inner.fallbacks.take_status_from(fallbacks);
    }

    /// Replace the current [`GuardFilter`] used by this `GuardMgr`.
    ///
    /// (Since there is only one kind of filter right now, there's no
    /// real reason to call this function, but at least it should work.
    pub fn set_filter(&self, filter: GuardFilter, netdir: &NetDir) {
        // First we have to see how much of the possible guard space
        // this new filter allows.  (We don't use this info yet, but we will
        // one we have nontrivial filters.)
        let n_guards = netdir.relays().filter(|r| r.is_flagged_guard()).count();
        let n_permitted = netdir
            .relays()
            .filter(|r| r.is_flagged_guard() && filter.permits(r))
            .count();
        let frac_permitted = if n_guards > 0 {
            n_permitted as f64 / (n_guards as f64)
        } else {
            1.0
        };

        let now = self.runtime.wallclock();
        let mut inner = self.inner.lock().expect("Poisoned lock");

        let restrictive_filter = frac_permitted < inner.params.filter_threshold;

        // TODO: Once we support nontrivial filters, we might have to
        // swap out "active_guards" depending on which set it is.

        if frac_permitted < inner.params.extreme_threshold {
            warn!(
                "The number of guards permitted is smaller than the guard param minimum of {}%.",
                inner.params.extreme_threshold * 100.0,
            );
        }

        info!(
            ?filter,
            restrictive = restrictive_filter,
            "Guard filter replaced."
        );

        inner
            .guards
            .active_guards_mut()
            .set_filter(filter, restrictive_filter);
        inner.update(now, Some(netdir));
    }

    /// Select a guard for a given [`GuardUsage`].
    ///
    /// On success, we return a [`FirstHopId`] object to identify which
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
    ///
    /// # Limitations
    ///
    /// This function will never return a guard that isn't listed in
    /// the [`NetDir`] most recently passed to [`GuardMgr::update_network`].
    /// That's _usually_ what you'd want, but when we're trying to
    /// bootstrap we might want to use _all_ guards as possible
    /// directory caches.  That's not implemented yet. (See ticket
    /// [#220](https://gitlab.torproject.org/tpo/core/arti/-/issues/220)).
    ///
    /// This function only looks at netdir when all of the known
    /// guards are down; to force an update, use [`GuardMgr::update_network`].
    pub fn select_guard(
        &self,
        usage: GuardUsage,
        netdir: Option<&NetDir>,
    ) -> Result<(FirstHop, GuardMonitor, GuardUsable), PickGuardError> {
        let now = self.runtime.now();
        let wallclock = self.runtime.wallclock();

        let mut inner = self.inner.lock().expect("Poisoned lock");

        // (I am not 100% sure that we need to consider_all_retries here, but
        // it should _probably_ not hurt.)
        inner.guards.active_guards_mut().consider_all_retries(now);

        let (origin, guard) = inner.select_guard_with_expand(&usage, netdir, now, wallclock)?;
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

        let pending_request =
            pending::PendingRequest::new(guard.id.clone(), usage, usable_sender, net_has_been_down);
        inner.pending.insert(request_id, pending_request);

        match &guard.id.0 {
            FirstHopIdInner::Guard(id) => inner.guards.active_guards_mut().record_attempt(id, now),
            FirstHopIdInner::Fallback(_) => {
                // We don't record attempts for fallbacks; we only care when
                // they have failed.
            }
        }

        Ok((guard, monitor, usable))
    }

    /// Record that _after_ we built a circuit with a guard, something described
    /// in `external_failure` went wrong with it.
    pub fn note_external_failure(
        &self,
        ed_identity: &pk::ed25519::Ed25519Identity,
        rsa_identity: &pk::rsa::RsaIdentity,
        external_failure: ExternalActivity,
    ) {
        let now = self.runtime.now();
        let mut inner = self.inner.lock().expect("Poisoned lock");

        for id in inner.lookup_ids(ed_identity, rsa_identity) {
            match &id.0 {
                FirstHopIdInner::Guard(id) => {
                    inner.guards.active_guards_mut().record_failure(
                        id,
                        Some(external_failure),
                        now,
                    );
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
    pub fn note_external_success(
        &self,
        ed_identity: &pk::ed25519::Ed25519Identity,
        rsa_identity: &pk::rsa::RsaIdentity,
        external_activity: ExternalActivity,
    ) {
        let mut inner = self.inner.lock().expect("Poisoned lock");

        inner.record_external_success(
            ed_identity,
            rsa_identity,
            external_activity,
            self.runtime.wallclock(),
        );
    }

    /// Return our best estimate of our current clock skew, based on reports from the
    /// guards and fallbacks we have contacted.
    pub fn skew_estimate(&self) -> Option<SkewEstimate> {
        let inner = self.inner.lock().expect("Poisoned lock");
        let now = self.runtime.now();
        SkewEstimate::estimate_skew(inner.skew_observations(), now)
    }

    /// Ensure that the message queue is flushed before proceeding to
    /// the next step.  Used for testing.
    #[cfg(test)]
    async fn flush_msg_queue(&self) {
        let (snd, rcv) = futures::channel::oneshot::channel();
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
        &self.default
    }

    /// Return a mutable reference to the currently active set of guards.
    fn active_guards_mut(&mut self) -> &mut GuardSet {
        &mut self.default
    }

    /// Update all non-persistent state for the guards in this object with the
    /// state in `other`.
    fn copy_status_from(&mut self, other: GuardSets) {
        self.default.copy_status_from(other.default);
    }
}

impl GuardMgrInner {
    /// Update the status of all guards in the active set, based on
    /// the passage of time and (optionally) a network directory.
    ///
    /// We can expire guards based on the time alone; we can only
    /// add guards or change their status with a NetDir.
    fn update(&mut self, now: SystemTime, netdir: Option<&NetDir>) {
        // Set the parameters.
        if let Some(netdir) = netdir {
            match GuardParams::try_from(netdir.params()) {
                Ok(params) => self.params = params,
                Err(e) => warn!("Unusable guard parameters from consensus: {}", e),
            }
        }

        // Then expire guards.  Do that early, in case we need more.
        self.guards
            .active_guards_mut()
            .expire_old_guards(&self.params, now);

        if let Some(netdir) = netdir {
            if self
                .guards
                .active_guards_mut()
                .missing_primary_microdescriptors(netdir)
                > 0
            {
                // We are missing primary guard descriptors, so we shouldn't update our guard
                // status.
                return;
            }
            self.guards
                .active_guards_mut()
                .update_status_from_netdir(netdir);
            loop {
                let added_any = self.guards.active_guards_mut().extend_sample_as_needed(
                    now,
                    &self.params,
                    netdir,
                );
                if !added_any {
                    break;
                }
            }
        }

        self.guards
            .active_guards_mut()
            .select_primary_guards(&self.params);
    }

    /// Replace the active guard state with `new_state`, preserving
    /// non-persistent state for any guards that are retained.
    fn replace_guards_with(&mut self, mut new_guards: GuardSets, now: SystemTime) {
        std::mem::swap(&mut self.guards, &mut new_guards);
        self.guards.copy_status_from(new_guards);
        self.update(now, None);
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

    /// Called when the circuit manager reports (via [`GuardMonitor`]) that
    /// a guard succeeded or failed.
    ///
    /// Changes the guard's status as appropriate, and updates the pending
    /// request as needed.
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
                let observation = skew::SkewObservation {
                    skew,
                    when: runtime.now(),
                };

                match &guard_id.0 {
                    FirstHopIdInner::Guard(id) => {
                        self.guards.active_guards_mut().record_skew(id, observation);
                    }
                    FirstHopIdInner::Fallback(id) => {
                        self.fallbacks.note_skew(id, observation);
                    }
                }
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
                (GuardStatus::Success, FirstHopIdInner::Guard(id)) => {
                    // If we had gone too long without any net activity when we
                    // gave out this guard, and now we're seeing a circuit
                    // succeed, tell the primary guards that they might be
                    // retriable.
                    if pending.net_has_been_down() {
                        self.maybe_retry_primary_guards(runtime.now());
                    }

                    // The guard succeeded.  Tell the GuardSet.
                    self.guards.active_guards_mut().record_success(
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
                (GuardStatus::Failure, FirstHopIdInner::Guard(id)) => {
                    self.guards
                        .active_guards_mut()
                        .record_failure(id, None, runtime.now());
                    pending.reply(false);
                }
                (GuardStatus::AttemptAbandoned, FirstHopIdInner::Guard(id)) => {
                    self.guards.active_guards_mut().record_attempt_abandoned(id);
                    pending.reply(false);
                }
                (GuardStatus::Indeterminate, FirstHopIdInner::Guard(id)) => {
                    self.guards
                        .active_guards_mut()
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
    fn record_external_success(
        &mut self,
        ed_identity: &pk::ed25519::Ed25519Identity,
        rsa_identity: &pk::rsa::RsaIdentity,
        external_activity: ExternalActivity,
        now: SystemTime,
    ) {
        for id in self.lookup_ids(ed_identity, rsa_identity) {
            match &id.0 {
                FirstHopIdInner::Guard(id) => {
                    self.guards.active_guards_mut().record_success(
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

    /// If the circuit built because of a given [`PendingRequest`] may
    /// now be used (or discarded), return `Some(true)` or
    /// `Some(false)` respectively.
    ///
    /// Return None if we can't yet give an answer about whether such
    /// a circuit is usable.
    fn guard_usability_status(&self, pending: &PendingRequest, now: Instant) -> Option<bool> {
        match &pending.guard_id().0 {
            FirstHopIdInner::Guard(id) => self.guards.active_guards().circ_usability_status(
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
        // TODO: Use Vec::drain_filter or Vec::retain_mut when/if it's stable.
        use retain_mut::RetainMut;

        // A bit ugly: we use a separate Vec here to avoid borrowing issues,
        // and put it back when we're done.
        let mut waiting = Vec::new();
        std::mem::swap(&mut waiting, &mut self.waiting);

        RetainMut::retain_mut(&mut waiting, |pending| {
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
    /// directory matching the provided keys.
    ///
    /// # TODO
    ///
    /// This function should probably not exist; it's only used so that dirmgr
    /// can report successes or failures, since by the time it observes them it
    /// doesn't know whether its circuit came from a guard or a fallback.  To
    /// solve that, we'll need CircMgr to record and report which one it was
    /// using, which will take some more plumbing.
    fn lookup_ids(
        &self,
        ed_identity: &pk::ed25519::Ed25519Identity,
        rsa_identity: &pk::rsa::RsaIdentity,
    ) -> Vec<FirstHopId> {
        let mut vec = Vec::with_capacity(2);

        let id = ids::GuardId::new(*ed_identity, *rsa_identity);
        if self.guards.active_guards().contains(&id) {
            vec.push(id.into());
        }

        let id = ids::FallbackId::new(*ed_identity, *rsa_identity);
        if self.fallbacks.contains(&id) {
            vec.push(id.into());
        }

        vec
    }

    /// Run any periodic events that update guard status, and return a
    /// duration after which periodic events should next be run.
    pub(crate) fn run_periodic_events(&mut self, wallclock: SystemTime, now: Instant) -> Duration {
        self.update(wallclock, None);
        self.expire_and_answer_pending_requests(now);
        Duration::from_secs(1) // TODO: Too aggressive.
    }

    /// Try to select a guard, expanding the sample if the first attempt fails.
    fn select_guard_with_expand(
        &mut self,
        usage: &GuardUsage,
        netdir: Option<&NetDir>,
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
        if let Some(dir) = netdir {
            trace!("No guards available, trying to extend the sample.");
            self.update(wallclock, Some(dir));
            if self
                .guards
                .active_guards_mut()
                .extend_sample_as_needed(wallclock, &self.params, dir)
            {
                self.guards
                    .active_guards_mut()
                    .select_primary_guards(&self.params);
                match self.select_guard_once(usage, now) {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        trace!("Couldn't select guard after expanding sample: {}", e);
                    }
                }
            }
        }

        // Okay, that didn't work either.  If we were asked for a directory
        // guard, then we may be able to use a fallback.
        if usage.kind == GuardUsageKind::OneHopDirectory {
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
        let (source, id) = self
            .guards
            .active_guards()
            .pick_guard(usage, &self.params, now)?;
        let guard = self
            .guards
            .active_guards()
            .get(&id)
            .expect("Selected guard that wasn't in our sample!?")
            .get_external_rep();

        Ok((source, guard))
    }

    /// Helper: Select a fallback directory.
    ///
    /// Called when we have no guard information to use. Return values are as
    /// for [`GuardMgr::select_guard()`]
    fn select_fallback(
        &self,
        now: Instant,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        let fallback = self.fallbacks.choose(&mut rand::thread_rng(), now)?;
        Ok((sample::ListKind::Fallback, fallback.clone()))
    }
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
    ///
    /// (Not fully implemented yet.)
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FirstHop {
    /// The guard's identities
    id: FirstHopId,
    /// The addresses at which the guard can be contacted.
    orports: Vec<SocketAddr>,
}

impl FirstHop {
    /// Return the identities of this guard.
    pub fn id(&self) -> &FirstHopId {
        &self.id
    }
    /// Look up this guard in `netdir`.
    pub fn get_relay<'a>(&self, netdir: &'a NetDir) -> Option<Relay<'a>> {
        self.id().get_relay(netdir)
    }
}

// This is somewhat redundant with the implementation in crate::guard::Guard.
impl tor_linkspec::ChanTarget for FirstHop {
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
    }
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
        &self.id.as_ref().ed25519
    }
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
        &self.id.as_ref().rsa
    }
}

/// The purpose for which we plan to use a guard.
///
/// This can affect the guard selection algorithm.
#[derive(Clone, Debug, Eq, PartialEq, Educe)]
#[educe(Default)]
#[non_exhaustive]
pub enum GuardUsageKind {
    /// We want to use this guard for a data circuit.
    ///
    /// (This encompasses everything except the `OneHopDirectory` case.)
    #[educe(Default)]
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
#[derive(Clone, Debug, Default, derive_builder::Builder)]
#[builder(build_fn(error = "tor_config::ConfigBuildError"))]
pub struct GuardUsage {
    /// The purpose for which this guard will be used.
    #[builder(default)]
    kind: GuardUsageKind,
    /// A list of restrictions on which guard may be used.
    #[builder(default)]
    restrictions: Vec<GuardRestriction>,
}

impl GuardUsageBuilder {
    /// Create a new empty [`GuardUsageBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `restriction` to the list of restrictions on this guard usage.
    pub fn push_restriction(&mut self, restriction: GuardRestriction) -> &mut Self {
        self.restrictions
            .get_or_insert_with(Vec::new)
            .push(restriction);
        self
    }
}

/// A restriction that applies to a single request for a guard.
///
/// Restrictions differ from filters (see [`GuardFilter`]) in that
/// they apply to single requests, not to our entire set of guards.
/// They're suitable for things like making sure that we don't start
/// and end a circuit at the same relay, or requiring a specific
/// subprotocol version for certain kinds of requests.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum GuardRestriction {
    /// Don't pick a guard with the provided Ed25519 identity.
    AvoidId(pk::ed25519::Ed25519Identity),
    /// Don't pick a guard with any of the provided Ed25519 identities.
    AvoidAllIds(HashSet<pk::ed25519::Ed25519Identity>),
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
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
        let guardmgr = GuardMgr::new(rt, statemgr.clone(), [].into()).unwrap();
        let (con, mds) = testnet::construct_network().unwrap();
        let override_p = "guard-min-filtered-sample-size=5 guard-n-primary-guards=2"
            .parse()
            .unwrap();
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

            guardmgr.update_network(&netdir);

            let (id, mon, usable) = guardmgr.select_guard(usage, Some(&netdir)).unwrap();
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
            let guardmgr2 = GuardMgr::new(rt.clone(), statemgr.clone(), [].into()).unwrap();
            guardmgr2.update_network(&netdir);

            // Since the guard was confirmed, we should get the same one this time!
            let usage = GuardUsage::default();
            let (id2, _mon, _usable) = guardmgr2.select_guard(usage, Some(&netdir)).unwrap();
            assert_eq!(id2, id);
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
            guardmgr.update_network(&netdir);

            // We'll have the first two guard fail, which should make us
            // try a non-primary guard.
            let (id1, mon, _usable) = guardmgr.select_guard(u.clone(), Some(&netdir)).unwrap();
            mon.failed();
            guardmgr.flush_msg_queue().await; // avoid race
            guardmgr.flush_msg_queue().await; // avoid race
            let (id2, mon, _usable) = guardmgr.select_guard(u.clone(), Some(&netdir)).unwrap();
            mon.failed();
            guardmgr.flush_msg_queue().await; // avoid race
            guardmgr.flush_msg_queue().await; // avoid race

            assert!(id1 != id2);

            // Now we should get two sampled guards. They should be different.
            let (id3, mon3, usable3) = guardmgr.select_guard(u.clone(), Some(&netdir)).unwrap();
            let (id4, mon4, usable4) = guardmgr.select_guard(u.clone(), Some(&netdir)).unwrap();
            assert!(id3 != id4);

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
            guardmgr.update_network(&netdir);
            guardmgr.set_filter(GuardFilter::TestingLimitKeys, &netdir);

            let (guard, _mon, _usable) = guardmgr.select_guard(u, Some(&netdir)).unwrap();
            // Make sure that the filter worked.
            assert_eq!(guard.id().as_ref().rsa.as_bytes()[0] % 4, 0);
        });
    }

    #[test]
    fn external_status() {
        use tor_linkspec::ChanTarget;
        test_with_all_runtimes!(|rt| async move {
            let (guardmgr, _statemgr, netdir) = init(rt);
            let data_usage = GuardUsage::default();
            let dir_usage = GuardUsageBuilder::new()
                .kind(GuardUsageKind::OneHopDirectory)
                .build()
                .unwrap();
            guardmgr.update_network(&netdir);
            {
                // Override this parameter, so that we can get deterministic results below.
                let mut inner = guardmgr.inner.lock().unwrap();
                inner.params.dir_parallelism = 1;
            }

            let (guard, mon, _usable) = guardmgr
                .select_guard(data_usage.clone(), Some(&netdir))
                .unwrap();
            mon.succeeded();

            // Record that this guard gave us a bad directory object.
            guardmgr.note_external_failure(
                guard.ed_identity(),
                guard.rsa_identity(),
                ExternalActivity::DirCache,
            );

            // We ask for another guard, for data usage.  We should get the same
            // one as last time, since the director failure doesn't mean this
            // guard is useless as a primary guard.
            let (g2, mon, _usable) = guardmgr.select_guard(data_usage, Some(&netdir)).unwrap();
            assert_eq!(g2.ed_identity(), guard.ed_identity());
            mon.succeeded();

            // But if we ask for a guard for directory usage, we should get a
            // different one, since the last guard we gave out failed.
            let (g3, mon, _usable) = guardmgr
                .select_guard(dir_usage.clone(), Some(&netdir))
                .unwrap();
            assert_ne!(g3.ed_identity(), guard.ed_identity());
            mon.succeeded();

            // Now record a success for for directory usage.
            guardmgr.note_external_success(
                guard.ed_identity(),
                guard.rsa_identity(),
                ExternalActivity::DirCache,
            );

            // Now that the guard is working as a cache, asking for it should get us the same guard.
            let (g4, _mon, _usable) = guardmgr.select_guard(dir_usage, Some(&netdir)).unwrap();
            assert_eq!(g4.ed_identity(), guard.ed_identity());
        });
    }
}
