//! Abstract code to manage a set of tunnels which has underlying circuit(s).
//!
//! This module implements the real logic for deciding when and how to
//! launch tunnels, and for which tunnels to hand out in response to
//! which requests.
//!
//! For testing and abstraction purposes, this module _does not_
//! actually know anything about tunnels _per se_.  Instead,
//! everything is handled using a set of traits that are internal to this
//! crate:
//!
//!  * [`AbstractTunnel`] is a view of a tunnel.
//!  * [`AbstractTunnelBuilder`] knows how to build an `AbstractCirc`.
//!
//! Using these traits, the [`AbstractTunnelMgr`] object manages a set of
//! tunnels , launching them as necessary, and keeping track of the
//! restrictions on their use.

// TODO:
// - Testing
//    - Error from prepare_action()
//    - Error reported by restrict_mut?

use crate::config::CircuitTiming;
use crate::usage::{SupportedTunnelUsage, TargetTunnelUsage};
use crate::{DirInfo, Error, PathConfig, Result, timeouts};

use retry_error::RetryError;
use tor_async_utils::mpsc_channel_no_memquota;
use tor_basic_utils::retry::RetryDelay;
use tor_config::MutCfg;
use tor_error::{AbsRetryTime, HasRetryTime, debug_report, info_report, internal, warn_report};
#[cfg(feature = "vanguards")]
use tor_guardmgr::vanguards::VanguardMgr;
use tor_linkspec::CircTarget;
use tor_proto::circuit::UniqId;
use tor_proto::client::circuit::{CircParameters, Path};
use tor_rtcompat::{Runtime, SleepProviderExt};

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::{FutureExt, Shared};
use futures::stream::{FuturesUnordered, StreamExt};
use oneshot_fused_workaround as oneshot;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::sync::{self, Arc, Weak};
use std::time::{Duration, Instant};
use tor_rtcompat::SpawnExt;
use tracing::{debug, instrument, trace, warn};
use weak_table::PtrWeakHashSet;

mod streams;

/// Description of how we got a tunnel.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TunnelProvenance {
    /// This channel was newly launched, or was in progress and finished while
    /// we were waiting.
    NewlyCreated,
    /// This channel already existed when we asked for it.
    Preexisting,
}

/// An error returned when we cannot apply circuit restriction.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestrictionFailed {
    /// Tried to restrict a specification, but the tunnel didn't support the
    /// requested usage.
    #[error("Specification did not support desired usage")]
    NotSupported,
}

/// Minimal abstract view of a tunnel.
///
/// From this module's point of view, tunnels are simply objects
/// with unique identities, and a possible closed-state.
#[async_trait]
pub(crate) trait AbstractTunnel: Debug {
    /// Type for a unique identifier for tunnels.
    type Id: Clone + Debug + Hash + Eq + Send + Sync;
    /// Return the unique identifier for this tunnel.
    ///
    /// # Requirements
    ///
    /// The values returned by this function are unique for distinct
    /// tunnels.
    fn id(&self) -> Self::Id;

    /// Return true if this tunnel is usable for some purpose.
    ///
    /// Reasons a tunnel might be unusable include being closed.
    fn usable(&self) -> bool;

    /// Return a list of [`Path`] objects describing the only circuit in this tunnel.
    ///
    /// Returns an error if the tunnel has more than one tunnel.
    fn single_path(&self) -> tor_proto::Result<Arc<Path>>;

    /// Return the number of hops in this tunnel.
    ///
    /// Returns an error if the circuit is closed.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the tunnel. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn n_hops(&self) -> tor_proto::Result<usize>;

    /// Return true if this tunnel is closed and therefore unusable.
    fn is_closing(&self) -> bool;

    /// Return a process-unique identifier for this tunnel.
    fn unique_id(&self) -> UniqId;

    /// Extend the tunnel via the most appropriate handshake to a new `target` hop.
    async fn extend<T: CircTarget + Sync>(
        &self,
        target: &T,
        params: CircParameters,
    ) -> tor_proto::Result<()>;

    /// Return a time at which this tunnel is last known to be used,
    /// or None if it is in use right now (or has never been used).
    async fn last_known_to_be_used_at(&self) -> tor_proto::Result<Option<Instant>>;
}

/// A plan for an `AbstractCircBuilder` that can maybe be mutated by tests.
///
/// You should implement this trait using all default methods for all code that isn't test code.
pub(crate) trait MockablePlan {
    /// Add a reason string that was passed to `SleepProvider::block_advance()` to this object
    /// so that it knows what to pass to `::release_advance()`.
    fn add_blocked_advance_reason(&mut self, _reason: String) {}
}

/// An object that knows how to build tunnels.
///
/// This creates tunnels in two phases. First, a plan is
/// made for how to build the tunnel. This planning phase should be
/// relatively fast, and must not suspend or block.  Its purpose is to
/// get an early estimate of which operations the tunnel will be able
/// to support when it's done.
///
/// Second, the tunnel is actually built, using the plan as input.

#[async_trait]
pub(crate) trait AbstractTunnelBuilder<R: Runtime>: Send + Sync {
    /// The tunnel type that this builder knows how to build.
    type Tunnel: AbstractTunnel + Send + Sync;
    /// An opaque type describing how a given tunnel will be built.
    /// It may represent some or all of a path-or it may not.
    //
    // TODO: It would be nice to have this parameterized on a lifetime,
    // and have that lifetime depend on the lifetime of the directory.
    // But I don't think that rust can do that.
    //
    // HACK(eta): I don't like the fact that `MockablePlan` is necessary here.
    type Plan: Send + Debug + MockablePlan;

    // TODO: I'd like to have a Dir type here to represent
    // create::DirInfo, but that would need to be parameterized too,
    // and would make everything complicated.

    /// Form a plan for how to build a new tunnel that supports `usage`.
    ///
    /// Return an opaque Plan object, and a new spec describing what
    /// the tunnel will actually support when it's built.  (For
    /// example, if the input spec requests a tunnel that connect to
    /// port 80, then "planning" the tunnel might involve picking an
    /// exit that supports port 80, and the resulting spec might be
    /// the exit's complete list of supported ports.)
    ///
    /// # Requirements
    ///
    /// The resulting Spec must support `usage`.
    fn plan_tunnel(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(Self::Plan, SupportedTunnelUsage)>;

    /// Construct a tunnel according to a given plan.
    ///
    /// On success, return a spec describing what the tunnel can be used for,
    /// and the tunnel that was just constructed.
    ///
    /// This function should implement some kind of a timeout for
    /// tunnel that are taking too long.
    ///
    /// # Requirements
    ///
    /// The spec that this function returns _must_ support the usage
    /// that was originally passed to `plan_tunnel`.  It _must_ also
    /// contain the spec that was originally returned by
    /// `plan_tunnel`.
    async fn build_tunnel(&self, plan: Self::Plan) -> Result<(SupportedTunnelUsage, Self::Tunnel)>;

    /// Return a "parallelism factor" with which tunnels should be
    /// constructed for a given purpose.
    ///
    /// If this function returns N, then whenever we launch tunnels
    /// for this purpose, then we launch N in parallel.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    fn launch_parallelism(&self, usage: &TargetTunnelUsage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return a "parallelism factor" for which tunnels should be
    /// used for a given purpose.
    ///
    /// If this function returns N, then whenever we select among
    /// open tunnels for this purpose, we choose at random from the
    /// best N.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    // TODO: Possibly this doesn't belong in this trait.
    fn select_parallelism(&self, usage: &TargetTunnelUsage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return true if we are currently attempting to learn tunnel
    /// timeouts by building testing tunnels.
    fn learning_timeouts(&self) -> bool;

    /// Flush state to the state manager if we own the lock.
    ///
    /// Return `Ok(true)` if we saved, and `Ok(false)` if we didn't hold the lock.
    fn save_state(&self) -> Result<bool>;

    /// Return this builder's [`PathConfig`].
    fn path_config(&self) -> Arc<PathConfig>;

    /// Replace this builder's [`PathConfig`].
    // TODO: This is dead_code because we only call this for the CircuitBuilder specialization of
    // CircMgr, not from the generic version, because this trait doesn't provide guardmgr, which is
    // needed by the [`CircMgr::reconfigure`] function that would be the only caller of this. We
    // should add `guardmgr` to this trait, make [`CircMgr::reconfigure`] generic, and remove this
    // dead_code marking.
    #[allow(dead_code)]
    fn set_path_config(&self, new_config: PathConfig);

    /// Return a reference to this builder's timeout estimator.
    fn estimator(&self) -> &timeouts::Estimator;

    /// Return a reference to this builder's `VanguardMgr`.
    #[cfg(feature = "vanguards")]
    fn vanguardmgr(&self) -> &Arc<VanguardMgr<R>>;

    /// Replace our state with a new owning state, assuming we have
    /// storage permission.
    fn upgrade_to_owned_state(&self) -> Result<()>;

    /// Reload persistent state from disk, if we don't have storage permission.
    fn reload_state(&self) -> Result<()>;

    /// Return a reference to this builder's `GuardMgr`.
    fn guardmgr(&self) -> &tor_guardmgr::GuardMgr<R>;

    /// Reconfigure this builder using the latest set of network parameters.
    ///
    /// (NOTE: for now, this only affects tunnel timeout estimation.)
    fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters);
}

/// Enumeration to track the expiration state of a tunnel.
///
/// A tunnel an either be unused (at which point it should expire if it is
/// _still unused_ by a certain time, or dirty (at which point it should
/// expire after a certain duration).
///
/// All tunnels start out "unused" and become "dirty" when their spec
/// is first restricted -- that is, when they are first handed out to be
/// used for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpirationInfo {
    /// The tunnel has never been used, and has never been restricted for use with a request.
    Unused {
        /// A time when the tunnel was created.
        created: Instant,
    },

    /// The tunnel is not-long-lived; we will expire by waiting until a certain amount of time
    /// after it was first used.
    Dirty {
        /// The time at which this tunnel's spec was first restricted.
        dirty_since: Instant,
    },

    /// The tunnel is long-lived; we will expire by waiting until it has passed
    /// a certain amount of time without having any streams attached to it.
    LongLived {
        /// Last time at which the tunnel was checked and found not to have any streams.
        ///
        /// (This is a bit complicated: We have to be vague here, since we need
        /// an async check to find out that a tunnel is used, or when it actually
        /// became disused.)
        last_known_to_be_used_at: Instant,
    },
}

impl ExpirationInfo {
    /// Return an ExpirationInfo for a newly created tunnel.
    fn new(now: Instant) -> Self {
        ExpirationInfo::Unused { created: now }
    }

    /// Mark this ExpirationInfo as having been in-use at `now`.
    ///
    /// If `long_lived` is false, the associated tunnel should expire a certain amount of time
    /// after it was _first_ used.
    /// If `long_lived` is true, the associated tunnel should expire a certain amount of time
    /// after it was _last_ used.
    fn mark_used(&mut self, now: Instant, long_lived: bool) {
        if long_lived {
            *self = ExpirationInfo::LongLived {
                last_known_to_be_used_at: now,
            };
        } else {
            match self {
                ExpirationInfo::Unused { .. } => {
                    // This is our first time using this circuit; mark it dirty
                    *self = ExpirationInfo::Dirty { dirty_since: now };
                }
                ExpirationInfo::Dirty { .. } => {
                    // no need to update; we're tracking the time when the circuit _first_ became
                    // dirty, so further uses don't matter.
                }
                ExpirationInfo::LongLived { .. } => {
                    // shouldn't occur: we shouldn't be able to attach a stream with non-long-lived isolation
                    // to a tunnel marked as long-lived.  In this case we leave the timestamp alone.
                    // (If there were a bug here, it would be harmless, since we would
                    // correct the timestamp the next time we tried to expire the circuit.)
                }
            }
        }
    }

    /// Return an internal error if this ExpirationInfo is not marked as long-lived.
    fn check_long_lived(&self) -> Result<()> {
        match self {
            ExpirationInfo::Unused { .. } | ExpirationInfo::Dirty { .. } => Err(internal!(
                "Tunnel was not long-lived as expected. (Expiration status: {:?})",
                self
            )
            .into()),
            ExpirationInfo::LongLived { .. } => Ok(()),
        }
    }
}

/// Settings to determine when circuits are expired.
#[derive(Clone, Debug)]
pub(crate) struct ExpirationParameters {
    /// Any unused circuit is expired this long after it was created.
    expire_unused_after: Duration,
    /// Any non long-lived dirty circuit is expired this long after it first becomes dirty.
    expire_dirty_after: Duration,
    /// Any long-lived circuit is expired after having been disused for this long.
    expire_disused_after: Duration,
}

/// An entry for an open tunnel held by an `AbstractTunnelMgr`.
#[derive(Debug, Clone)]
pub(crate) struct OpenEntry<T> {
    /// The supported usage for this tunnel.
    spec: SupportedTunnelUsage,
    /// The tunnel under management.
    tunnel: Arc<T>,
    /// When does this tunnel expire?
    ///
    /// (Note that expired tunnels are removed from the manager,
    /// which does not actually close them until there are no more
    /// references to them.)
    expiration: ExpirationInfo,
}

impl<T: AbstractTunnel> OpenEntry<T> {
    /// Make a new OpenEntry for a given tunnel and spec.
    fn new(spec: SupportedTunnelUsage, tunnel: T, expiration: ExpirationInfo) -> Self {
        OpenEntry {
            spec,
            tunnel: tunnel.into(),
            expiration,
        }
    }

    /// Return true if the underlying tunnel can be used for `usage`.
    pub(crate) fn supports(&self, usage: &TargetTunnelUsage) -> bool {
        self.tunnel.usable() && self.spec.supports(usage)
    }

    /// Change the underlying tunnel's permissible usage, based on its having
    /// been used for `usage` at time `now`.
    ///
    /// Return an error if the tunnel may not be used for `usage`.
    fn restrict_mut(&mut self, usage: &TargetTunnelUsage, now: Instant) -> Result<()> {
        self.spec.restrict_mut(usage)?;
        self.expiration.mark_used(now, self.spec.is_long_lived());
        Ok(())
    }

    /// Find the "best" entry from a slice of OpenEntry for supporting
    /// a given `usage`.
    ///
    /// If `parallelism` is some N greater than 1, we pick randomly
    /// from the best `N` tunnels.
    ///
    /// # Requirements
    ///
    /// Requires that `ents` is nonempty, and that every element of `ents`
    /// supports `spec`.
    fn find_best<'a>(
        // we do not mutate `ents`, but to return `&mut Self` we must have a mutable borrow
        ents: &'a mut [&'a mut Self],
        usage: &TargetTunnelUsage,
        parallelism: usize,
    ) -> &'a mut Self {
        let _ = usage; // not yet used.
        use rand::seq::IndexedMutRandom as _;
        let parallelism = parallelism.clamp(1, ents.len());
        // TODO: Actually look over the whole list to see which is better.
        let slice = &mut ents[0..parallelism];
        let mut rng = rand::rng();
        slice.choose_mut(&mut rng).expect("Input list was empty")
    }

    /// Return true if this tunnel should be expired given that the current time is `now`,
    /// and the current settings are `params`.
    fn should_expire(&self, now: Instant, params: &ExpirationParameters) -> ShouldExpire {
        match self.expiration {
            ExpirationInfo::Unused { created } => {
                ShouldExpire::certain(now, created + params.expire_unused_after)
            }
            ExpirationInfo::Dirty { dirty_since } => {
                ShouldExpire::certain(now, dirty_since + params.expire_dirty_after)
            }
            ExpirationInfo::LongLived {
                last_known_to_be_used_at,
            } => {
                ShouldExpire::uncertain(now, last_known_to_be_used_at + params.expire_disused_after)
            }
        }
    }
}

/// When should a tunnel expire?
///
/// Reflects possible uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShouldExpire {
    /// The tunnel should expire now.
    Now,
    /// The circuit might expire now; we need to check.
    ///
    /// (This is the result we get when we know that this is a tunnel that should expire
    /// if it has gone for some duration D without having any streams on it,
    /// and that it definitely had a stream at time T.  It is now at least time T+D,
    /// but we don't know whether the tunnel has any streams in the intervening time.
    /// We need to call the async fn `last_known_to_be_used_at` to check.)
    PossiblyNow,
    /// The tunnel will not expire before the specified time.
    NotBefore(Instant),
}

impl ShouldExpire {
    /// Return a ShouldExpire reflecting an expiration that is known to be happening at `expiration`.
    fn certain(now: Instant, expiration: Instant) -> Self {
        if now >= expiration {
            ShouldExpire::Now
        } else {
            ShouldExpire::NotBefore(expiration)
        }
    }

    /// Return a ShouldExpire reflecting an expiration that is known to be no sooner than `expiration`,
    /// but possibly later.
    fn uncertain(now: Instant, expiration: Instant) -> Self {
        if now >= expiration {
            ShouldExpire::PossiblyNow
        } else {
            ShouldExpire::NotBefore(expiration)
        }
    }
}

/// A result type whose "Ok" value is the Id for a tunnel from B.
type PendResult<B, R> = Result<<<B as AbstractTunnelBuilder<R>>::Tunnel as AbstractTunnel>::Id>;

/// An in-progress tunnel request tracked by an `AbstractTunnelMgr`.
///
/// (In addition to tracking tunnels, `AbstractTunnelMgr` tracks
/// _requests_ for tunnels.  The manager uses these entries if it
/// finds that some tunnel created _after_ a request first launched
/// might meet the request's requirements.)
struct PendingRequest<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Usage for the operation requested by this request
    usage: TargetTunnelUsage,
    /// A channel to use for telling this request about tunnels that it
    /// might like.
    notify: mpsc::Sender<PendResult<B, R>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> PendingRequest<B, R> {
    /// Return true if this request would be supported by `spec`.
    fn supported_by(&self, spec: &SupportedTunnelUsage) -> bool {
        spec.supports(&self.usage)
    }
}

/// An entry for an under-construction in-progress tunnel tracked by
/// an `AbstractTunnelMgr`.
#[derive(Debug)]
struct PendingEntry<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Specification that this tunnel will support, if every pending
    /// request that is waiting for it is attached to it.
    ///
    /// This spec becomes more and more restricted as more pending
    /// requests are waiting for this tunnel.
    ///
    /// This spec is contained by circ_spec, and must support the usage
    /// of every pending request that's waiting for this tunnel.
    tentative_assignment: sync::Mutex<SupportedTunnelUsage>,
    /// A shared future for requests to use when waiting for
    /// notification of this tunnel's success.
    receiver: Shared<oneshot::Receiver<PendResult<B, R>>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> PendingEntry<B, R> {
    /// Make a new PendingEntry that starts out supporting a given
    /// spec.  Return that PendingEntry, along with a Sender to use to
    /// report the result of building this tunnel.
    fn new(spec: &SupportedTunnelUsage) -> (Self, oneshot::Sender<PendResult<B, R>>) {
        let tentative_assignment = sync::Mutex::new(spec.clone());
        let (sender, receiver) = oneshot::channel();
        let receiver = receiver.shared();
        let entry = PendingEntry {
            tentative_assignment,
            receiver,
        };
        (entry, sender)
    }

    /// Return true if this tunnel's current tentative assignment
    /// supports `usage`.
    fn supports(&self, usage: &TargetTunnelUsage) -> bool {
        let assignment = self.tentative_assignment.lock().expect("poisoned lock");
        assignment.supports(usage)
    }

    /// Try to change the tentative assignment of this tunnel by
    /// restricting it for use with `usage`.
    ///
    /// Return an error if the current tentative assignment didn't
    /// support `usage` in the first place.
    fn tentative_restrict_mut(&self, usage: &TargetTunnelUsage) -> Result<()> {
        if let Ok(mut assignment) = self.tentative_assignment.lock() {
            assignment.restrict_mut(usage)?;
        }
        Ok(())
    }

    /// Find the best PendingEntry values from a slice for use with
    /// `usage`.
    ///
    /// # Requirements
    ///
    /// The `ents` slice must not be empty.  Every element of `ents`
    /// must support the given spec.
    fn find_best(ents: &[Arc<Self>], usage: &TargetTunnelUsage) -> Vec<Arc<Self>> {
        // TODO: Actually look over the whole list to see which is better.
        let _ = usage; // currently unused
        vec![Arc::clone(&ents[0])]
    }
}

/// Wrapper type to represent the state between planning to build a
/// tunnel and constructing it.
#[derive(Debug)]
struct TunnelBuildPlan<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// The Plan object returned by [`AbstractTunnelBuilder::plan_tunnel`].
    plan: B::Plan,
    /// A sender to notify any pending requests when this tunnel is done.
    sender: oneshot::Sender<PendResult<B, R>>,
    /// A strong entry to the PendingEntry for this tunnel build attempt.
    pending: Arc<PendingEntry<B, R>>,
}

/// The inner state of an [`AbstractTunnelMgr`].
struct TunnelList<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// A map from tunnel ID to [`OpenEntry`] values for all managed
    /// open tunnels.
    ///
    /// A tunnel is added here from [`AbstractTunnelMgr::do_launch`] when we find
    /// that it completes successfully, and has not been cancelled.
    /// When we decide that such a tunnel should no longer be handed out for
    /// any new requests, we "retire" the tunnel by removing it from this map.
    #[allow(clippy::type_complexity)]
    open_tunnels: HashMap<<B::Tunnel as AbstractTunnel>::Id, OpenEntry<B::Tunnel>>,
    /// Weak-set of PendingEntry for tunnels that are being built.
    ///
    /// Because this set only holds weak references, and the only strong
    /// reference to the PendingEntry is held by the task building the tunnel,
    /// this set's members are lazily removed after the tunnel is either built
    /// or fails to build.
    ///
    /// This set is used for two purposes:
    ///
    /// 1. When a tunnel request finds that there is no open tunnel for its
    ///    purposes, it checks here to see if there is a pending tunnel that it
    ///    could wait for.
    /// 2. When a pending tunnel finishes building, it checks here to make sure
    ///    that it has not been cancelled. (Removing an entry from this set marks
    ///    it as cancelled.)
    ///
    /// An entry is added here in [`AbstractTunnelMgr::prepare_action`] when we
    /// decide that a tunnel needs to be launched.
    ///
    /// Later, in [`AbstractTunnelMgr::do_launch`], once the tunnel has finished
    /// (or failed), we remove the entry (by pointer identity).
    /// If we cannot find the entry, we conclude that the request has been
    /// _cancelled_, and so we discard any tunnel that was created.
    pending_tunnels: PtrWeakHashSet<Weak<PendingEntry<B, R>>>,
    /// Weak-set of PendingRequest for requests that are waiting for a
    /// tunnel to be built.
    ///
    /// Because this set only holds weak references, and the only
    /// strong reference to the PendingRequest is held by the task
    /// waiting for the tunnel to be built, this set's members are
    /// lazily removed after the request succeeds or fails.
    pending_requests: PtrWeakHashSet<Weak<PendingRequest<B, R>>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> TunnelList<B, R> {
    /// Make a new empty `CircList`
    fn new() -> Self {
        TunnelList {
            open_tunnels: HashMap::new(),
            pending_tunnels: PtrWeakHashSet::new(),
            pending_requests: PtrWeakHashSet::new(),
        }
    }

    /// Add `e` to the list of open tunnels.
    fn add_open(&mut self, e: OpenEntry<B::Tunnel>) {
        let id = e.tunnel.id();
        self.open_tunnels.insert(id, e);
    }

    /// Find all the usable open tunnels that support `usage`.
    ///
    /// Return None if there are no such tunnels.
    fn find_open(&mut self, usage: &TargetTunnelUsage) -> Option<Vec<&mut OpenEntry<B::Tunnel>>> {
        let list = self.open_tunnels.values_mut();
        let v = SupportedTunnelUsage::find_supported(list, usage);
        if v.is_empty() { None } else { Some(v) }
    }

    /// Find an open tunnel by ID.
    ///
    /// Return None if no such tunnels exists in this list.
    fn get_open_mut(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<&mut OpenEntry<B::Tunnel>> {
        self.open_tunnels.get_mut(id)
    }

    /// Extract an open tunnel by ID, removing it from this list.
    ///
    /// Return None if no such tunnel exists in this list.
    fn take_open(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<OpenEntry<B::Tunnel>> {
        self.open_tunnels.remove(id)
    }

    /// Remove tunnels based on expiration times.
    ///
    /// We remove every unused tunnel that is set to expire by
    /// `unused_cutoff`, and every dirty tunnel that has been dirty
    /// since before `dirty_cutoff`.
    ///
    /// Return the next time at which anything will definitely expire,
    /// and a list of long-lived tunnels where we need to check their usage status
    /// before we can be sure if they are expired.
    #[must_use]
    fn expire_tunnels(
        &mut self,
        now: Instant,
        params: &ExpirationParameters,
    ) -> (Option<Instant>, Vec<Weak<B::Tunnel>>) {
        let mut need_check = Vec::new();
        let mut earliest_expiration = None;
        self.open_tunnels
            .retain(|_k, v| match v.should_expire(now, params) {
                // Expires now: Do not retain.
                ShouldExpire::Now => false,

                // Will expire at `when`: keep, but update `earliest_expiration`.
                ShouldExpire::NotBefore(when) => {
                    earliest_expiration = match earliest_expiration {
                        Some(t) if t < when => Some(t),
                        _ => Some(when),
                    };
                    true
                }

                // Need to check tunnel to see if/when it is disused.
                ShouldExpire::PossiblyNow => {
                    need_check.push(Arc::downgrade(&v.tunnel));
                    true
                }
            });
        (earliest_expiration, need_check)
    }

    /// Return the time when the tunnel with given `id`, should expire.
    ///
    /// Return None if no such tunnel exists.
    fn tunnel_should_expire(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
        params: &ExpirationParameters,
    ) -> Option<ShouldExpire> {
        self.open_tunnels
            .get(id)
            .map(|v| v.should_expire(now, params))
    }

    /// Update the "last known to be in use" time of a long-lived tunnel with ID `id`,
    /// based on learning when it was last used.
    ///
    /// Expire the tunnel if appropriate.
    ///
    /// If the tunnel is still part of the map, return the next instant at which it might expire.
    ///
    /// Returns an error if the tunnel was present but was _not_ already marked as long-lived.
    fn update_long_lived_tunnel_last_used(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
        params: &ExpirationParameters,
        disused_since: &tor_proto::Result<Option<Instant>>,
    ) -> crate::Result<Option<Instant>> {
        let Ok(disused_since) = disused_since else {
            // got an error looking up disused time: discard the circuit.
            let discard = self.take_open(id);
            if let Some(ent) = discard {
                ent.expiration.check_long_lived()?;
            }
            return Ok(None);
        };
        let Some(tun) = self.open_tunnels.get_mut(id) else {
            // Circuit isn't there. Return.
            return Ok(None);
        };
        tun.expiration.check_long_lived()?;
        let last_known_in_use_at = disused_since.unwrap_or(now);

        tun.expiration.mark_used(last_known_in_use_at, true);
        match tun.should_expire(now, params) {
            ShouldExpire::Now | ShouldExpire::PossiblyNow => {
                let _discard = self.take_open(id);
                Ok(None)
            }
            ShouldExpire::NotBefore(instant) => Ok(Some(instant)),
        }
    }

    /// Add `pending` to the set of in-progress tunnels.
    fn add_pending_tunnel(&mut self, pending: Arc<PendingEntry<B, R>>) {
        self.pending_tunnels.insert(pending);
    }

    /// Find all pending tunnels that support `usage`.
    ///
    /// If no such tunnels are currently being built, return None.
    fn find_pending_tunnels(
        &self,
        usage: &TargetTunnelUsage,
    ) -> Option<Vec<Arc<PendingEntry<B, R>>>> {
        let result: Vec<_> = self
            .pending_tunnels
            .iter()
            .filter(|p| p.supports(usage))
            .filter(|p| !matches!(p.receiver.peek(), Some(Err(_))))
            .collect();

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Return true if `circ` is still pending.
    ///
    /// A tunnel will become non-pending when finishes (successfully or not), or when it's
    /// removed from this list via `clear_all_tunnels()`.
    fn tunnel_is_pending(&self, circ: &Arc<PendingEntry<B, R>>) -> bool {
        self.pending_tunnels.contains(circ)
    }

    /// Construct and add a new entry to the set of request waiting
    /// for a tunnel.
    ///
    /// Return the request, and a new receiver stream that it should
    /// use for notification of possible tunnels to use.
    fn add_pending_request(&mut self, pending: &Arc<PendingRequest<B, R>>) {
        self.pending_requests.insert(Arc::clone(pending));
    }

    /// Return all pending requests that would be satisfied by a tunnel
    /// that supports `circ_spec`.
    fn find_pending_requests(
        &self,
        circ_spec: &SupportedTunnelUsage,
    ) -> Vec<Arc<PendingRequest<B, R>>> {
        self.pending_requests
            .iter()
            .filter(|pend| pend.supported_by(circ_spec))
            .collect()
    }

    /// Clear all pending and open tunnels.
    ///
    /// Calling `clear_all_tunnels` ensures that any request that is answered _after
    /// this method runs_ will receive a tunnels that was launched _after this
    /// method runs_.
    fn clear_all_tunnels(&mut self) {
        // Note that removing entries from pending_circs will also cause the
        // tunnel tasks to realize that they are cancelled when they
        // go to tell anybody about their results.
        self.pending_tunnels.clear();
        self.open_tunnels.clear();
    }
}

/// Timing information for tunnels that have been built but never used.
///
/// Currently taken from the network parameters.
struct UnusedTimings {
    /// Minimum lifetime of a tunnel created while learning
    /// tunnel timeouts.
    learning: Duration,
    /// Minimum lifetime of a tunnel created while not learning
    /// tunnel timeouts.
    not_learning: Duration,
}

// This isn't really fallible, given the definitions of the underlying
// types.
#[allow(clippy::fallible_impl_from)]
impl From<&tor_netdir::params::NetParameters> for UnusedTimings {
    fn from(v: &tor_netdir::params::NetParameters) -> Self {
        // These try_into() calls can't fail, so unwrap() can't panic.
        #[allow(clippy::unwrap_used)]
        UnusedTimings {
            learning: v
                .unused_client_circ_timeout_while_learning_cbt
                .try_into()
                .unwrap(),
            not_learning: v.unused_client_circ_timeout.try_into().unwrap(),
        }
    }
}

/// Abstract implementation for tunnel management.
///
/// The algorithm provided here is fairly simple. In its simplest form:
///
/// When somebody asks for a tunnel for a given operation: if we find
/// one open already, we return it.  If we find in-progress tunnels
/// that would meet our needs, we wait for one to finish (or for all
/// to fail).  And otherwise, we launch one or more tunnels to meet the
/// request's needs.
///
/// If this process fails, then we retry it, up to a timeout or a
/// numerical limit.
///
/// If a tunnel not previously considered for a given request
/// finishes before the request is satisfied, and if the tunnel would
/// satisfy the request, we try to give that tunnel as an answer to
/// that request even if it was not one of the tunnels that request
/// was waiting for.
pub(crate) struct AbstractTunnelMgr<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Builder used to construct tunnels.
    builder: B,
    /// An asynchronous runtime to use for launching tasks and
    /// checking timeouts.
    runtime: R,
    /// A CircList to manage our list of tunnels, requests, and
    /// pending tunnels.
    tunnels: sync::Mutex<TunnelList<B, R>>,

    /// Configured information about when to expire tunnels and requests.
    circuit_timing: MutCfg<CircuitTiming>,

    /// Minimum lifetime of an unused tunnel.
    ///
    /// Derived from the network parameters.
    unused_timing: sync::Mutex<UnusedTimings>,
}

/// An action to take in order to satisfy a request for a tunnel.
enum Action<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// We found an open tunnel: return immediately.
    Open(Arc<B::Tunnel>),
    /// We found one or more pending tunnels: wait until one succeeds,
    /// or all fail.
    Wait(FuturesUnordered<Shared<oneshot::Receiver<PendResult<B, R>>>>),
    /// We should launch tunnels: here are the instructions for how
    /// to do so.
    Build(Vec<TunnelBuildPlan<B, R>>),
}

impl<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> AbstractTunnelMgr<B, R> {
    /// Construct a new AbstractTunnelMgr.
    pub(crate) fn new(builder: B, runtime: R, circuit_timing: CircuitTiming) -> Self {
        let circs = sync::Mutex::new(TunnelList::new());
        let dflt_params = tor_netdir::params::NetParameters::default();
        let unused_timing = (&dflt_params).into();
        AbstractTunnelMgr {
            builder,
            runtime,
            tunnels: circs,
            circuit_timing: circuit_timing.into(),
            unused_timing: sync::Mutex::new(unused_timing),
        }
    }

    /// Reconfigure this manager using the latest set of network parameters.
    pub(crate) fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        let mut u = self
            .unused_timing
            .lock()
            .expect("Poisoned lock for unused_timing");
        *u = p.into();
    }

    /// Return this manager's [`CircuitTiming`].
    pub(crate) fn circuit_timing(&self) -> Arc<CircuitTiming> {
        self.circuit_timing.get()
    }

    /// Return this manager's [`CircuitTiming`].
    pub(crate) fn set_circuit_timing(&self, new_config: CircuitTiming) {
        self.circuit_timing.replace(new_config);
    }
    /// Return a circuit suitable for use with a given `usage`,
    /// creating that circuit if necessary, and restricting it
    /// under the assumption that it will be used for that spec.
    ///
    /// This is the primary entry point for AbstractTunnelMgr.
    #[allow(clippy::cognitive_complexity)] // TODO #2010: Refactor?
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(Arc<B::Tunnel>, TunnelProvenance)> {
        /// Largest number of "resets" that we will accept in this attempt.
        ///
        /// A "reset" is an internally generated error that does not represent a
        /// real problem; only a "whoops, got to try again" kind of a situation.
        /// For example, if we reconfigure in the middle of an attempt and need
        /// to re-launch the circuit, that counts as a "reset", since there was
        /// nothing actually _wrong_ with the circuit we were building.
        ///
        /// We accept more resets than we do real failures. However,
        /// we don't accept an unlimited number: we don't want to inadvertently
        /// permit infinite loops here. If we ever bump against this limit, we
        /// should not automatically increase it: we should instead figure out
        /// why it is happening and try to make it not happen.
        const MAX_RESETS: usize = 8;

        let circuit_timing = self.circuit_timing();
        let timeout_at = self.runtime.now() + circuit_timing.request_timeout;
        let max_tries = circuit_timing.request_max_retries;
        // We compute the maximum number of failures by dividing the maximum
        // number of circuits to attempt by the number that will be launched in
        // parallel for each iteration.
        let max_failures = usize::div_ceil(
            max_tries as usize,
            std::cmp::max(1, self.builder.launch_parallelism(usage)),
        );

        let mut retry_schedule = RetryDelay::from_msec(100);
        let mut retry_err = RetryError::<Box<Error>>::in_attempt_to("find or build a tunnel");

        let mut n_failures = 0;
        let mut n_resets = 0;

        for attempt_num in 1.. {
            // How much time is remaining?
            let remaining = match timeout_at.checked_duration_since(self.runtime.now()) {
                None => {
                    retry_err.push_timed(
                        Error::RequestTimeout,
                        self.runtime.now(),
                        Some(self.runtime.wallclock()),
                    );
                    break;
                }
                Some(t) => t,
            };

            let error = match self.prepare_action(usage, dir, true) {
                Ok(action) => {
                    // We successfully found an action: Take that action.
                    let outcome = self
                        .runtime
                        .timeout(remaining, Arc::clone(self).take_action(action, usage))
                        .await;

                    match outcome {
                        Ok(Ok(circ)) => return Ok(circ),
                        Ok(Err(e)) => {
                            debug!("Circuit attempt {} failed.", attempt_num);
                            Error::RequestFailed(e)
                        }
                        Err(_) => {
                            // We ran out of "remaining" time; there is nothing
                            // more to be done.
                            warn!("All tunnel attempts failed due to timeout");
                            retry_err.push_timed(
                                Error::RequestTimeout,
                                self.runtime.now(),
                                Some(self.runtime.wallclock()),
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    // We couldn't pick the action!
                    debug_report!(
                        &e,
                        "Couldn't pick action for tunnel attempt {}",
                        attempt_num,
                    );
                    e
                }
            };

            // There's been an error.  See how long we wait before we retry.
            let now = self.runtime.now();
            let retry_time =
                error.abs_retry_time(now, || retry_schedule.next_delay(&mut rand::rng()));

            let (count, count_limit) = if error.is_internal_reset() {
                (&mut n_resets, MAX_RESETS)
            } else {
                (&mut n_failures, max_failures)
            };
            // Record the error, flattening it if needed.
            match error {
                // Flatten nested RetryError, using mockable time for each error
                Error::RequestFailed(e) => {
                    retry_err.extend_from_retry_error(e);
                }
                e => retry_err.push_timed(e, now, Some(self.runtime.wallclock())),
            }

            *count += 1;
            // If we have reached our limit of this kind of problem, we're done.
            if *count >= count_limit {
                warn!("Reached circuit build retry limit, exiting...");
                break;
            }

            // Wait, or not, as appropriate.
            match retry_time {
                AbsRetryTime::Immediate => {}
                AbsRetryTime::Never => break,
                AbsRetryTime::At(t) => {
                    let remaining = timeout_at.saturating_duration_since(now);
                    let delay = t.saturating_duration_since(now);
                    trace!(?delay, "Waiting to retry...");
                    self.runtime.sleep(std::cmp::min(delay, remaining)).await;
                }
            }
        }

        warn!("Request failed");
        Err(Error::RequestFailed(retry_err))
    }

    /// Make sure a circuit exists, without actually asking for it.
    ///
    /// Make sure that there is a circuit (built or in-progress) that could be
    /// used for `usage`, and launch one or more circuits in a background task
    /// if there is not.
    // TODO: This should probably take some kind of parallelism parameter.
    #[cfg(test)]
    pub(crate) async fn ensure_tunnel(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<()> {
        let action = self.prepare_action(usage, dir, false)?;
        if let Action::Build(plans) = action {
            for plan in plans {
                let self_clone = Arc::clone(self);
                let _ignore_receiver = self_clone.spawn_launch(usage, plan);
            }
        }

        Ok(())
    }

    /// Choose which action we should take in order to provide a tunnel
    /// for a given `usage`.
    ///
    /// If `restrict_circ` is true, we restrict the spec of any
    /// circ we decide to use to mark that it _is_ being used for
    /// `usage`.
    #[instrument(level = "trace", skip_all)]
    fn prepare_action(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
        restrict_circ: bool,
    ) -> Result<Action<B, R>> {
        let mut list = self.tunnels.lock().expect("poisoned lock");

        if let Some(mut open) = list.find_open(usage) {
            // We have open tunnels that meet the spec: return the best one.
            let parallelism = self.builder.select_parallelism(usage);
            let best = OpenEntry::find_best(&mut open, usage, parallelism);
            if restrict_circ {
                let now = self.runtime.now();
                best.restrict_mut(usage, now)?;
            }
            // TODO: If we have fewer tunnels here than our select
            // parallelism, perhaps we should launch more?

            return Ok(Action::Open(best.tunnel.clone()));
        }

        if let Some(pending) = list.find_pending_tunnels(usage) {
            // There are pending tunnels that could meet the spec.
            // Restrict them under the assumption that they could all
            // be used for this, and then wait until one is ready (or
            // all have failed)
            let best = PendingEntry::find_best(&pending, usage);
            if restrict_circ {
                for item in &best {
                    // TODO: Do we want to tentatively restrict _all_ of these?
                    // not clear to me.
                    item.tentative_restrict_mut(usage)?;
                }
            }
            let stream = best.iter().map(|item| item.receiver.clone()).collect();
            // TODO: if we have fewer tunnels here than our launch
            // parallelism, we might want to launch more.

            return Ok(Action::Wait(stream));
        }

        // Okay, we need to launch tunnels here.
        let parallelism = std::cmp::max(1, self.builder.launch_parallelism(usage));
        let mut plans = Vec::new();
        let mut last_err = None;
        for _ in 0..parallelism {
            match self.plan_by_usage(dir, usage) {
                Ok((pending, plan)) => {
                    list.add_pending_tunnel(pending);
                    plans.push(plan);
                }
                Err(e) => {
                    debug!("Unable to make a plan for {:?}: {}", usage, e);
                    last_err = Some(e);
                }
            }
        }
        if !plans.is_empty() {
            Ok(Action::Build(plans))
        } else if let Some(last_err) = last_err {
            Err(last_err)
        } else {
            // we didn't even try to plan anything!
            Err(internal!("no plans were built, but no errors were found").into())
        }
    }

    /// Execute an action returned by pick-action, and return the
    /// resulting tunnel or error.
    #[allow(clippy::cognitive_complexity, clippy::type_complexity)] // TODO #2010: Refactor
    #[instrument(level = "trace", skip_all)]
    async fn take_action(
        self: Arc<Self>,
        act: Action<B, R>,
        usage: &TargetTunnelUsage,
    ) -> std::result::Result<(Arc<B::Tunnel>, TunnelProvenance), RetryError<Box<Error>>> {
        /// Store the error `err` into `retry_err`, as appropriate.
        fn record_error<R: Runtime>(
            retry_err: &mut RetryError<Box<Error>>,
            source: streams::Source,
            building: bool,
            mut err: Error,
            runtime: &R,
        ) {
            if source == streams::Source::Right {
                // We don't care about this error, since it is from neither a tunnel we launched
                // nor one that we're waiting on.
                return;
            }
            if !building {
                // We aren't building our own tunnels, so our errors are
                // secondary reports of other tunnels' failures.
                err = Error::PendingFailed(Box::new(err));
            }
            retry_err.push_timed(err, runtime.now(), Some(runtime.wallclock()));
        }
        /// Return a string describing what it means, within the context of this
        /// function, to have gotten an answer from `source`.
        fn describe_source(building: bool, source: streams::Source) -> &'static str {
            match (building, source) {
                (_, streams::Source::Right) => "optimistic advice",
                (true, streams::Source::Left) => "tunnel we're building",
                (false, streams::Source::Left) => "pending tunnel",
            }
        }

        // Get or make a stream of futures to wait on.
        let (building, wait_on_stream) = match act {
            Action::Open(c) => {
                // There's already a perfectly good open tunnel; we can return
                // it now.
                trace!("Returning existing tunnel.");
                return Ok((c, TunnelProvenance::Preexisting));
            }
            Action::Wait(f) => {
                // There is one or more pending tunnel that we're waiting for.
                // If any succeeds, we try to use it.  If they all fail, we
                // fail.
                trace!("Waiting for tunnel.");
                (false, f)
            }
            Action::Build(plans) => {
                // We're going to launch one or more tunnels in parallel.  We
                // report success if any succeeds, and failure of they all fail.
                trace!("Building new tunnel.");
                let futures = FuturesUnordered::new();
                for plan in plans {
                    let self_clone = Arc::clone(&self);
                    // (This is where we actually launch tunnels.)
                    futures.push(self_clone.spawn_launch(usage, plan));
                }
                (true, futures)
            }
        };

        // Insert ourself into the list of pending requests, and make a
        // stream for us to listen on for notification from pending tunnels
        // other than those we are pending on.
        let (pending_request, additional_stream) = {
            // We don't want this queue to participate in memory quota tracking.
            // There isn't any tunnel yet, so there wouldn't be anything to account it to.
            // If this queue has the oldest data, probably the whole system is badly broken.
            // Tearing down the whole tunnel manager won't help.
            let (send, recv) = mpsc_channel_no_memquota(8);
            let pending = Arc::new(PendingRequest {
                usage: usage.clone(),
                notify: send,
            });

            let mut list = self.tunnels.lock().expect("poisoned lock");
            list.add_pending_request(&pending);

            (pending, recv)
        };

        // We use our "select_biased" stream combiner here to ensure that:
        //   1) Circuits from wait_on_stream (the ones we're pending on) are
        //      preferred.
        //   2) We exit this function when those tunnels are exhausted.
        //   3) We still get notified about other tunnels that might meet our
        //      interests.
        //
        // The events from Left stream are the oes that we explicitly asked for,
        // so we'll treat errors there as real problems.  The events from the
        // Right stream are ones that we got opportunistically told about; it's
        // not a big deal if those fail.
        let mut incoming = streams::select_biased(wait_on_stream, additional_stream.map(Ok));

        let mut retry_error = RetryError::in_attempt_to("wait for tunnels");

        while let Some((src, id)) = incoming.next().await {
            match id {
                Ok(Ok(ref id)) => {
                    // Great, we have a tunnel . See if we can use it!
                    let mut list = self.tunnels.lock().expect("poisoned lock");
                    if let Some(ent) = list.get_open_mut(id) {
                        let now = self.runtime.now();
                        match ent.restrict_mut(usage, now) {
                            Ok(()) => {
                                // Great, this will work.  We drop the
                                // pending request now explicitly to remove
                                // it from the list.
                                drop(pending_request);
                                if matches!(ent.expiration, ExpirationInfo::Unused { .. }) {
                                    let try_to_expire_after = if ent.spec.is_long_lived() {
                                        self.circuit_timing().disused_circuit_timeout
                                    } else {
                                        self.circuit_timing().max_dirtiness
                                    };
                                    // Since this tunnel hasn't been used yet, schedule expiration
                                    // task after `max_dirtiness` from now.
                                    spawn_expiration_task(
                                        &self.runtime,
                                        Arc::downgrade(&self),
                                        ent.tunnel.id(),
                                        now + try_to_expire_after,
                                    );
                                }
                                return Ok((ent.tunnel.clone(), TunnelProvenance::NewlyCreated));
                            }
                            Err(e) => {
                                // In this case, a `UsageMismatched` error just means that we lost the race
                                // to restrict this tunnel.
                                let e = match e {
                                    Error::UsageMismatched(e) => Error::LostUsabilityRace(e),
                                    x => x,
                                };
                                if src == streams::Source::Left {
                                    info_report!(
                                        &e,
                                        "{} suggested we use {:?}, but restrictions failed",
                                        describe_source(building, src),
                                        id,
                                    );
                                } else {
                                    debug_report!(
                                        &e,
                                        "{} suggested we use {:?}, but restrictions failed",
                                        describe_source(building, src),
                                        id,
                                    );
                                }
                                record_error(&mut retry_error, src, building, e, &self.runtime);
                                continue;
                            }
                        }
                    }
                }
                Ok(Err(ref e)) => {
                    debug!("{} sent error {:?}", describe_source(building, src), e);
                    record_error(&mut retry_error, src, building, e.clone(), &self.runtime);
                }
                Err(oneshot::Canceled) => {
                    debug!(
                        "{} went away (Canceled), quitting take_action right away",
                        describe_source(building, src)
                    );
                    record_error(
                        &mut retry_error,
                        src,
                        building,
                        Error::PendingCanceled,
                        &self.runtime,
                    );
                    return Err(retry_error);
                }
            }

            debug!(
                "While waiting on tunnel: {:?} from {}",
                id,
                describe_source(building, src)
            );
        }

        // Nothing worked.  We drop the pending request now explicitly
        // to remove it from the list.  (We could just let it get dropped
        // implicitly, but that's a bit confusing.)
        drop(pending_request);

        Err(retry_error)
    }

    /// Given a directory and usage, compute the necessary objects to
    /// build a tunnel: A [`PendingEntry`] to keep track of the in-process
    /// tunnel, and a [`TunnelBuildPlan`] that we'll give to the thread
    /// that will build the tunnel.
    ///
    /// The caller should probably add the resulting `PendingEntry` to
    /// `self.circs`.
    ///
    /// This is an internal function that we call when we're pretty sure
    /// we want to build a tunnel.
    #[allow(clippy::type_complexity)]
    fn plan_by_usage(
        &self,
        dir: DirInfo<'_>,
        usage: &TargetTunnelUsage,
    ) -> Result<(Arc<PendingEntry<B, R>>, TunnelBuildPlan<B, R>)> {
        let (plan, bspec) = self.builder.plan_tunnel(usage, dir)?;
        let (pending, sender) = PendingEntry::new(&bspec);
        let pending = Arc::new(pending);

        let plan = TunnelBuildPlan {
            plan,
            sender,
            pending: Arc::clone(&pending),
        };

        Ok((pending, plan))
    }

    /// Launch a managed tunnel for a target usage, without checking
    /// whether one already exists or is pending.
    ///
    /// Return a listener that will be informed when the tunnel is done.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn launch_by_usage(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<Shared<oneshot::Receiver<PendResult<B, R>>>> {
        let (pending, plan) = self.plan_by_usage(dir, usage)?;

        self.tunnels
            .lock()
            .expect("Poisoned lock for tunnel list")
            .add_pending_tunnel(pending);

        Ok(Arc::clone(self).spawn_launch(usage, plan))
    }

    /// Spawn a background task to launch a tunnel, and report its status.
    ///
    /// The `usage` argument is the usage from the original request that made
    /// us build this tunnel.
    #[instrument(level = "trace", skip_all)]
    fn spawn_launch(
        self: Arc<Self>,
        usage: &TargetTunnelUsage,
        plan: TunnelBuildPlan<B, R>,
    ) -> Shared<oneshot::Receiver<PendResult<B, R>>> {
        let _ = usage; // Currently unused.
        let TunnelBuildPlan {
            mut plan,
            sender,
            pending,
        } = plan;
        let request_loyalty = self.circuit_timing().request_loyalty;

        let wait_on_future = pending.receiver.clone();
        let runtime = self.runtime.clone();
        let runtime_copy = self.runtime.clone();

        let tid = rand::random::<u64>();
        // We release this block when the tunnel builder task terminates.
        let reason = format!("tunnel builder task {}", tid);
        runtime.block_advance(reason.clone());
        // During tests, the `FakeBuilder` will need to release the block in order to fake a timeout
        // correctly.
        plan.add_blocked_advance_reason(reason);

        runtime
            .spawn(async move {
                let self_clone = Arc::clone(&self);
                let future = AssertUnwindSafe(self_clone.do_launch(plan, pending)).catch_unwind();
                let (new_spec, reply) = match future.await {
                    Ok(x) => x, // Success or regular failure
                    Err(e) => {
                        // Okay, this is a panic.  We have to tell the calling
                        // thread about it, then exit this tunnel builder task.
                        let _ = sender.send(Err(internal!("tunnel build task panicked").into()));
                        std::panic::panic_any(e);
                    }
                };

                // Tell anybody who was listening about it that this
                // tunnel is now usable or failed.
                //
                // (We ignore any errors from `send`: That just means that nobody
                // was waiting for this tunnel.)
                let _ = sender.send(reply.clone());

                if let Some(new_spec) = new_spec {
                    // Wait briefly before we notify opportunistically.  This
                    // delay will give the tunnels that were originally
                    // specifically intended for a request a little more time
                    // to finish, before we offer it this tunnel instead.
                    let sl = runtime_copy.sleep(request_loyalty);
                    runtime_copy.allow_one_advance(request_loyalty);
                    sl.await;

                    let pending = {
                        let list = self.tunnels.lock().expect("poisoned lock");
                        list.find_pending_requests(&new_spec)
                    };
                    for pending_request in pending {
                        let _ = pending_request.notify.clone().try_send(reply.clone());
                    }
                }
                runtime_copy.release_advance(format!("tunnel builder task {}", tid));
            })
            .expect("Couldn't spawn tunnel-building task");

        wait_on_future
    }

    /// Run in the background to launch a tunnel. Return a 2-tuple of the new
    /// tunnel spec and the outcome that should be sent to the initiator.
    #[instrument(level = "trace", skip_all)]
    async fn do_launch(
        self: Arc<Self>,
        plan: <B as AbstractTunnelBuilder<R>>::Plan,
        pending: Arc<PendingEntry<B, R>>,
    ) -> (Option<SupportedTunnelUsage>, PendResult<B, R>) {
        let outcome = self.builder.build_tunnel(plan).await;

        match outcome {
            Err(e) => (None, Err(e)),
            Ok((new_spec, tunnel)) => {
                let id = tunnel.id();

                let use_duration = self.pick_use_duration();
                let now = self.runtime.now();
                let exp_inst = now + use_duration;
                let runtime_copy = self.runtime.clone();
                spawn_expiration_task(&runtime_copy, Arc::downgrade(&self), tunnel.id(), exp_inst);
                // I used to call restrict_mut here, but now I'm not so
                // sure. Doing restrict_mut makes sure that this
                // tunnel will be suitable for the request that asked
                // for us in the first place, but that should be
                // ensured anyway by our tracking its tentative
                // assignment.
                //
                // new_spec.restrict_mut(&usage_copy).unwrap();
                let use_before = ExpirationInfo::new(now);
                let open_ent = OpenEntry::new(new_spec.clone(), tunnel, use_before);
                {
                    let mut list = self.tunnels.lock().expect("poisoned lock");
                    // Finally, before we return this tunnel, we need to make
                    // sure that this pending tunnel is still pending.  (If it
                    // is not pending, then it was cancelled through a call to
                    // `retire_all_tunnels`, and the configuration that we used
                    // to launch it is now sufficiently outdated that we should
                    // no longer give this tunnel to a client.)
                    if list.tunnel_is_pending(&pending) {
                        list.add_open(open_ent);
                        // We drop our reference to 'pending' here:
                        // this should make all the weak references to
                        // the `PendingEntry` become dangling.
                        drop(pending);
                        (Some(new_spec), Ok(id))
                    } else {
                        // This tunnel is no longer pending! It must have been cancelled, probably
                        // by a call to retire_all_tunnels()
                        drop(pending); // ibid
                        (None, Err(Error::CircCanceled))
                    }
                }
            }
        }
    }

    /// Return the currently configured expiration parameters.
    fn expiration_params(&self) -> ExpirationParameters {
        let expire_unused_after = self.pick_use_duration();
        let expire_dirty_after = self.circuit_timing().max_dirtiness;
        let expire_disused_after = self.circuit_timing().disused_circuit_timeout;

        ExpirationParameters {
            expire_unused_after,
            expire_dirty_after,
            expire_disused_after,
        }
    }

    /// Plan and launch a new tunnel to a given target, bypassing our managed
    /// pool of tunnels.
    ///
    /// This method will always return a new tunnel, and never return a tunnel
    /// that this CircMgr gives out for anything else.
    ///
    /// The new tunnel will participate in the guard and timeout apparatus as
    /// appropriate, no retry attempt will be made if the tunnel fails.
    #[cfg(feature = "hs-common")]
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn launch_unmanaged(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(SupportedTunnelUsage, B::Tunnel)> {
        let (_, plan) = self.plan_by_usage(dir, usage)?;
        self.builder.build_tunnel(plan.plan).await
    }

    /// Remove the tunnel with a given `id` from this manager.
    ///
    /// After this function is called, that tunnel will no longer be handed
    /// out to any future requests.
    ///
    /// Return None if we have no tunnel with the given ID.
    pub(crate) fn take_tunnel(
        &self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<Arc<B::Tunnel>> {
        let mut list = self.tunnels.lock().expect("poisoned lock");
        list.take_open(id).map(|e| e.tunnel)
    }

    /// Remove all open and pending tunnels and from this manager, to ensure
    /// they can't be given out for any more requests.
    ///
    /// Calling `retire_all_tunnels` ensures that any tunnel request that gets
    /// an  answer _after this method runs_ will receive a tunnel that was
    /// launched _after this method runs_.
    ///
    /// We call this method this when our configuration changes in such a way
    /// that we want to make sure that any new (or pending) requests will
    /// receive tunnels that are built using the new configuration.
    //
    // For more information, see documentation on [`CircuitList::open_circs`],
    // [`CircuitList::pending_circs`], and comments in `do_launch`.
    pub(crate) fn retire_all_tunnels(&self) {
        let mut list = self.tunnels.lock().expect("poisoned lock");
        list.clear_all_tunnels();
    }

    /// Expire tunnels according to the rules in `config` and the
    /// current time `now`.
    ///
    /// Expired tunnels will not be automatically closed, but they will
    /// no longer be given out for new tunnels.
    ///
    /// Return the earliest time at which any current tunnel will expire.
    pub(crate) async fn expire_tunnels(&self, now: Instant) -> Option<Instant> {
        let expiration_params = self.expiration_params();

        // While holding the lock, we call TunnelList::expire_tunnels.
        // That function will expire what it can, and return a list of the tunnels for which
        // we need to call `disused_since`.
        let (mut earliest_expiration, need_to_check) = {
            let mut list = self.tunnels.lock().expect("poisoned lock");
            list.expire_tunnels(now, &expiration_params)
        };

        // Now we've dropped the lock, and can do async checks.
        let mut last_known_usage = Vec::new();
        for tunnel in need_to_check {
            let Some(tunnel) = Weak::upgrade(&tunnel) else {
                continue; // The tunnel is already gone.
            };
            last_known_usage.push((tunnel.id(), tunnel.last_known_to_be_used_at().await));
        }

        // Now get the lock again, and tell the list what we learned.
        //
        // Note that if this function is called twice simultaneously, in some corner cases, we might
        // decide to expire something twice.  That's okay.
        {
            let mut list = self.tunnels.lock().expect("poisoned lock");
            for (id, disused_since) in last_known_usage {
                match list.update_long_lived_tunnel_last_used(
                    &id,
                    now,
                    &expiration_params,
                    &disused_since,
                ) {
                    Ok(Some(may_expire)) => {
                        earliest_expiration = match earliest_expiration {
                            Some(exp) if exp < may_expire => Some(exp),
                            _ => Some(may_expire),
                        };
                    }
                    Ok(None) => {}
                    Err(e) => warn_report!(e, "Error while updating status on tunnel {:?}", id),
                }
            }
        }

        earliest_expiration
    }

    /// Consider expiring the tunnel with given tunnel `id`,
    /// according to the rules in `config` and the current time `now`.
    ///
    /// Returns None if the circuit is expired; otherwise returns the next time at which the circuit may expire.
    pub(crate) async fn consider_expiring_tunnel(
        &self,
        tun_id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
    ) -> Result<Option<Instant>> {
        let expiration_params = self.expiration_params();

        // With the lock, call TunneList::tunnel_should_expire, and expire it (or don't)
        // if the decision is obvious.
        let tunnel = {
            let mut list: sync::MutexGuard<'_, TunnelList<B, R>> =
                self.tunnels.lock().expect("poisoned lock");
            let Some(should_expire) = list.tunnel_should_expire(tun_id, now, &expiration_params)
            else {
                return Ok(None);
            };
            match should_expire {
                ShouldExpire::Now => {
                    let _discard = list.take_open(tun_id);
                    return Ok(None);
                }
                ShouldExpire::NotBefore(t) => return Ok(Some(t)),
                ShouldExpire::PossiblyNow => {
                    let Some(tunnel_ent) = list.get_open_mut(tun_id) else {
                        return Ok(None);
                    };
                    Arc::clone(&tunnel_ent.tunnel)
                }
            }
        };

        // If we get here, then we have a long-lived tunnel for which we need to check `disused_since`
        let last_known_in_use_at = tunnel.last_known_to_be_used_at().await;

        // Now we tell the TunnelList what we learned.
        {
            let mut list: sync::MutexGuard<'_, TunnelList<B, R>> =
                self.tunnels.lock().expect("poisoned lock");
            list.update_long_lived_tunnel_last_used(
                tun_id,
                now,
                &expiration_params,
                &last_known_in_use_at,
            )
        }
    }

    /// Return the number of open tunnels held by this tunnel manager.
    pub(crate) fn n_tunnels(&self) -> usize {
        let list = self.tunnels.lock().expect("poisoned lock");
        list.open_tunnels.len()
    }

    /// Return the number of pending tunnels tracked by this tunnel manager.
    #[cfg(test)]
    pub(crate) fn n_pending_tunnels(&self) -> usize {
        let list = self.tunnels.lock().expect("poisoned lock");
        list.pending_tunnels.len()
    }

    /// Get a reference to this manager's runtime.
    pub(crate) fn peek_runtime(&self) -> &R {
        &self.runtime
    }

    /// Get a reference to this manager's builder.
    pub(crate) fn peek_builder(&self) -> &B {
        &self.builder
    }

    /// Pick a duration by when a new tunnel should expire from now
    /// if it has not yet been used
    fn pick_use_duration(&self) -> Duration {
        let timings = self
            .unused_timing
            .lock()
            .expect("Poisoned lock for unused_timing");

        if self.builder.learning_timeouts() {
            timings.learning
        } else {
            // TODO: In Tor, this calculation also depends on
            // stuff related to predicted ports and channel
            // padding.
            use tor_basic_utils::RngExt as _;
            let mut rng = rand::rng();
            rng.gen_range_checked(timings.not_learning..=timings.not_learning * 2)
                .expect("T .. 2x T turned out to be an empty duration range?!")
        }
    }
}

/// Spawn an expiration task that expires a tunnel at given instant.
///
/// When the timeout occurs, if the tunnel manager is still present,
/// the task will ask the manager to expire the tunnel, if the tunnel
/// is ready to expire.
//
// TODO: It would be good to do away with this function entirely, and have a smarter expiration
// function.  This one only exists because there is not an "expire some circuits" background task.
fn spawn_expiration_task<B, R>(
    runtime: &R,
    circmgr: Weak<AbstractTunnelMgr<B, R>>,
    circ_id: <<B as AbstractTunnelBuilder<R>>::Tunnel as AbstractTunnel>::Id,
    exp_inst: Instant,
) where
    R: Runtime,
    B: 'static + AbstractTunnelBuilder<R>,
{
    let now = runtime.now();
    let rt_copy = runtime.clone();
    let mut duration = exp_inst.saturating_duration_since(now);

    // NOTE: Once there was an optimization here that ran the expiration immediately if
    // `duration` was zero.
    // I discarded that optimization when I made `consider_expiring_tunnel` async,
    // since we really want this function _not_ to be async,
    // because we run it in contexts where we hold a Mutex on the tunnel list.

    // Spawn a timer expiration task with given expiration instant.
    if let Err(e) = runtime.spawn(async move {
        loop {
            rt_copy.sleep(duration).await;
            let cm = if let Some(cm) = Weak::upgrade(&circmgr) {
                cm
            } else {
                return;
            };
            match cm.consider_expiring_tunnel(&circ_id, exp_inst).await {
                Ok(None) => return,
                Ok(Some(when)) => {
                    duration = when.saturating_duration_since(rt_copy.now());
                }
                Err(e) => {
                    warn_report!(
                        e,
                        "Error while considering expiration for tunnel {:?}",
                        circ_id
                    );
                    return;
                }
            }
        }
    }) {
        warn_report!(e, "Unable to launch expiration task");
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::isolation::test::{IsolationTokenEq, assert_isoleq};
    use crate::mocks::{FakeBuilder, FakeCirc, FakeId, FakeOp};
    use crate::usage::{ExitPolicy, SupportedTunnelUsage};
    use crate::{
        Error, IsolationToken, StreamIsolation, TargetPort, TargetPorts, TargetTunnelUsage,
    };
    use std::sync::LazyLock;
    use tor_dircommon::fallback::FallbackList;
    use tor_guardmgr::TestConfig;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_netdir::testnet;
    use tor_persist::TestingStateMgr;
    use tor_rtcompat::SleepProvider;
    use tor_rtmock::MockRuntime;

    #[allow(deprecated)] // TODO #1885
    use tor_rtmock::MockSleepRuntime;

    static FALLBACKS_EMPTY: LazyLock<FallbackList> = LazyLock::new(|| [].into());

    fn di() -> DirInfo<'static> {
        (&*FALLBACKS_EMPTY).into()
    }

    fn target_to_spec(target: &TargetTunnelUsage) -> SupportedTunnelUsage {
        match target {
            TargetTunnelUsage::Exit {
                ports,
                isolation,
                country_code,
                require_stability,
            } => SupportedTunnelUsage::Exit {
                policy: ExitPolicy::from_target_ports(&TargetPorts::from(&ports[..])),
                isolation: Some(isolation.clone()),
                country_code: country_code.clone(),
                all_relays_stable: *require_stability,
            },
            _ => unimplemented!(),
        }
    }

    impl<U: PartialEq> IsolationTokenEq for OpenEntry<U> {
        fn isol_eq(&self, other: &Self) -> bool {
            self.spec.isol_eq(&other.spec)
                && self.tunnel == other.tunnel
                && self.expiration == other.expiration
        }
    }

    impl<U: PartialEq> IsolationTokenEq for &mut OpenEntry<U> {
        fn isol_eq(&self, other: &Self) -> bool {
            self.spec.isol_eq(&other.spec)
                && self.tunnel == other.tunnel
                && self.expiration == other.expiration
        }
    }

    fn make_builder<R: Runtime>(runtime: &R) -> FakeBuilder<R> {
        let state_mgr = TestingStateMgr::new();
        let guard_config = TestConfig::default();
        FakeBuilder::new(runtime, state_mgr, &guard_config)
    }

    #[test]
    fn basic_tests() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);

            let builder = make_builder(&rt);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            let webports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // Check initialization.
            assert_eq!(mgr.n_tunnels(), 0);
            assert!(mgr.peek_builder().script.lock().unwrap().is_empty());

            // Launch a tunnel ; make sure we get it.
            let c1 = rt.wait_for(mgr.get_or_launch(&webports, di())).await;
            let c1 = c1.unwrap().0;
            assert_eq!(mgr.n_tunnels(), 1);

            // Make sure we get the one we already made if we ask for it.
            let port80 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
            let c2 = mgr.get_or_launch(&port80, di()).await;

            let c2 = c2.unwrap().0;
            assert!(FakeCirc::eq(&c1, &c2));
            assert_eq!(mgr.n_tunnels(), 1);

            // Now try launching two tunnels "at once" to make sure that our
            // pending-tunnel code works.

            let dnsport = TargetTunnelUsage::new_from_ipv4_ports(&[53]);
            let dnsport_restrict = TargetTunnelUsage::Exit {
                ports: vec![TargetPort::ipv4(53)],
                isolation: StreamIsolation::builder().build().unwrap(),
                country_code: None,
                require_stability: false,
            };

            let (c3, c4) = rt
                .wait_for(futures::future::join(
                    mgr.get_or_launch(&dnsport, di()),
                    mgr.get_or_launch(&dnsport_restrict, di()),
                ))
                .await;

            let c3 = c3.unwrap().0;
            let c4 = c4.unwrap().0;
            assert!(!FakeCirc::eq(&c1, &c3));
            assert!(FakeCirc::eq(&c3, &c4));
            assert_eq!(c3.id(), c4.id());
            assert_eq!(mgr.n_tunnels(), 2);

            // Now we're going to remove c3 from consideration.  It's the
            // same as c4, so removing c4 will give us None.
            let c3_taken = mgr.take_tunnel(&c3.id()).unwrap();
            let now_its_gone = mgr.take_tunnel(&c4.id());
            assert!(FakeCirc::eq(&c3_taken, &c3));
            assert!(now_its_gone.is_none());
            assert_eq!(mgr.n_tunnels(), 1);

            // Having removed them, let's launch another dnsport and make
            // sure we get a different tunnel.
            let c5 = rt.wait_for(mgr.get_or_launch(&dnsport, di())).await;
            let c5 = c5.unwrap().0;
            assert!(!FakeCirc::eq(&c3, &c5));
            assert!(!FakeCirc::eq(&c4, &c5));
            assert_eq!(mgr.n_tunnels(), 2);

            // Now try launch_by_usage.
            let prev = mgr.n_pending_tunnels();
            assert!(mgr.launch_by_usage(&dnsport, di()).is_ok());
            assert_eq!(mgr.n_pending_tunnels(), prev + 1);
            // TODO: Actually make sure that launch_by_usage launched
            // the right thing.
        });
    }

    #[test]
    fn request_timeout() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);

            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // This will fail once, and then completely time out.  The
            // result will be a failure.
            let builder = make_builder(&rt);
            builder.set(&ports, vec![FakeOp::Fail, FakeOp::Timeout]);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            let c1 = mgr
                .peek_runtime()
                .wait_for(mgr.get_or_launch(&ports, di()))
                .await;

            assert!(matches!(c1, Err(Error::RequestFailed(_))));
        });
    }

    #[test]
    fn request_timeout2() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);

            // Now try a more complicated case: we'll try to get things so
            // that we wait for a little over our predicted time because
            // of our wait-for-next-action logic.
            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);
            let builder = make_builder(&rt);
            builder.set(
                &ports,
                vec![
                    FakeOp::Delay(Duration::from_millis(60_000 - 25)),
                    FakeOp::NoPlan,
                ],
            );

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            let c1 = mgr
                .peek_runtime()
                .wait_for(mgr.get_or_launch(&ports, di()))
                .await;

            assert!(matches!(c1, Err(Error::RequestFailed(_))));
        });
    }

    #[test]
    fn request_unplannable() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);

            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // This will fail a the planning stages, a lot.
            let builder = make_builder(&rt);
            builder.set(&ports, vec![FakeOp::NoPlan; 2000]);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

            assert!(matches!(c1, Err(Error::RequestFailed(_))));
        });
    }

    #[test]
    fn request_fails_too_much() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // This will fail 1000 times, which is above the retry limit.
            let builder = make_builder(&rt);
            builder.set(&ports, vec![FakeOp::Fail; 1000]);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

            assert!(matches!(c1, Err(Error::RequestFailed(_))));
        });
    }

    #[test]
    fn request_wrong_spec() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // The first time this is called, it will build a tunnel
            // with the wrong spec.  (A tunnel builder should never
            // actually _do_ that, but it's something we code for.)
            let builder = make_builder(&rt);
            builder.set(
                &ports,
                vec![FakeOp::WrongSpec(target_to_spec(
                    &TargetTunnelUsage::new_from_ipv4_ports(&[22]),
                ))],
            );

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

            assert!(c1.is_ok());
        });
    }

    #[test]
    fn request_retried() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            // This will fail twice, and then succeed. The result will be
            // a success.
            let builder = make_builder(&rt);
            builder.set(&ports, vec![FakeOp::Fail, FakeOp::Fail]);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            // This test doesn't exercise any timeout behaviour.
            rt.block_advance("test doesn't require advancing");

            let (c1, c2) = rt
                .wait_for(futures::future::join(
                    mgr.get_or_launch(&ports, di()),
                    mgr.get_or_launch(&ports, di()),
                ))
                .await;

            let c1 = c1.unwrap().0;
            let c2 = c2.unwrap().0;

            assert!(FakeCirc::eq(&c1, &c2));
        });
    }

    #[test]
    fn isolated() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let builder = make_builder(&rt);
            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            // Set our isolation so that iso1 and iso2 can't share a tunnel,
            // but no_iso can share a tunnel with either.
            let iso1 = TargetTunnelUsage::Exit {
                ports: vec![TargetPort::ipv4(443)],
                isolation: StreamIsolation::builder()
                    .owner_token(IsolationToken::new())
                    .build()
                    .unwrap(),
                country_code: None,
                require_stability: false,
            };
            let iso2 = TargetTunnelUsage::Exit {
                ports: vec![TargetPort::ipv4(443)],
                isolation: StreamIsolation::builder()
                    .owner_token(IsolationToken::new())
                    .build()
                    .unwrap(),
                country_code: None,
                require_stability: false,
            };
            let no_iso1 = TargetTunnelUsage::new_from_ipv4_ports(&[443]);
            let no_iso2 = no_iso1.clone();

            // We're going to try launching these tunnels in 24 different
            // orders, to make sure that the outcome is correct each time.
            use itertools::Itertools;
            let timeouts: Vec<_> = [0_u64, 2, 4, 6]
                .iter()
                .map(|d| Duration::from_millis(*d))
                .collect();

            for delays in timeouts.iter().permutations(4) {
                let d1 = delays[0];
                let d2 = delays[1];
                let d3 = delays[2];
                let d4 = delays[2];
                let (c_iso1, c_iso2, c_no_iso1, c_no_iso2) = rt
                    .wait_for(futures::future::join4(
                        async {
                            rt.sleep(*d1).await;
                            mgr.get_or_launch(&iso1, di()).await
                        },
                        async {
                            rt.sleep(*d2).await;
                            mgr.get_or_launch(&iso2, di()).await
                        },
                        async {
                            rt.sleep(*d3).await;
                            mgr.get_or_launch(&no_iso1, di()).await
                        },
                        async {
                            rt.sleep(*d4).await;
                            mgr.get_or_launch(&no_iso2, di()).await
                        },
                    ))
                    .await;

                let c_iso1 = c_iso1.unwrap().0;
                let c_iso2 = c_iso2.unwrap().0;
                let c_no_iso1 = c_no_iso1.unwrap().0;
                let c_no_iso2 = c_no_iso2.unwrap().0;

                assert!(!FakeCirc::eq(&c_iso1, &c_iso2));
                assert!(!FakeCirc::eq(&c_iso1, &c_no_iso1));
                assert!(!FakeCirc::eq(&c_iso1, &c_no_iso2));
                assert!(!FakeCirc::eq(&c_iso2, &c_no_iso1));
                assert!(!FakeCirc::eq(&c_iso2, &c_no_iso2));
                assert!(FakeCirc::eq(&c_no_iso1, &c_no_iso2));
            }
        });
    }

    #[test]
    fn opportunistic() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);

            // The first request will time out completely, but we're
            // making a second request after we launch it.  That
            // request should succeed, and notify the first request.

            let ports1 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
            let ports2 = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

            let builder = make_builder(&rt);
            builder.set(&ports1, vec![FakeOp::Timeout]);

            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            // Note that ports2 will be wider than ports1, so the second
            // request will have to launch a new tunnel.

            let (c1, c2) = rt
                .wait_for(futures::future::join(
                    mgr.get_or_launch(&ports1, di()),
                    async {
                        rt.sleep(Duration::from_millis(100)).await;
                        mgr.get_or_launch(&ports2, di()).await
                    },
                ))
                .await;

            if let (Ok((c1, _)), Ok((c2, _))) = (c1, c2) {
                assert!(FakeCirc::eq(&c1, &c2));
            } else {
                panic!();
            };
        });
    }

    #[test]
    fn prebuild() {
        MockRuntime::test_with_various(|rt| async move {
            // This time we're going to use ensure_tunnel() to make
            // sure that a tunnel gets built, and then launch two
            // other tunnels that will use it.
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let builder = make_builder(&rt);
            let mgr = Arc::new(AbstractTunnelMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            let ports1 = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);
            let ports2 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
            let ports3 = TargetTunnelUsage::new_from_ipv4_ports(&[443]);

            let (ok, c1, c2) = rt
                .wait_for(futures::future::join3(
                    mgr.ensure_tunnel(&ports1, di()),
                    async {
                        rt.sleep(Duration::from_millis(10)).await;
                        mgr.get_or_launch(&ports2, di()).await
                    },
                    async {
                        rt.sleep(Duration::from_millis(50)).await;
                        mgr.get_or_launch(&ports3, di()).await
                    },
                ))
                .await;

            assert!(ok.is_ok());

            let c1 = c1.unwrap().0;
            let c2 = c2.unwrap().0;

            // If we had launched these separately, they wouldn't share
            // a tunnel.
            assert!(FakeCirc::eq(&c1, &c2));
        });
    }

    #[test]
    fn expiration() {
        MockRuntime::test_with_various(|rt| async move {
            use crate::config::CircuitTimingBuilder;
            // Now let's make some tunnels -- one dirty, one clean, and
            // make sure that one expires and one doesn't.
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let builder = make_builder(&rt);

            let circuit_timing = CircuitTimingBuilder::default()
                .max_dirtiness(Duration::from_secs(15))
                .build()
                .unwrap();

            let mgr = Arc::new(AbstractTunnelMgr::new(builder, rt.clone(), circuit_timing));

            let imap = TargetTunnelUsage::new_from_ipv4_ports(&[993]);
            let pop = TargetTunnelUsage::new_from_ipv4_ports(&[995]);

            let (ok, pop1) = rt
                .wait_for(futures::future::join(
                    mgr.ensure_tunnel(&imap, di()),
                    mgr.get_or_launch(&pop, di()),
                ))
                .await;

            assert!(ok.is_ok());
            let pop1 = pop1.unwrap().0;

            rt.advance(Duration::from_secs(30)).await;
            rt.advance(Duration::from_secs(15)).await;
            let imap1 = rt.wait_for(mgr.get_or_launch(&imap, di())).await.unwrap().0;

            // This should expire the pop tunnel, since it came from
            // get_or_launch() [which marks the tunnel as being
            // used].  It should not expire the imap tunnel, since
            // it was not dirty until 15 seconds after the cutoff.
            let now = rt.now();

            mgr.expire_tunnels(now).await;

            let (pop2, imap2) = rt
                .wait_for(futures::future::join(
                    mgr.get_or_launch(&pop, di()),
                    mgr.get_or_launch(&imap, di()),
                ))
                .await;

            let pop2 = pop2.unwrap().0;
            let imap2 = imap2.unwrap().0;

            assert!(!FakeCirc::eq(&pop2, &pop1));
            assert!(FakeCirc::eq(&imap2, &imap1));
        });
    }

    /// Returns three exit policies; one that permits nothing, one that permits ports 80
    /// and 443 only, and one that permits all ports.
    fn get_exit_policies() -> (ExitPolicy, ExitPolicy, ExitPolicy) {
        // FIXME(eta): the below is copypasta; would be nice to have a better way of
        //             constructing ExitPolicy objects for testing maybe
        let network = testnet::construct_netdir().unwrap_if_sufficient().unwrap();

        // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
        // exits.  Odd-numbered ones allow only ports 80 and 443;
        // even-numbered ones allow all ports.
        let id_noexit: Ed25519Identity = [0x05; 32].into();
        let id_webexit: Ed25519Identity = [0x11; 32].into();
        let id_fullexit: Ed25519Identity = [0x20; 32].into();

        let not_exit = network.by_id(&id_noexit).unwrap();
        let web_exit = network.by_id(&id_webexit).unwrap();
        let full_exit = network.by_id(&id_fullexit).unwrap();

        let ep_none = ExitPolicy::from_relay(&not_exit);
        let ep_web = ExitPolicy::from_relay(&web_exit);
        let ep_full = ExitPolicy::from_relay(&full_exit);
        (ep_none, ep_web, ep_full)
    }

    #[test]
    fn test_find_supported() {
        let (ep_none, ep_web, ep_full) = get_exit_policies();
        let fake_circ = FakeCirc { id: FakeId::next() };
        let expiration = ExpirationInfo::Unused {
            created: Instant::now(),
        };

        let mut entry_none = OpenEntry::new(
            SupportedTunnelUsage::Exit {
                policy: ep_none,
                isolation: None,
                country_code: None,
                all_relays_stable: true,
            },
            fake_circ.clone(),
            expiration.clone(),
        );
        let mut entry_none_c = entry_none.clone();
        let mut entry_web = OpenEntry::new(
            SupportedTunnelUsage::Exit {
                policy: ep_web,
                isolation: None,
                country_code: None,
                all_relays_stable: true,
            },
            fake_circ.clone(),
            expiration.clone(),
        );
        let mut entry_web_c = entry_web.clone();
        let mut entry_full = OpenEntry::new(
            SupportedTunnelUsage::Exit {
                policy: ep_full,
                isolation: None,
                country_code: None,
                all_relays_stable: true,
            },
            fake_circ,
            expiration,
        );
        let mut entry_full_c = entry_full.clone();

        let usage_web = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
        let empty: Vec<&mut OpenEntry<FakeCirc>> = vec![];

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(vec![&mut entry_none].into_iter(), &usage_web),
            empty
        );

        // HACK(eta): We have to faff around with clones and such because
        //            `abstract_spec_find_supported` has a silly signature that involves `&mut`
        //            refs, which we can't have more than one of.

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_web,
            ),
            vec![&mut entry_web_c]
        );

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
                &usage_web,
            ),
            vec![&mut entry_web_c, &mut entry_full_c]
        );

        // Test preemptive tunnel usage:

        let usage_preemptive_web = TargetTunnelUsage::Preemptive {
            port: Some(TargetPort::ipv4(80)),
            circs: 2,
            require_stability: false,
        };
        let usage_preemptive_dns = TargetTunnelUsage::Preemptive {
            port: None,
            circs: 2,
            require_stability: false,
        };

        // shouldn't return anything unless there are >=2 tunnels

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none].into_iter(),
                &usage_preemptive_web
            ),
            empty
        );

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none].into_iter(),
                &usage_preemptive_dns
            ),
            empty
        );

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_preemptive_web
            ),
            empty
        );

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_preemptive_dns
            ),
            vec![&mut entry_none_c, &mut entry_web_c]
        );

        assert_isoleq!(
            SupportedTunnelUsage::find_supported(
                vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
                &usage_preemptive_web
            ),
            vec![&mut entry_web_c, &mut entry_full_c]
        );
    }

    #[test]
    fn test_circlist_preemptive_target_circs() {
        MockRuntime::test_with_various(|rt| async move {
            #[allow(deprecated)] // TODO #1885
            let rt = MockSleepRuntime::new(rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let dirinfo = DirInfo::Directory(&netdir);

            let builder = make_builder(&rt);

            for circs in [2, 8].iter() {
                let mut circlist = TunnelList::<FakeBuilder<MockRuntime>, MockRuntime>::new();

                let preemptive_target = TargetTunnelUsage::Preemptive {
                    port: Some(TargetPort::ipv4(80)),
                    circs: *circs,
                    require_stability: false,
                };

                for _ in 0..*circs {
                    assert!(circlist.find_open(&preemptive_target).is_none());

                    let usage = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
                    let (plan, _) = builder.plan_tunnel(&usage, dirinfo).unwrap();
                    let (spec, circ) = rt.wait_for(builder.build_tunnel(plan)).await.unwrap();
                    let entry = OpenEntry::new(
                        spec,
                        circ,
                        ExpirationInfo::new(rt.now() + Duration::from_secs(60)),
                    );
                    circlist.add_open(entry);
                }

                assert!(circlist.find_open(&preemptive_target).is_some());
            }
        });
    }
}
