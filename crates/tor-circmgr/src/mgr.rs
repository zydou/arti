//! Abstract code to manage a set of circuits.
//!
//! This module implements the real logic for deciding when and how to
//! launch circuits, and for which circuits to hand out in response to
//! which requests.
//!
//! For testing and abstraction purposes, this module _does not_
//! actually know anything about circuits _per se_.  Instead,
//! everything is handled using a set of traits that are internal to this
//! crate:
//!
//!  * [`AbstractCirc`] is a view of a circuit.
//!  * [`AbstractSpec`] represents a circuit's possible usages.
//!  * [`AbstractCircBuilder`] knows how to build an `AbstractCirc`.
//!
//! Using these traits, the [`AbstractCircMgr`] object manages a set of
//! circuits, launching them as necessary, and keeping track of the
//! restrictions on their use.

// TODO:
// - Testing
//    - Error from prepare_action()
//    - Error reported by restrict_mut?

use crate::config::CircuitTiming;
use crate::{DirInfo, Error, Result};

use retry_error::RetryError;
use tor_basic_utils::retry::RetryDelay;
use tor_chanmgr::ChannelUsage;
use tor_config::MutCfg;
use tor_error::{debug_report, info_report, internal, warn_report, AbsRetryTime, HasRetryTime};
use tor_rtcompat::{Runtime, SleepProviderExt};

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::{FutureExt, Shared};
use futures::stream::{FuturesUnordered, StreamExt};
use futures::task::SpawnExt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::sync::{self, Arc, Weak};
use std::time::{Duration, Instant};
use tor_async_utils::oneshot;
use tracing::{debug, warn};
use weak_table::PtrWeakHashSet;

mod streams;

/// Description of how we got a circuit.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum CircProvenance {
    /// This channel was newly launched, or was in progress and finished while
    /// we were waiting.
    NewlyCreated,
    /// This channel already existed when we asked for it.
    Preexisting,
}

/// Represents restrictions on circuit usage.
///
/// An `AbstractSpec` describes what a circuit can be used for.  Each
/// `AbstractSpec` type has an associated `Usage` type that
/// describes a _single_ operation that the circuit might support or
/// not.
///
/// (For example, an `AbstractSpec` can describe a set of ports
/// supported by the exit relay on a circuit.  In that case, its
/// `Usage` type could be a single port that a client wants to
/// connect to.)
///
/// If an `AbstractSpec` A allows every operation described in a
/// `Usage` B, we say that A "supports" B.
///
/// If one `AbstractSpec` A supports every operation supported by
/// another `AbstractSpec` B, we say that A "contains" B.
///
/// Some circuits can be used for either of two operations, but not both.
/// For example, a circuit that is used as a rendezvous point can't
/// be used as an introduction point.  To represent these transitions,
/// we use a `restrict` operation.  Every time a circuit is used for something
/// new, that new use "restricts" the circuit's spec, and narrows
/// what the circuit can be used for.
pub(crate) trait AbstractSpec: Clone + Debug {
    /// A type to represent the kind of usages that this circuit permits.
    type Usage: Clone + Debug + Send + Sync;

    /// Return true if this spec permits the usage described by `other`.
    ///
    /// If this function returns `true`, then it is okay to use a circuit
    /// with this spec for the target usage described by `other`.
    fn supports(&self, other: &Self::Usage) -> bool;

    /// Change the value of this spec based on the circuit having
    /// been used for `usage`.
    ///
    /// # Requirements
    ///
    /// Must return an error and make no changes to `self` if `usage`
    /// was not supported by this spec.
    ///
    /// If this function returns Ok, the resulting spec must be
    /// contained by the original spec, and must support `usage`.
    fn restrict_mut(&mut self, usage: &Self::Usage) -> std::result::Result<(), RestrictionFailed>;

    /// Find all open circuits in `list` whose specifications permit
    /// `usage`.
    ///
    /// By default, this calls `abstract_spec_find_supported`.
    fn find_supported<'a, 'b, C: AbstractCirc>(
        list: impl Iterator<Item = &'b mut OpenEntry<Self, C>>,
        usage: &Self::Usage,
    ) -> Vec<&'b mut OpenEntry<Self, C>> {
        abstract_spec_find_supported(list, usage)
    }

    /// How the circuit will be used, for use by the channel
    fn channel_usage(&self) -> ChannelUsage;
}

/// An error type returned by [`AbstractSpec::restrict_mut`]
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestrictionFailed {
    /// Tried to restrict a specification, but the circuit didn't support the
    /// requested usage.
    #[error("Specification did not support desired usage")]
    NotSupported,
}

/// Default implementation of `AbstractSpec::find_supported`; provided as a separate function
/// so it can be used in overridden implementations.
///
/// This returns the all circuits in `list` for which `circuit.spec.supports(usage)` returns
/// `true`.
pub(crate) fn abstract_spec_find_supported<'a, 'b, S: AbstractSpec, C: AbstractCirc>(
    list: impl Iterator<Item = &'b mut OpenEntry<S, C>>,
    usage: &S::Usage,
) -> Vec<&'b mut OpenEntry<S, C>> {
    list.filter(|circ| circ.supports(usage)).collect()
}

/// Minimal abstract view of a circuit.
///
/// From this module's point of view, circuits are simply objects
/// with unique identities, and a possible closed-state.
pub(crate) trait AbstractCirc: Debug {
    /// Type for a unique identifier for circuits.
    type Id: Clone + Debug + Hash + Eq + Send + Sync;
    /// Return the unique identifier for this circuit.
    ///
    /// # Requirements
    ///
    /// The values returned by this function are unique for distinct
    /// circuits.
    fn id(&self) -> Self::Id;

    /// Return true if this circuit is usable for some purpose.
    ///
    /// Reasons a circuit might be unusable include being closed.
    fn usable(&self) -> bool;
}

/// A plan for an `AbstractCircBuilder` that can maybe be mutated by tests.
///
/// You should implement this trait using all default methods for all code that isn't test code.
pub(crate) trait MockablePlan {
    /// Add a reason string that was passed to `SleepProvider::block_advance()` to this object
    /// so that it knows what to pass to `::release_advance()`.
    fn add_blocked_advance_reason(&mut self, _reason: String) {}
}

/// An object that knows how to build circuits.
///
/// AbstractCircBuilder creates circuits in two phases.  First, a plan is
/// made for how to build the circuit.  This planning phase should be
/// relatively fast, and must not suspend or block.  Its purpose is to
/// get an early estimate of which operations the circuit will be able
/// to support when it's done.
///
/// Second, the circuit is actually built, using the plan as input.
#[async_trait]
pub(crate) trait AbstractCircBuilder: Send + Sync {
    /// The specification type describing what operations circuits can
    /// be used for.
    type Spec: AbstractSpec + Debug + Send + Sync;
    /// The circuit type that this builder knows how to build.
    type Circ: AbstractCirc + Send + Sync;
    /// An opaque type describing how a given circuit will be built.
    /// It may represent some or all of a path-or it may not.
    // TODO: It would be nice to have this parameterized on a lifetime,
    // and have that lifetime depend on the lifetime of the directory.
    // But I don't think that rust can do that.

    // HACK(eta): I don't like the fact that `MockablePlan` is necessary here.
    type Plan: Send + Debug + MockablePlan;

    // TODO: I'd like to have a Dir type here to represent
    // create::DirInfo, but that would need to be parameterized too,
    // and would make everything complicated.

    /// Form a plan for how to build a new circuit that supports `usage`.
    ///
    /// Return an opaque Plan object, and a new spec describing what
    /// the circuit will actually support when it's built.  (For
    /// example, if the input spec requests a circuit that connect to
    /// port 80, then "planning" the circuit might involve picking an
    /// exit that supports port 80, and the resulting spec might be
    /// the exit's complete list of supported ports.)
    ///
    /// # Requirements
    ///
    /// The resulting Spec must support `usage`.
    fn plan_circuit(
        &self,
        usage: &<Self::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<(Self::Plan, Self::Spec)>;

    /// Construct a circuit according to a given plan.
    ///
    /// On success, return a spec describing what the circuit can be used for,
    /// and the circuit that was just constructed.
    ///
    /// This function should implement some kind of a timeout for
    /// circuits that are taking too long.
    ///
    /// # Requirements
    ///
    /// The spec that this function returns _must_ support the usage
    /// that was originally passed to `plan_circuit`.  It _must_ also
    /// contain the spec that was originally returned by
    /// `plan_circuit`.
    async fn build_circuit(&self, plan: Self::Plan) -> Result<(Self::Spec, Arc<Self::Circ>)>;

    /// Return a "parallelism factor" with which circuits should be
    /// constructed for a given purpose.
    ///
    /// If this function returns N, then whenever we launch circuits
    /// for this purpose, then we launch N in parallel.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    fn launch_parallelism(&self, usage: &<Self::Spec as AbstractSpec>::Usage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return a "parallelism factor" for which circuits should be
    /// used for a given purpose.
    ///
    /// If this function returns N, then whenever we select among
    /// open circuits for this purpose, we choose at random from the
    /// best N.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    // TODO: Possibly this doesn't belong in this trait.
    fn select_parallelism(&self, usage: &<Self::Spec as AbstractSpec>::Usage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return true if we are currently attempting to learn circuit
    /// timeouts by building testing circuits.
    fn learning_timeouts(&self) -> bool;
}

/// Enumeration to track the expiration state of a circuit.
///
/// A circuit an either be unused (at which point it should expire if it is
/// _still unused_ by a certain time, or dirty (at which point it should
/// expire after a certain duration).
///
/// All circuits start out "unused" and become "dirty" when their spec
/// is first restricted -- that is, when they are first handed out to be
/// used for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpirationInfo {
    /// The circuit has never been used.
    Unused {
        /// A time when the circuit should expire.
        use_before: Instant,
    },
    /// The circuit has been used (or at least, restricted for use with a
    /// request) at least once.
    Dirty {
        /// The time at which this circuit's spec was first restricted.
        dirty_since: Instant,
    },
}

impl ExpirationInfo {
    /// Return an ExpirationInfo for a newly created circuit.
    fn new(use_before: Instant) -> Self {
        ExpirationInfo::Unused { use_before }
    }

    /// Mark this ExpirationInfo as dirty, if it is not already dirty.
    fn mark_dirty(&mut self, now: Instant) {
        if matches!(self, ExpirationInfo::Unused { .. }) {
            *self = ExpirationInfo::Dirty { dirty_since: now };
        }
    }
}

/// An entry for an open circuit held by an `AbstractCircMgr`.
#[derive(PartialEq, Debug, Clone, Eq)]
pub(crate) struct OpenEntry<S, C> {
    /// Current AbstractCircSpec for this circuit's permitted usages.
    spec: S,
    /// The circuit under management.
    circ: Arc<C>,
    /// When does this circuit expire?
    ///
    /// (Note that expired circuits are removed from the manager,
    /// which does not actually close them until there are no more
    /// references to them.)
    expiration: ExpirationInfo,
}

impl<S: AbstractSpec, C: AbstractCirc> OpenEntry<S, C> {
    /// Make a new OpenEntry for a given circuit and spec.
    fn new(spec: S, circ: Arc<C>, expiration: ExpirationInfo) -> Self {
        OpenEntry {
            spec,
            circ,
            expiration,
        }
    }

    /// Return true if this circuit can be used for `usage`.
    fn supports(&self, usage: &<S as AbstractSpec>::Usage) -> bool {
        self.circ.usable() && self.spec.supports(usage)
    }

    /// Change this circuit's permissible usage, based on its having
    /// been used for `usage` at time `now`.
    ///
    /// Return an error if this circuit may not be used for `usage`.
    fn restrict_mut(&mut self, usage: &<S as AbstractSpec>::Usage, now: Instant) -> Result<()> {
        self.spec.restrict_mut(usage)?;
        self.expiration.mark_dirty(now);
        Ok(())
    }

    /// Find the "best" entry from a slice of OpenEntry for supporting
    /// a given `usage`.
    ///
    /// If `parallelism` is some N greater than 1, we pick randomly
    /// from the best `N` circuits.
    ///
    /// # Requirements
    ///
    /// Requires that `ents` is nonempty, and that every element of `ents`
    /// supports `spec`.
    fn find_best<'a>(
        // we do not mutate `ents`, but to return `&mut Self` we must have a mutable borrow
        ents: &'a mut [&'a mut Self],
        usage: &<S as AbstractSpec>::Usage,
        parallelism: usize,
    ) -> &'a mut Self {
        let _ = usage; // not yet used.
        use rand::seq::SliceRandom;
        let parallelism = parallelism.clamp(1, ents.len());
        // TODO: Actually look over the whole list to see which is better.
        let slice = &mut ents[0..parallelism];
        let mut rng = rand::thread_rng();
        slice.choose_mut(&mut rng).expect("Input list was empty")
    }

    /// Return true if this circuit has been marked as dirty before
    /// `dirty_cutoff`, or if it is an unused circuit set to expire before
    /// `unused_cutoff`.
    fn should_expire(&self, unused_cutoff: Instant, dirty_cutoff: Instant) -> bool {
        match self.expiration {
            ExpirationInfo::Unused { use_before } => use_before <= unused_cutoff,
            ExpirationInfo::Dirty { dirty_since } => dirty_since <= dirty_cutoff,
        }
    }
}

/// A result type whose "Ok" value is the Id for a circuit from B.
type PendResult<B> = Result<<<B as AbstractCircBuilder>::Circ as AbstractCirc>::Id>;

/// An in-progress circuit request tracked by an `AbstractCircMgr`.
///
/// (In addition to tracking circuits, `AbstractCircMgr` tracks
/// _requests_ for circuits.  The manager uses these entries if it
/// finds that some circuit created _after_ a request first launched
/// might meet the request's requirements.)
struct PendingRequest<B: AbstractCircBuilder> {
    /// Usage for the operation requested by this request
    usage: <B::Spec as AbstractSpec>::Usage,
    /// A channel to use for telling this request about circuits that it
    /// might like.
    notify: mpsc::Sender<PendResult<B>>,
}

impl<B: AbstractCircBuilder> PendingRequest<B> {
    /// Return true if this request would be supported by `spec`.
    fn supported_by(&self, spec: &B::Spec) -> bool {
        spec.supports(&self.usage)
    }
}

/// An entry for an under-construction in-progress circuit tracked by
/// an `AbstractCircMgr`.
#[derive(Debug)]
struct PendingEntry<B: AbstractCircBuilder> {
    /// Specification that this circuit will support, if every pending
    /// request that is waiting for it is attached to it.
    ///
    /// This spec becomes more and more restricted as more pending
    /// requests are waiting for this circuit.
    ///
    /// This spec is contained by circ_spec, and must support the usage
    /// of every pending request that's waiting for this circuit.
    tentative_assignment: sync::Mutex<B::Spec>,
    /// A shared future for requests to use when waiting for
    /// notification of this circuit's success.
    receiver: Shared<oneshot::Receiver<PendResult<B>>>,
}

impl<B: AbstractCircBuilder> PendingEntry<B> {
    /// Make a new PendingEntry that starts out supporting a given
    /// spec.  Return that PendingEntry, along with a Sender to use to
    /// report the result of building this circuit.
    fn new(circ_spec: &B::Spec) -> (Self, oneshot::Sender<PendResult<B>>) {
        let tentative_assignment = sync::Mutex::new(circ_spec.clone());
        let (sender, receiver) = oneshot::channel();
        let receiver = receiver.shared();
        let entry = PendingEntry {
            tentative_assignment,
            receiver,
        };
        (entry, sender)
    }

    /// Return true if this circuit's current tentative assignment
    /// supports `usage`.
    fn supports(&self, usage: &<B::Spec as AbstractSpec>::Usage) -> bool {
        let assignment = self.tentative_assignment.lock().expect("poisoned lock");
        assignment.supports(usage)
    }

    /// Try to change the tentative assignment of this circuit by
    /// restricting it for use with `usage`.
    ///
    /// Return an error if the current tentative assignment didn't
    /// support `usage` in the first place.
    fn tentative_restrict_mut(&self, usage: &<B::Spec as AbstractSpec>::Usage) -> Result<()> {
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
    fn find_best(ents: &[Arc<Self>], usage: &<B::Spec as AbstractSpec>::Usage) -> Vec<Arc<Self>> {
        // TODO: Actually look over the whole list to see which is better.
        let _ = usage; // currently unused
        vec![Arc::clone(&ents[0])]
    }
}

/// Wrapper type to represent the state between planning to build a
/// circuit and constructing it.
#[derive(Debug)]
struct CircBuildPlan<B: AbstractCircBuilder> {
    /// The Plan object returned by [`AbstractCircBuilder::plan_circuit`].
    plan: B::Plan,
    /// A sender to notify any pending requests when this circuit is done.
    sender: oneshot::Sender<PendResult<B>>,
    /// A strong entry to the PendingEntry for this circuit build attempt.
    pending: Arc<PendingEntry<B>>,
}

/// The inner state of an [`AbstractCircMgr`].
struct CircList<B: AbstractCircBuilder> {
    /// A map from circuit ID to [`OpenEntry`] values for all managed
    /// open circuits.
    ///
    /// A circuit is added here from [`AbstractCircMgr::do_launch`] when we find
    /// that it completes successfully, and has not been cancelled.
    /// When we decide that such a circuit should no longer be handed out for
    /// any new requests, we "retire" the circuit by removing it from this map.
    #[allow(clippy::type_complexity)]
    open_circs: HashMap<<B::Circ as AbstractCirc>::Id, OpenEntry<B::Spec, B::Circ>>,
    /// Weak-set of PendingEntry for circuits that are being built.
    ///
    /// Because this set only holds weak references, and the only strong
    /// reference to the PendingEntry is held by the task building the circuit,
    /// this set's members are lazily removed after the circuit is either built
    /// or fails to build.
    ///
    /// This set is used for two purposes:
    ///
    /// 1. When a circuit request finds that there is no open circuit for its
    ///    purposes, it checks here to see if there is a pending circuit that it
    ///    could wait for.
    /// 2. When a pending circuit finishes building, it checks here to make sure
    ///    that it has not been cancelled. (Removing an entry from this set marks
    ///    it as cancelled.)
    ///
    /// An entry is added here in [`AbstractCircMgr::prepare_action`] when we
    /// decide that a circuit needs to be launched.
    ///
    /// Later, in [`AbstractCircMgr::do_launch`], once the circuit has finished
    /// (or failed), we remove the entry (by pointer identity).
    /// If we cannot find the entry, we conclude that the request has been
    /// _cancelled_, and so we discard any circuit that was created.
    pending_circs: PtrWeakHashSet<Weak<PendingEntry<B>>>,
    /// Weak-set of PendingRequest for requests that are waiting for a
    /// circuit to be built.
    ///
    /// Because this set only holds weak references, and the only
    /// strong reference to the PendingRequest is held by the task
    /// waiting for the circuit to be built, this set's members are
    /// lazily removed after the request succeeds or fails.
    pending_requests: PtrWeakHashSet<Weak<PendingRequest<B>>>,
}

impl<B: AbstractCircBuilder> CircList<B> {
    /// Make a new empty `CircList`
    fn new() -> Self {
        CircList {
            open_circs: HashMap::new(),
            pending_circs: PtrWeakHashSet::new(),
            pending_requests: PtrWeakHashSet::new(),
        }
    }

    /// Add `e` to the list of open circuits.
    fn add_open(&mut self, e: OpenEntry<B::Spec, B::Circ>) {
        let id = e.circ.id();
        self.open_circs.insert(id, e);
    }

    /// Find all the usable open circuits that support `usage`.
    ///
    /// Return None if there are no such circuits.
    fn find_open(
        &mut self,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Option<Vec<&mut OpenEntry<B::Spec, B::Circ>>> {
        let list = self.open_circs.values_mut();
        let v = <B::Spec as AbstractSpec>::find_supported(list, usage);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    /// Find an open circuit by ID.
    ///
    /// Return None if no such circuit exists in this list.
    fn get_open_mut(
        &mut self,
        id: &<B::Circ as AbstractCirc>::Id,
    ) -> Option<&mut OpenEntry<B::Spec, B::Circ>> {
        self.open_circs.get_mut(id)
    }

    /// Extract an open circuit by ID, removing it from this list.
    ///
    /// Return None if no such circuit exists in this list.
    fn take_open(
        &mut self,
        id: &<B::Circ as AbstractCirc>::Id,
    ) -> Option<OpenEntry<B::Spec, B::Circ>> {
        self.open_circs.remove(id)
    }

    /// Remove circuits based on expiration times.
    ///
    /// We remove every unused circuit that is set to expire by
    /// `unused_cutoff`, and every dirty circuit that has been dirty
    /// since before `dirty_cutoff`.
    fn expire_circs(&mut self, unused_cutoff: Instant, dirty_cutoff: Instant) {
        self.open_circs
            .retain(|_k, v| !v.should_expire(unused_cutoff, dirty_cutoff));
    }

    /// Remove the circuit with given `id`, if it is scheduled to
    /// expire now, according to the provided expiration times.
    fn expire_circ(
        &mut self,
        id: &<B::Circ as AbstractCirc>::Id,
        unused_cutoff: Instant,
        dirty_cutoff: Instant,
    ) {
        let should_expire = self
            .open_circs
            .get(id)
            .map(|v| v.should_expire(unused_cutoff, dirty_cutoff))
            .unwrap_or_else(|| false);
        if should_expire {
            self.open_circs.remove(id);
        }
    }

    /// Add `pending` to the set of in-progress circuits.
    fn add_pending_circ(&mut self, pending: Arc<PendingEntry<B>>) {
        self.pending_circs.insert(pending);
    }

    /// Find all pending circuits that support `usage`.
    ///
    /// If no such circuits are currently being built, return None.
    fn find_pending_circs(
        &self,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Option<Vec<Arc<PendingEntry<B>>>> {
        let result: Vec<_> = self
            .pending_circs
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
    /// A circuit will become non-pending when finishes (successfully or not), or when it's
    /// removed from this list via `clear_all_circuits()`.
    fn circ_is_pending(&self, circ: &Arc<PendingEntry<B>>) -> bool {
        self.pending_circs.contains(circ)
    }

    /// Construct and add a new entry to the set of request waiting
    /// for a circuit.
    ///
    /// Return the request, and a new receiver stream that it should
    /// use for notification of possible circuits to use.
    fn add_pending_request(&mut self, pending: &Arc<PendingRequest<B>>) {
        self.pending_requests.insert(Arc::clone(pending));
    }

    /// Return all pending requests that would be satisfied by a circuit
    /// that supports `circ_spec`.
    fn find_pending_requests(&self, circ_spec: &B::Spec) -> Vec<Arc<PendingRequest<B>>> {
        self.pending_requests
            .iter()
            .filter(|pend| pend.supported_by(circ_spec))
            .collect()
    }

    /// Clear all pending circuits and open circuits.
    ///
    /// Calling `clear_all_circuits` ensures that any request that is answered _after
    /// this method runs_ will receive a circuit that was launched _after this
    /// method runs_.
    fn clear_all_circuits(&mut self) {
        // Note that removing entries from pending_circs will also cause the
        // circuit tasks to realize that they are cancelled when they
        // go to tell anybody about their results.
        self.pending_circs.clear();
        self.open_circs.clear();
    }
}

/// Timing information for circuits that have been built but never used.
///
/// Currently taken from the network parameters.
struct UnusedTimings {
    /// Minimum lifetime of a circuit created while learning
    /// circuit timeouts.
    learning: Duration,
    /// Minimum lifetime of a circuit created while not learning
    /// circuit timeouts.
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

/// Abstract implementation for circuit management.
///
/// The algorithm provided here is fairly simple. In its simplest form:
///
/// When somebody asks for a circuit for a given operation: if we find
/// one open already, we return it.  If we find in-progress circuits
/// that would meet our needs, we wait for one to finish (or for all
/// to fail).  And otherwise, we launch one or more circuits to meet the
/// request's needs.
///
/// If this process fails, then we retry it, up to a timeout or a
/// numerical limit.
///
/// If a circuit not previously considered for a given request
/// finishes before the request is satisfied, and if the circuit would
/// satisfy the request, we try to give that circuit as an answer to
/// that request even if it was not one of the circuits that request
/// was waiting for.
pub(crate) struct AbstractCircMgr<B: AbstractCircBuilder, R: Runtime> {
    /// Builder used to construct circuits.
    builder: B,
    /// An asynchronous runtime to use for launching tasks and
    /// checking timeouts.
    runtime: R,
    /// A CircList to manage our list of circuits, requests, and
    /// pending circuits.
    circs: sync::Mutex<CircList<B>>,

    /// Configured information about when to expire circuits and requests.
    circuit_timing: MutCfg<CircuitTiming>,

    /// Minimum lifetime of an unused circuit.
    ///
    /// Derived from the network parameters.
    unused_timing: sync::Mutex<UnusedTimings>,
}

/// An action to take in order to satisfy a request for a circuit.
enum Action<B: AbstractCircBuilder> {
    /// We found an open circuit: return immediately.
    Open(Arc<B::Circ>),
    /// We found one or more pending circuits: wait until one succeeds,
    /// or all fail.
    Wait(FuturesUnordered<Shared<oneshot::Receiver<PendResult<B>>>>),
    /// We should launch circuits: here are the instructions for how
    /// to do so.
    Build(Vec<CircBuildPlan<B>>),
}

impl<B: AbstractCircBuilder + 'static, R: Runtime> AbstractCircMgr<B, R> {
    /// Construct a new AbstractCircMgr.
    pub(crate) fn new(builder: B, runtime: R, circuit_timing: CircuitTiming) -> Self {
        let circs = sync::Mutex::new(CircList::new());
        let dflt_params = tor_netdir::params::NetParameters::default();
        let unused_timing = (&dflt_params).into();
        AbstractCircMgr {
            builder,
            runtime,
            circs,
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
    /// This is the primary entry point for AbstractCircMgr.
    pub(crate) async fn get_or_launch(
        self: &Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<(Arc<B::Circ>, CircProvenance)> {
        /// Return CEIL(a/b).
        ///
        /// Requires that a+b is less than usize::MAX.
        ///
        /// This can be removed once the MSRV is >= 1.73.0, which is the version
        /// that stabilized `std::usize::div_ceil`.
        ///
        /// # Panics
        ///
        /// Panics if b is 0.
        fn div_ceil(a: usize, b: usize) -> usize {
            (a + b - 1) / b
        }
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
        let max_failures = div_ceil(
            max_tries as usize,
            std::cmp::max(1, self.builder.launch_parallelism(usage)),
        );

        let mut retry_schedule = RetryDelay::from_msec(100);
        let mut retry_err = RetryError::<Box<Error>>::in_attempt_to("find or build a circuit");

        let mut n_failures = 0;
        let mut n_resets = 0;

        for attempt_num in 1.. {
            // How much time is remaining?
            let remaining = match timeout_at.checked_duration_since(self.runtime.now()) {
                None => {
                    retry_err.push(Error::RequestTimeout);
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
                            warn!("All circuit attempts failed due to timeout");
                            retry_err.push(Error::RequestTimeout);
                            break;
                        }
                    }
                }
                Err(e) => {
                    // We couldn't pick the action!
                    debug_report!(
                        &e,
                        "Couldn't pick action for circuit attempt {}",
                        attempt_num,
                    );
                    e
                }
            };

            // There's been an error.  See how long we wait before we retry.
            let now = self.runtime.now();
            let retry_time =
                error.abs_retry_time(now, || retry_schedule.next_delay(&mut rand::thread_rng()));

            let (count, count_limit) = if error.is_internal_reset() {
                (&mut n_resets, MAX_RESETS)
            } else {
                (&mut n_failures, max_failures)
            };
            // Record the error, flattening it if needed.
            match error {
                Error::RequestFailed(e) => retry_err.extend(e),
                e => retry_err.push(e),
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
    #[allow(dead_code)]
    pub(crate) async fn ensure_circuit(
        self: &Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
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

    /// Choose which action we should take in order to provide a circuit
    /// for a given `usage`.
    ///
    /// If `restrict_circ` is true, we restrict the spec of any
    /// circ we decide to use to mark that it _is_ being used for
    /// `usage`.
    fn prepare_action(
        &self,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
        restrict_circ: bool,
    ) -> Result<Action<B>> {
        let mut list = self.circs.lock().expect("poisoned lock");

        if let Some(mut open) = list.find_open(usage) {
            // We have open circuits that meet the spec: return the best one.
            let parallelism = self.builder.select_parallelism(usage);
            let best = OpenEntry::find_best(&mut open, usage, parallelism);
            if restrict_circ {
                let now = self.runtime.now();
                best.restrict_mut(usage, now)?;
            }
            // TODO: If we have fewer circuits here than our select
            // parallelism, perhaps we should launch more?

            return Ok(Action::Open(best.circ.clone()));
        }

        if let Some(pending) = list.find_pending_circs(usage) {
            // There are pending circuits that could meet the spec.
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
            // TODO: if we have fewer circuits here than our launch
            // parallelism, we might want to launch more.

            return Ok(Action::Wait(stream));
        }

        // Okay, we need to launch circuits here.
        let parallelism = std::cmp::max(1, self.builder.launch_parallelism(usage));
        let mut plans = Vec::new();
        let mut last_err = None;
        for _ in 0..parallelism {
            match self.plan_by_usage(dir, usage) {
                Ok((pending, plan)) => {
                    list.add_pending_circ(pending);
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
    /// resulting circuit or error.
    async fn take_action(
        self: Arc<Self>,
        act: Action<B>,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> std::result::Result<(Arc<B::Circ>, CircProvenance), RetryError<Box<Error>>> {
        /// Store the error `err` into `retry_err`, as appropriate.
        fn record_error(
            retry_err: &mut RetryError<Box<Error>>,
            source: streams::Source,
            building: bool,
            mut err: Error,
        ) {
            if source == streams::Source::Right {
                // We don't care about this error, since it is from neither a circuit we launched
                // nor one that we're waiting on.
                return;
            }
            if !building {
                // We aren't building our own circuits, so our errors are
                // secondary reports of other circuits' failures.
                err = Error::PendingFailed(Box::new(err));
            }
            retry_err.push(err);
        }
        /// Return a string describing what it means, within the context of this
        /// function, to have gotten an answer from `source`.
        fn describe_source(building: bool, source: streams::Source) -> &'static str {
            match (building, source) {
                (_, streams::Source::Right) => "optimistic advice",
                (true, streams::Source::Left) => "circuit we're building",
                (false, streams::Source::Left) => "pending circuit",
            }
        }

        // Get or make a stream of futures to wait on.
        let (building, wait_on_stream) = match act {
            Action::Open(c) => {
                // There's already a perfectly good open circuit; we can return
                // it now.
                return Ok((c, CircProvenance::Preexisting));
            }
            Action::Wait(f) => {
                // There is one or more pending circuit that we're waiting for.
                // If any succeeds, we try to use it.  If they all fail, we
                // fail.
                (false, f)
            }
            Action::Build(plans) => {
                // We're going to launch one or more circuits in parallel.  We
                // report success if any succeeds, and failure of they all fail.
                let futures = FuturesUnordered::new();
                for plan in plans {
                    let self_clone = Arc::clone(&self);
                    // (This is where we actually launch circuits.)
                    futures.push(self_clone.spawn_launch(usage, plan));
                }
                (true, futures)
            }
        };

        // Insert ourself into the list of pending requests, and make a
        // stream for us to listen on for notification from pending circuits
        // other than those we are pending on.
        let (pending_request, additional_stream) = {
            let (send, recv) = mpsc::channel(8);
            let pending = Arc::new(PendingRequest {
                usage: usage.clone(),
                notify: send,
            });

            let mut list = self.circs.lock().expect("poisoned lock");
            list.add_pending_request(&pending);

            (pending, recv)
        };

        // We use our "select_biased" stream combiner here to ensure that:
        //   1) Circuits from wait_on_stream (the ones we're pending on) are
        //      preferred.
        //   2) We exit this function when those circuits are exhausted.
        //   3) We still get notified about other circuits that might meet our
        //      interests.
        //
        // The events from Left stream are the oes that we explicitly asked for,
        // so we'll treat errors there as real problems.  The events from the
        // Right stream are ones that we got opportunistically told about; it's
        // not a big deal if those fail.
        let mut incoming = streams::select_biased(wait_on_stream, additional_stream.map(Ok));

        let mut retry_error = RetryError::in_attempt_to("wait for circuits");

        while let Some((src, id)) = incoming.next().await {
            match id {
                Ok(Ok(ref id)) => {
                    // Great, we have a circuit. See if we can use it!
                    let mut list = self.circs.lock().expect("poisoned lock");
                    if let Some(ent) = list.get_open_mut(id) {
                        let now = self.runtime.now();
                        match ent.restrict_mut(usage, now) {
                            Ok(()) => {
                                // Great, this will work.  We drop the
                                // pending request now explicitly to remove
                                // it from the list.
                                drop(pending_request);
                                if matches!(ent.expiration, ExpirationInfo::Unused { .. }) {
                                    // Since this circuit hasn't been used yet, schedule expiration task after `max_dirtiness` from now.
                                    spawn_expiration_task(
                                        &self.runtime,
                                        Arc::downgrade(&self),
                                        ent.circ.id(),
                                        now + self.circuit_timing().max_dirtiness,
                                    );
                                }
                                return Ok((ent.circ.clone(), CircProvenance::NewlyCreated));
                            }
                            Err(e) => {
                                // In this case, a `UsageMismatched` error just means that we lost the race
                                // to restrict this circuit.
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
                                record_error(&mut retry_error, src, building, e);
                                continue;
                            }
                        }
                    }
                }
                Ok(Err(ref e)) => {
                    debug!("{} sent error {:?}", describe_source(building, src), e);
                    record_error(&mut retry_error, src, building, e.clone());
                }
                Err(oneshot::Canceled) => {
                    debug!(
                        "{} went away (Canceled), quitting take_action right away",
                        describe_source(building, src)
                    );
                    record_error(&mut retry_error, src, building, Error::PendingCanceled);
                    return Err(retry_error);
                }
            }

            debug!(
                "While waiting on circuit: {:?} from {}",
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
    /// build a circuit: A [`PendingEntry`] to keep track of the in-process
    /// circuit, and a [`CircBuildPlan`] that we'll give to the thread
    /// that will build the circuit.
    ///
    /// The caller should probably add the resulting `PendingEntry` to
    /// `self.circs`.
    ///
    /// This is an internal function that we call when we're pretty sure
    /// we want to build a circuit.
    fn plan_by_usage(
        &self,
        dir: DirInfo<'_>,
        usage: &<B::Spec as AbstractSpec>::Usage,
    ) -> Result<(Arc<PendingEntry<B>>, CircBuildPlan<B>)> {
        let (plan, bspec) = self.builder.plan_circuit(usage, dir)?;
        let (pending, sender) = PendingEntry::new(&bspec);
        let pending = Arc::new(pending);

        let plan = CircBuildPlan {
            plan,
            sender,
            pending: Arc::clone(&pending),
        };

        Ok((pending, plan))
    }

    /// Launch a managed circuit for a target usage, without checking
    /// whether one already exists or is pending.
    ///
    /// Return a listener that will be informed when the circuit is done.
    pub(crate) fn launch_by_usage(
        self: &Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<Shared<oneshot::Receiver<PendResult<B>>>> {
        let (pending, plan) = self.plan_by_usage(dir, usage)?;

        self.circs
            .lock()
            .expect("Poisoned lock for circuit list")
            .add_pending_circ(pending);

        Ok(Arc::clone(self).spawn_launch(usage, plan))
    }

    /// Spawn a background task to launch a circuit, and report its status.
    ///
    /// The `usage` argument is the usage from the original request that made
    /// us build this circuit.
    fn spawn_launch(
        self: Arc<Self>,
        usage: &<B::Spec as AbstractSpec>::Usage,
        plan: CircBuildPlan<B>,
    ) -> Shared<oneshot::Receiver<PendResult<B>>> {
        let _ = usage; // Currently unused.
        let CircBuildPlan {
            mut plan,
            sender,
            pending,
        } = plan;
        let request_loyalty = self.circuit_timing().request_loyalty;

        let wait_on_future = pending.receiver.clone();
        let runtime = self.runtime.clone();
        let runtime_copy = self.runtime.clone();

        let tid = rand::random::<u64>();
        // We release this block when the circuit builder task terminates.
        let reason = format!("circuit builder task {}", tid);
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
                        // thread about it, then exit this circuit builder task.
                        let _ = sender.send(Err(internal!("circuit build task panicked").into()));
                        std::panic::panic_any(e);
                    }
                };

                // Tell anybody who was listening about it that this
                // circuit is now usable or failed.
                //
                // (We ignore any errors from `send`: That just means that nobody
                // was waiting for this circuit.)
                let _ = sender.send(reply.clone());

                if let Some(new_spec) = new_spec {
                    // Wait briefly before we notify opportunistically.  This
                    // delay will give the circuits that were originally
                    // specifically intended for a request a little more time
                    // to finish, before we offer it this circuit instead.
                    let sl = runtime_copy.sleep(request_loyalty);
                    runtime_copy.allow_one_advance(request_loyalty);
                    sl.await;

                    let pending = {
                        let list = self.circs.lock().expect("poisoned lock");
                        list.find_pending_requests(&new_spec)
                    };
                    for pending_request in pending {
                        let _ = pending_request.notify.clone().try_send(reply.clone());
                    }
                }
                runtime_copy.release_advance(format!("circuit builder task {}", tid));
            })
            .expect("Couldn't spawn circuit-building task");

        wait_on_future
    }

    /// Run in the background to launch a circuit. Return a 2-tuple of the new
    /// circuit spec and the outcome that should be sent to the initiator.
    async fn do_launch(
        self: Arc<Self>,
        plan: <B as AbstractCircBuilder>::Plan,
        pending: Arc<PendingEntry<B>>,
    ) -> (Option<<B as AbstractCircBuilder>::Spec>, PendResult<B>) {
        let outcome = self.builder.build_circuit(plan).await;

        match outcome {
            Err(e) => (None, Err(e)),
            Ok((new_spec, circ)) => {
                let id = circ.id();

                let use_duration = self.pick_use_duration();
                let exp_inst = self.runtime.now() + use_duration;
                let runtime_copy = self.runtime.clone();
                spawn_expiration_task(&runtime_copy, Arc::downgrade(&self), circ.id(), exp_inst);
                // I used to call restrict_mut here, but now I'm not so
                // sure. Doing restrict_mut makes sure that this
                // circuit will be suitable for the request that asked
                // for us in the first place, but that should be
                // ensured anyway by our tracking its tentative
                // assignment.
                //
                // new_spec.restrict_mut(&usage_copy).unwrap();
                let use_before = ExpirationInfo::new(exp_inst);
                let open_ent = OpenEntry::new(new_spec.clone(), circ, use_before);
                {
                    let mut list = self.circs.lock().expect("poisoned lock");
                    // Finally, before we return this circuit, we need to make
                    // sure that this pending circuit is still pending.  (If it
                    // is not pending, then it was cancelled through a call to
                    // `retire_all_circuits`, and the configuration that we used
                    // to launch it is now sufficiently outdated that we should
                    // no longer give this circuit to a client.)
                    if list.circ_is_pending(&pending) {
                        list.add_open(open_ent);
                        // We drop our reference to 'pending' here:
                        // this should make all the weak references to
                        // the `PendingEntry` become dangling.
                        drop(pending);
                        (Some(new_spec), Ok(id))
                    } else {
                        // This circuit is no longer pending! It must have been cancelled, probably
                        // by a call to retire_all_circuits()
                        drop(pending); // ibid
                        (None, Err(Error::CircCanceled))
                    }
                }
            }
        }
    }

    /// Plan and launch a new circuit to a given target, bypassing our managed
    /// pool of circuits.
    ///
    /// This method will always return a new circuit, and never return a circuit
    /// that this CircMgr gives out for anything else.
    ///
    /// The new circuit will participate in the guard and timeout apparatus as
    /// appropriate, no retry attempt will be made if the circuit fails.
    #[cfg(feature = "hs-common")]
    pub(crate) async fn launch_unmanaged(
        &self,
        usage: &<B::Spec as AbstractSpec>::Usage,
        dir: DirInfo<'_>,
    ) -> Result<(<B as AbstractCircBuilder>::Spec, Arc<B::Circ>)> {
        let (_, plan) = self.plan_by_usage(dir, usage)?;
        self.builder.build_circuit(plan.plan).await
    }

    /// Remove the circuit with a given `id` from this manager.
    ///
    /// After this function is called, that circuit will no longer be handed
    /// out to any future requests.
    ///
    /// Return None if we have no circuit with the given ID.
    pub(crate) fn take_circ(&self, id: &<B::Circ as AbstractCirc>::Id) -> Option<Arc<B::Circ>> {
        let mut list = self.circs.lock().expect("poisoned lock");
        list.take_open(id).map(|e| e.circ)
    }

    /// Remove all open and pending circuits and from this manager, to ensure
    /// they can't be given out for any more requests.
    ///
    /// Calling `retire_all_circuits` ensures that any circuit request that gets
    /// an  answer _after this method runs_ will receive a circuit that was
    /// launched _after this method runs_.
    ///
    /// We call this method this when our configuration changes in such a way
    /// that we want to make sure that any new (or pending) requests will
    /// receive circuits that are built using the new configuration.
    //
    // For more information, see documentation on [`CircuitList::open_circs`],
    // [`CircuitList::pending_circs`], and comments in `do_launch`.
    pub(crate) fn retire_all_circuits(&self) {
        let mut list = self.circs.lock().expect("poisoned lock");
        list.clear_all_circuits();
    }

    /// Expire circuits according to the rules in `config` and the
    /// current time `now`.
    ///
    /// Expired circuits will not be automatically closed, but they will
    /// no longer be given out for new circuits.
    pub(crate) fn expire_circs(&self, now: Instant) {
        let mut list = self.circs.lock().expect("poisoned lock");
        if let Some(dirty_cutoff) = now.checked_sub(self.circuit_timing().max_dirtiness) {
            list.expire_circs(now, dirty_cutoff);
        }
    }

    /// Consider expiring the circuit with given circuit `id`,
    /// according to the rules in `config` and the current time `now`.
    pub(crate) fn expire_circ(&self, circ_id: &<B::Circ as AbstractCirc>::Id, now: Instant) {
        let mut list = self.circs.lock().expect("poisoned lock");
        if let Some(dirty_cutoff) = now.checked_sub(self.circuit_timing().max_dirtiness) {
            list.expire_circ(circ_id, now, dirty_cutoff);
        }
    }

    /// Return the number of open circuits held by this circuit manager.
    pub(crate) fn n_circs(&self) -> usize {
        let list = self.circs.lock().expect("poisoned lock");
        list.open_circs.len()
    }

    /// Return the number of pending circuits tracked by this circuit manager.
    #[cfg(test)]
    pub(crate) fn n_pending_circs(&self) -> usize {
        let list = self.circs.lock().expect("poisoned lock");
        list.pending_circs.len()
    }

    /// Get a reference to this manager's runtime.
    pub(crate) fn peek_runtime(&self) -> &R {
        &self.runtime
    }

    /// Get a reference to this manager's builder.
    pub(crate) fn peek_builder(&self) -> &B {
        &self.builder
    }

    /// Pick a duration by when a new circuit should expire from now
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
            let mut rng = rand::thread_rng();
            rng.gen_range_checked(timings.not_learning..=timings.not_learning * 2)
                .expect("T .. 2x T turned out to be an empty duration range?!")
        }
    }
}

/// Spawn an expiration task that expires a circuit at given instant.
///
/// If given instant is earlier than now, expire the circuit immediately.
/// Otherwise, spawn a timer expiration task on given runtime.
///
/// When the timeout occurs, if the circuit manager is still present,
/// the task will ask the manager to expire the circuit, if the circuit
/// is ready to expire.
fn spawn_expiration_task<B, R>(
    runtime: &R,
    circmgr: Weak<AbstractCircMgr<B, R>>,
    circ_id: <<B as AbstractCircBuilder>::Circ as AbstractCirc>::Id,
    exp_inst: Instant,
) where
    R: Runtime,
    B: 'static + AbstractCircBuilder,
{
    let now = runtime.now();
    let rt_copy = runtime.clone();
    let duration = exp_inst.saturating_duration_since(now);

    if duration == Duration::ZERO {
        // Circuit should already expire. Expire it now.
        let cm = if let Some(cm) = Weak::upgrade(&circmgr) {
            cm
        } else {
            // Circuits manager has already been dropped, so are the references it held.
            return;
        };
        cm.expire_circ(&circ_id, now);
    } else {
        // Spawn a timer expiration task with given expiration instant.
        if let Err(e) = runtime.spawn(async move {
            rt_copy.sleep(duration).await;
            let cm = if let Some(cm) = Weak::upgrade(&circmgr) {
                cm
            } else {
                return;
            };
            cm.expire_circ(&circ_id, exp_inst);
        }) {
            warn_report!(e, "Unable to launch expiration task");
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
    use crate::isolation::test::{assert_isoleq, IsolationTokenEq};
    use crate::usage::{ExitPolicy, SupportedCircUsage};
    use crate::{Error, StreamIsolation, TargetCircUsage, TargetPort};
    use once_cell::sync::Lazy;
    use std::collections::BTreeSet;
    use std::sync::atomic::{self, AtomicUsize};
    use tor_guardmgr::fallback::FallbackList;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_netdir::testnet;
    use tor_rtcompat::SleepProvider;
    use tor_rtmock::MockSleepRuntime;
    use tracing::trace;

    #[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
    struct FakeId {
        id: usize,
    }

    static NEXT_FAKE_ID: AtomicUsize = AtomicUsize::new(0);
    impl FakeId {
        fn next() -> Self {
            let id = NEXT_FAKE_ID.fetch_add(1, atomic::Ordering::SeqCst);
            FakeId { id }
        }
    }

    #[derive(Debug, PartialEq, Clone, Eq)]
    struct FakeCirc {
        id: FakeId,
    }

    impl FakeCirc {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl AbstractCirc for FakeCirc {
        type Id = FakeId;
        fn id(&self) -> FakeId {
            self.id
        }
        fn usable(&self) -> bool {
            true
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    struct FakeSpec {
        ports: BTreeSet<u16>,
        isolation: Option<u8>,
    }

    impl AbstractSpec for FakeSpec {
        type Usage = FakeSpec;
        fn supports(&self, other: &FakeSpec) -> bool {
            let ports_ok = self.ports.is_superset(&other.ports);
            let iso_ok = match (self.isolation, other.isolation) {
                (None, _) => true,
                (_, None) => true,
                (Some(a), Some(b)) => a == b,
            };
            ports_ok && iso_ok
        }
        fn restrict_mut(&mut self, other: &FakeSpec) -> std::result::Result<(), RestrictionFailed> {
            if !self.ports.is_superset(&other.ports) {
                return Err(RestrictionFailed::NotSupported);
            }
            let new_iso = match (self.isolation, other.isolation) {
                (None, x) => x,
                (x, None) => x,
                (Some(a), Some(b)) if a == b => Some(a),
                (_, _) => return Err(RestrictionFailed::NotSupported),
            };

            self.isolation = new_iso;
            Ok(())
        }
        fn channel_usage(&self) -> ChannelUsage {
            ChannelUsage::UserTraffic
        }
    }

    impl FakeSpec {
        fn new<T>(ports: T) -> Self
        where
            T: IntoIterator,
            T::Item: Into<u16>,
        {
            let ports = ports.into_iter().map(Into::into).collect();
            FakeSpec {
                ports,
                isolation: None,
            }
        }
        fn isolated(self, group: u8) -> Self {
            FakeSpec {
                ports: self.ports,
                isolation: Some(group),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakePlan {
        spec: FakeSpec,
        op: FakeOp,
    }

    #[derive(Debug)]
    struct FakeBuilder<RT: Runtime> {
        runtime: RT,
        script: sync::Mutex<HashMap<FakeSpec, Vec<FakeOp>>>,
    }

    #[derive(Debug, Clone)]
    enum FakeOp {
        Succeed,
        Fail,
        Delay(Duration),
        Timeout,
        TimeoutReleaseAdvance(String),
        NoPlan,
        WrongSpec(FakeSpec),
    }

    impl MockablePlan for FakePlan {
        fn add_blocked_advance_reason(&mut self, reason: String) {
            if let FakeOp::Timeout = self.op {
                self.op = FakeOp::TimeoutReleaseAdvance(reason);
            }
        }
    }

    const FAKE_CIRC_DELAY: Duration = Duration::from_millis(30);

    static FALLBACKS_EMPTY: Lazy<FallbackList> = Lazy::new(|| [].into());

    fn di() -> DirInfo<'static> {
        (&*FALLBACKS_EMPTY).into()
    }

    #[async_trait]
    impl<RT: Runtime> AbstractCircBuilder for FakeBuilder<RT> {
        type Spec = FakeSpec;
        type Circ = FakeCirc;
        type Plan = FakePlan;

        fn plan_circuit(&self, spec: &FakeSpec, _dir: DirInfo<'_>) -> Result<(FakePlan, FakeSpec)> {
            let next_op = self.next_op(spec);
            if matches!(next_op, FakeOp::NoPlan) {
                return Err(Error::NoRelay {
                    path_kind: "example",
                    role: "example",
                    problem: "called with no plan".to_string(),
                });
            }
            let plan = FakePlan {
                spec: spec.clone(),
                op: next_op,
            };
            Ok((plan, spec.clone()))
        }

        async fn build_circuit(&self, plan: FakePlan) -> Result<(FakeSpec, Arc<FakeCirc>)> {
            let op = plan.op;
            let sl = self.runtime.sleep(FAKE_CIRC_DELAY);
            self.runtime.allow_one_advance(FAKE_CIRC_DELAY);
            sl.await;
            match op {
                FakeOp::Succeed => Ok((plan.spec, Arc::new(FakeCirc { id: FakeId::next() }))),
                FakeOp::WrongSpec(s) => Ok((s, Arc::new(FakeCirc { id: FakeId::next() }))),
                FakeOp::Fail => Err(Error::CircTimeout(None)),
                FakeOp::Delay(d) => {
                    let sl = self.runtime.sleep(d);
                    self.runtime.allow_one_advance(d);
                    sl.await;
                    Err(Error::PendingCanceled)
                }
                FakeOp::Timeout => unreachable!(), // should be converted to the below
                FakeOp::TimeoutReleaseAdvance(reason) => {
                    trace!("releasing advance to fake a timeout");
                    self.runtime.release_advance(reason);
                    let () = futures::future::pending().await;
                    unreachable!()
                }
                FakeOp::NoPlan => unreachable!(),
            }
        }

        fn learning_timeouts(&self) -> bool {
            false
        }
    }

    impl<RT: Runtime> FakeBuilder<RT> {
        fn new(rt: &RT) -> Self {
            FakeBuilder {
                runtime: rt.clone(),
                script: sync::Mutex::new(HashMap::new()),
            }
        }

        /// set a plan for a given FakeSpec.
        fn set<I>(&self, spec: FakeSpec, v: I)
        where
            I: IntoIterator<Item = FakeOp>,
        {
            let mut ops: Vec<_> = v.into_iter().collect();
            ops.reverse();
            let mut lst = self.script.lock().unwrap();
            lst.insert(spec, ops);
        }

        fn next_op(&self, spec: &FakeSpec) -> FakeOp {
            let mut script = self.script.lock().unwrap();
            let mut s = script.get_mut(spec);
            match s {
                None => FakeOp::Succeed,
                Some(ref mut lst) => lst.pop().unwrap_or(FakeOp::Succeed),
            }
        }
    }

    impl<T: IsolationTokenEq, U: PartialEq> IsolationTokenEq for OpenEntry<T, U> {
        fn isol_eq(&self, other: &Self) -> bool {
            self.spec.isol_eq(&other.spec)
                && self.circ == other.circ
                && self.expiration == other.expiration
        }
    }

    impl<T: IsolationTokenEq, U: PartialEq> IsolationTokenEq for &mut OpenEntry<T, U> {
        fn isol_eq(&self, other: &Self) -> bool {
            self.spec.isol_eq(&other.spec)
                && self.circ == other.circ
                && self.expiration == other.expiration
        }
    }

    #[test]
    fn basic_tests() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);

            let builder = FakeBuilder::new(&rt);

            let mgr = Arc::new(AbstractCircMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            let webports = FakeSpec::new(vec![80_u16, 443]);

            // Check initialization.
            assert_eq!(mgr.n_circs(), 0);
            assert!(mgr.peek_builder().script.lock().unwrap().is_empty());

            // Launch a circuit; make sure we get it.
            let c1 = rt.wait_for(mgr.get_or_launch(&webports, di())).await;
            let c1 = c1.unwrap().0;
            assert_eq!(mgr.n_circs(), 1);

            // Make sure we get the one we already made if we ask for it.
            let port80 = FakeSpec::new(vec![80_u16]);
            let c2 = mgr.get_or_launch(&port80, di()).await;

            let c2 = c2.unwrap().0;
            assert!(FakeCirc::eq(&c1, &c2));
            assert_eq!(mgr.n_circs(), 1);

            // Now try launching two circuits "at once" to make sure that our
            // pending-circuit code works.

            let dnsport = FakeSpec::new(vec![53_u16]);
            let dnsport_restrict = dnsport.clone().isolated(7);

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
            assert_eq!(mgr.n_circs(), 2);

            // Now we're going to remove c3 from consideration.  It's the
            // same as c4, so removing c4 will give us None.
            let c3_taken = mgr.take_circ(&c3.id()).unwrap();
            let now_its_gone = mgr.take_circ(&c4.id());
            assert!(FakeCirc::eq(&c3_taken, &c3));
            assert!(now_its_gone.is_none());
            assert_eq!(mgr.n_circs(), 1);

            // Having removed them, let's launch another dnsport and make
            // sure we get a different circuit.
            let c5 = rt.wait_for(mgr.get_or_launch(&dnsport, di())).await;
            let c5 = c5.unwrap().0;
            assert!(!FakeCirc::eq(&c3, &c5));
            assert!(!FakeCirc::eq(&c4, &c5));
            assert_eq!(mgr.n_circs(), 2);

            // Now try launch_by_usage.
            let prev = mgr.n_pending_circs();
            assert!(mgr.launch_by_usage(&dnsport, di()).is_ok());
            assert_eq!(mgr.n_pending_circs(), prev + 1);
            // TODO: Actually make sure that launch_by_usage launched
            // the right thing.
        });
    }

    #[test]
    fn request_timeout() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);

            let ports = FakeSpec::new(vec![80_u16, 443]);

            // This will fail once, and then completely time out.  The
            // result will be a failure.
            let builder = FakeBuilder::new(&rt);
            builder.set(ports.clone(), vec![FakeOp::Fail, FakeOp::Timeout]);

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);

            // Now try a more complicated case: we'll try to get things so
            // that we wait for a little over our predicted time because
            // of our wait-for-next-action logic.
            let ports = FakeSpec::new(vec![80_u16, 443]);
            let builder = FakeBuilder::new(&rt);
            builder.set(
                ports.clone(),
                vec![
                    FakeOp::Delay(Duration::from_millis(60_000 - 25)),
                    FakeOp::NoPlan,
                ],
            );

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);

            let ports = FakeSpec::new(vec![80_u16, 443]);

            // This will fail a the planning stages, a lot.
            let builder = FakeBuilder::new(&rt);
            builder.set(ports.clone(), vec![FakeOp::NoPlan; 2000]);

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);
            let ports = FakeSpec::new(vec![80_u16, 443]);

            // This will fail 1000 times, which is above the retry limit.
            let builder = FakeBuilder::new(&rt);
            builder.set(ports.clone(), vec![FakeOp::Fail; 1000]);

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);
            let ports = FakeSpec::new(vec![80_u16, 443]);

            // The first time this is called, it will build a circuit
            // with the wrong spec.  (A circuit builder should never
            // actually _do_ that, but it's something we code for.)
            let builder = FakeBuilder::new(&rt);
            builder.set(
                ports.clone(),
                vec![FakeOp::WrongSpec(FakeSpec::new(vec![22_u16]))],
            );

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);
            let ports = FakeSpec::new(vec![80_u16, 443]);

            // This will fail twice, and then succeed. The result will be
            // a success.
            let builder = FakeBuilder::new(&rt);
            builder.set(ports.clone(), vec![FakeOp::Fail, FakeOp::Fail]);

            let mgr = Arc::new(AbstractCircMgr::new(
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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);
            let builder = FakeBuilder::new(&rt);
            let mgr = Arc::new(AbstractCircMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            let ports = FakeSpec::new(vec![443_u16]);
            // Set our isolation so that iso1 and iso2 can't share a circuit,
            // but no_iso can share a circuit with either.
            let iso1 = ports.clone().isolated(1);
            let iso2 = ports.clone().isolated(2);
            let no_iso = ports.clone();

            // We're going to try launching these circuits in 6 different
            // orders, to make sure that the outcome is correct each time.
            use itertools::Itertools;
            let timeouts: Vec<_> = [0_u64, 5, 10]
                .iter()
                .map(|d| Duration::from_millis(*d))
                .collect();

            for delays in timeouts.iter().permutations(3) {
                let d1 = delays[0];
                let d2 = delays[1];
                let d3 = delays[2];
                let (c_iso1, c_iso2, c_none) = rt
                    .wait_for(futures::future::join3(
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
                            mgr.get_or_launch(&no_iso, di()).await
                        },
                    ))
                    .await;

                let c_iso1 = c_iso1.unwrap().0;
                let c_iso2 = c_iso2.unwrap().0;
                let c_none = c_none.unwrap().0;

                assert!(!FakeCirc::eq(&c_iso1, &c_iso2));
                assert!(FakeCirc::eq(&c_iso1, &c_none) || FakeCirc::eq(&c_iso2, &c_none));
            }
        });
    }

    #[test]
    fn opportunistic() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let rt = MockSleepRuntime::new(rt);

            // The first request will time out completely, but we're
            // making a second request after we launch it.  That
            // request should succeed, and notify the first request.

            let ports1 = FakeSpec::new(vec![80_u16]);
            let ports2 = FakeSpec::new(vec![80_u16, 443]);

            let builder = FakeBuilder::new(&rt);
            builder.set(ports1.clone(), vec![FakeOp::Timeout]);

            let mgr = Arc::new(AbstractCircMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));
            // Note that ports2 will be wider than ports1, so the second
            // request will have to launch a new circuit.

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
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            // This time we're going to use ensure_circuit() to make
            // sure that a circuit gets built, and then launch two
            // other circuits that will use it.
            let rt = MockSleepRuntime::new(rt);
            let builder = FakeBuilder::new(&rt);
            let mgr = Arc::new(AbstractCircMgr::new(
                builder,
                rt.clone(),
                CircuitTiming::default(),
            ));

            let ports1 = FakeSpec::new(vec![80_u16, 443]);
            let ports2 = FakeSpec::new(vec![80_u16]);
            let ports3 = FakeSpec::new(vec![443_u16]);
            let (ok, c1, c2) = rt
                .wait_for(futures::future::join3(
                    mgr.ensure_circuit(&ports1, di()),
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
            // a circuit.
            assert!(FakeCirc::eq(&c1, &c2));
        });
    }

    #[test]
    fn expiration() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            use crate::config::CircuitTimingBuilder;
            // Now let's make some circuits -- one dirty, one clean, and
            // make sure that one expires and one doesn't.
            let rt = MockSleepRuntime::new(rt);
            let builder = FakeBuilder::new(&rt);

            let circuit_timing = CircuitTimingBuilder::default()
                .max_dirtiness(Duration::from_secs(15))
                .build()
                .unwrap();

            let mgr = Arc::new(AbstractCircMgr::new(builder, rt.clone(), circuit_timing));

            let imap = FakeSpec::new(vec![993_u16]);
            let pop = FakeSpec::new(vec![995_u16]);

            let (ok, pop1) = rt
                .wait_for(futures::future::join(
                    mgr.ensure_circuit(&imap, di()),
                    mgr.get_or_launch(&pop, di()),
                ))
                .await;

            assert!(ok.is_ok());
            let pop1 = pop1.unwrap().0;

            rt.advance(Duration::from_secs(30)).await;
            rt.advance(Duration::from_secs(15)).await;
            let imap1 = rt.wait_for(mgr.get_or_launch(&imap, di())).await.unwrap().0;

            // This should expire the pop circuit, since it came from
            // get_or_launch() [which marks the circuit as being
            // used].  It should not expire the imap circuit, since
            // it was not dirty until 15 seconds after the cutoff.
            let now = rt.now();

            mgr.expire_circs(now);

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
        let fake_circ = Arc::new(FakeCirc { id: FakeId::next() });
        let expiration = ExpirationInfo::Unused {
            use_before: Instant::now() + Duration::from_secs(60 * 60),
        };

        let mut entry_none = OpenEntry::new(
            SupportedCircUsage::Exit {
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
            SupportedCircUsage::Exit {
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
            SupportedCircUsage::Exit {
                policy: ep_full,
                isolation: None,
                country_code: None,
                all_relays_stable: true,
            },
            fake_circ,
            expiration,
        );
        let mut entry_full_c = entry_full.clone();

        let usage_web = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation: StreamIsolation::no_isolation(),
            country_code: None,
            require_stability: false,
        };
        let empty: Vec<&mut OpenEntry<SupportedCircUsage, FakeCirc>> = vec![];

        assert_isoleq!(
            SupportedCircUsage::find_supported(vec![&mut entry_none].into_iter(), &usage_web),
            empty
        );

        // HACK(eta): We have to faff around with clones and such because
        //            `abstract_spec_find_supported` has a silly signature that involves `&mut`
        //            refs, which we can't have more than one of.

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_web,
            ),
            vec![&mut entry_web_c]
        );

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
                &usage_web,
            ),
            vec![&mut entry_web_c, &mut entry_full_c]
        );

        // Test preemptive circuit usage:

        let usage_preemptive_web = TargetCircUsage::Preemptive {
            port: Some(TargetPort::ipv4(80)),
            circs: 2,
            require_stability: false,
        };
        let usage_preemptive_dns = TargetCircUsage::Preemptive {
            port: None,
            circs: 2,
            require_stability: false,
        };

        // shouldn't return anything unless there are >=2 circuits

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none].into_iter(),
                &usage_preemptive_web
            ),
            empty
        );

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none].into_iter(),
                &usage_preemptive_dns
            ),
            empty
        );

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_preemptive_web
            ),
            empty
        );

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none, &mut entry_web].into_iter(),
                &usage_preemptive_dns
            ),
            vec![&mut entry_none_c, &mut entry_web_c]
        );

        assert_isoleq!(
            SupportedCircUsage::find_supported(
                vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
                &usage_preemptive_web
            ),
            vec![&mut entry_web_c, &mut entry_full_c]
        );
    }
}
