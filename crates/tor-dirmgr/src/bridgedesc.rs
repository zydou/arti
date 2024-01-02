//! `BridgeDescMgr` - downloads and caches bridges' router descriptors

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt::{self, Debug, Display};
use std::num::NonZeroU8;
use std::ops;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use derive_more::{Deref, DerefMut};
use educe::Educe;
use futures::future;
use futures::select;
use futures::stream::{BoxStream, StreamExt};
use futures::task::{SpawnError, SpawnExt as _};
use futures::FutureExt;
use tracing::{debug, error, info, trace};

use safelog::sensitive;
use tor_basic_utils::retry::RetryDelay;
use tor_basic_utils::BinaryHeapExt as _;
use tor_checkable::{SelfSigned, Timebound};
use tor_circmgr::CircMgr;
use tor_error::{error_report, internal, ErrorKind, HasKind};
use tor_error::{AbsRetryTime, HasRetryTime, RetryTime};
use tor_guardmgr::bridge::{BridgeConfig, BridgeDesc};
use tor_guardmgr::bridge::{BridgeDescError, BridgeDescEvent, BridgeDescList, BridgeDescProvider};
use tor_netdoc::doc::routerdesc::RouterDesc;
use tor_rtcompat::Runtime;

use crate::event::FlagPublisher;
use crate::storage::CachedBridgeDescriptor;
use crate::{DirMgrStore, DynStore};

#[cfg(test)]
mod bdtest;

/// The key we use in all our data structures
///
/// This type saves typing and would make it easier to change the bridge descriptor manager
/// to take and handle another way of identifying the bridges it is working with.
type BridgeKey = BridgeConfig;

/// Active vs dormant state, as far as the bridge descriptor manager is concerned
///
/// This is usually derived in higher layers from `arti_client::DormantMode`,
/// whether `TorClient::bootstrap()` has been called, etc.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
// TODO: These proliferating `Dormancy` enums should be centralized and unified with `TaskHandle`
//     https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/845#note_2853190
pub enum Dormancy {
    /// Dormant (inactive)
    ///
    /// Bridge descriptor downloads, or refreshes, will not be started.
    ///
    /// In-progress downloads will be stopped if possible,
    /// but they may continue until they complete (or fail).
    // TODO async task cancellation: actually cancel these in this case
    ///
    /// So a dormant BridgeDescMgr may still continue to
    /// change the return value from [`bridges()`](BridgeDescProvider::bridges)
    /// and continue to report [`BridgeDescEvent`]s.
    ///
    /// When the BridgeDescMgr is dormant,
    /// `bridges()` may return stale descriptors
    /// (that is, descriptors which ought to have been refetched and may no longer be valid),
    /// or stale errors
    /// (that is, errors which occurred some time ago,
    /// and which would normally have been retried by now).
    Dormant,

    /// Active
    ///
    /// Bridge descriptors will be downloaded as requested.
    ///
    /// When a bridge descriptor manager has been `Dormant`,
    /// it may continue to provide stale data (as described)
    /// for a while after it is made `Active`,
    /// until the required refreshes and retries have taken place (or failed).
    Active,
}

/// **Downloader and cache for bridges' router descriptors**
///
/// This is a handle which is cheap to clone and has internal mutability.
#[derive(Clone)]
pub struct BridgeDescMgr<R: Runtime, M = ()>
where
    M: Mockable<R>,
{
    /// The actual manager
    ///
    /// We have the `Arc` in here, rather than in our callers, because this
    /// makes the API nicer for them, and also because some of our tasks
    /// want a handle they can use to relock and modify the state.
    mgr: Arc<Manager<R, M>>,
}

/// Configuration for the `BridgeDescMgr`
///
/// Currently, the only way to make this is via its `Default` impl.
// TODO: there should be some way to override the defaults.  See #629 for considerations.
#[derive(Debug, Clone)]
pub struct BridgeDescDownloadConfig {
    /// How many bridge descriptor downloads to attempt in parallel?
    parallelism: NonZeroU8,

    /// Default/initial time to retry a failure to download a descriptor
    ///
    /// (This has the semantics of an initial delay for [`RetryDelay`],
    /// and is used unless there is more specific retry information for the particular failure.)
    retry: Duration,

    /// When a downloaded descriptor is going to expire, how soon in advance to refetch it?
    prefetch: Duration,

    /// Minimum interval between successive refetches of the descriptor for the same bridge
    ///
    /// This limits the download activity which can be caused by an errant bridge.
    ///
    /// If the descriptor's validity information is shorter than this, we will use
    /// it after it has expired (rather than treating the bridge as broken).
    min_refetch: Duration,

    /// Maximum interval between successive refetches of the descriptor for the same bridge
    ///
    /// This sets an upper bound on how old a descriptor we are willing to use.
    /// When this time expires, a refetch attempt will be started even if the
    /// descriptor is not going to expire soon.
    //
    // TODO: When this is configurable, we need to make sure we reject
    // configurations with max_refresh < min_refresh, or we may panic.
    max_refetch: Duration,
}

impl Default for BridgeDescDownloadConfig {
    fn default() -> Self {
        let secs = Duration::from_secs;
        BridgeDescDownloadConfig {
            parallelism: 4.try_into().expect("parallelism is zero"),
            retry: secs(30),
            prefetch: secs(1000),
            min_refetch: secs(3600),
            max_refetch: secs(3600 * 3), // matches C Tor behaviour
        }
    }
}

/// Mockable internal methods for within the `BridgeDescMgr`
///
/// Implemented for `()`, meaning "do not use mocks: use the real versions of everything".
///
/// This (`()`) is the default for the type parameter in
/// [`BridgeDescMgr`],
/// and it is the only publicly available implementation,
/// since this trait is sealed.
pub trait Mockable<R>: mockable::MockableAPI<R> {}
impl<R: Runtime> Mockable<R> for () {}

/// Private module which seals [`Mockable`]
/// by containing [`MockableAPI`](mockable::MockableAPI)
mod mockable {
    use super::*;

    /// Defines the actual mockable APIs
    ///
    /// Not nameable (and therefore not implementable)
    /// outside the `bridgedesc` module,
    #[async_trait]
    pub trait MockableAPI<R>: Clone + Send + Sync + 'static {
        /// Circuit manager
        type CircMgr: Send + Sync + 'static;

        /// Download this bridge's descriptor, and return it as a string
        ///
        /// Runs in a task.
        /// Called by `Manager::download_descriptor`, which handles parsing and validation.
        ///
        /// If `if_modified_since` is `Some`,
        /// should tolerate an HTTP 304 Not Modified and return `None` in that case.
        /// If `if_modified_since` is `None`, returning `Ok(None,)` is forbidden.
        async fn download(
            self,
            runtime: &R,
            circmgr: &Self::CircMgr,
            bridge: &BridgeConfig,
            if_modified_since: Option<SystemTime>,
        ) -> Result<Option<String>, Error>;
    }
}
#[async_trait]
impl<R: Runtime> mockable::MockableAPI<R> for () {
    type CircMgr = Arc<CircMgr<R>>;

    /// Actual code for downloading a descriptor document
    async fn download(
        self,
        runtime: &R,
        circmgr: &Self::CircMgr,
        bridge: &BridgeConfig,
        _if_modified_since: Option<SystemTime>,
    ) -> Result<Option<String>, Error> {
        // TODO actually support _if_modified_since
        let circuit = circmgr.get_or_launch_dir_specific(bridge).await?;
        let mut stream = circuit
            .begin_dir_stream()
            .await
            .map_err(Error::StreamFailed)?;
        let request = tor_dirclient::request::RoutersOwnDescRequest::new();
        let response = tor_dirclient::send_request(runtime, &request, &mut stream, None)
            .await
            .map_err(|dce| match dce {
                tor_dirclient::Error::RequestFailed(re) => Error::RequestFailed(re),
                _ => internal!(
                    "tor_dirclient::send_request gave non-RequestFailed {:?}",
                    dce
                )
                .into(),
            })?;
        let output = response.into_output_string()?;
        Ok(Some(output))
    }
}

/// The actual manager.
struct Manager<R: Runtime, M: Mockable<R>> {
    /// The mutable state
    state: Mutex<State>,

    /// Runtime, used for tasks and sleeping
    runtime: R,

    /// Circuit manager, used for creating circuits
    circmgr: M::CircMgr,

    /// Persistent state store
    store: Arc<Mutex<DynStore>>,

    /// Mock for testing, usually `()`
    mockable: M,
}

/// State: our downloaded descriptors (cache), and records of what we're doing
///
/// Various functions (both tasks and public entrypoints),
/// which generally start with a `Manager`,
/// lock the mutex and modify this.
///
/// Generally, the flow is:
///
///  * A public entrypoint, or task, obtains a [`StateGuard`].
///    It modifies the state to represent the callers' new requirements,
///    or things it has done, by updating the state,
///    preserving the invariants but disturbing the "liveness" (see below).
///
///  * [`StateGuard::drop`] calls [`State::process`].
///    This restores the liveness properties.
///
/// ### Possible states of a bridge:
///
/// A bridge can be in one of the following states,
/// represented by its presence in these particular data structures inside `State`:
///
///  * `running`/`queued`: newly added, no outcome yet.
///  * `current` + `running`/`queued`: we are fetching (or going to)
///  * `current = OK` + `refetch_schedule`: fetched OK, will refetch before expiry
///  * `current = Err` + `retry_schedule`: failed, will retry at some point
///
/// ### Invariants:
///
/// Can be disrupted in the middle of a principal function,
/// but should be restored on return.
///
/// * **Tracked**:
///   Each bridge appears at most once in
///   `running`, `queued`, `refetch_schedule` and `retry_schedule`.
///   We call such a bridge Tracked.
///
/// * **Current**
///   Every bridge in `current` is Tracked.
///   (But not every Tracked bridge is necessarily in `current`, yet.)
///
/// * **Schedules**
///   Every bridge in `refetch_schedule` or `retry_schedule` is also in `current`.
///
/// * **Input**:
///   Exactly each bridge that was passed to
///   the last call to [`set_bridges()`](BridgeDescMgr::set_bridges) is Tracked.
///   (If we encountered spawn failures, we treat this as trying to shut down,
///   so we cease attempts to get bridges, and discard the relevant state, violating this.)
///
/// * **Limit**:
///   `running` is capped at the effective parallelism: zero if we are dormant,
///   the configured parallelism otherwise.
///
/// ### Liveness properties:
///
/// These can be disrupted by any function which holds a [`StateGuard`].
/// Will be restored by [`process()`](State::process),
/// which is called when `StateGuard` is dropped.
///
/// Functions that take a `StateGuard` may disturb these invariants
/// and rely on someone else to restore them.
///
/// * **Running**:
///   If `queued` is nonempty, `running` is full.
///
/// * **Timeout**:
///   `earliest_timeout` is the earliest timeout in
///   either `retry_schedule` or `refetch_schedule`.
///   (Disturbances of this property which occur due to system time warps
///   are not necessarily detected and remedied in a timely way,
///   but will be remedied no later than after `max_refetch`.)
struct State {
    /// Our configuration
    config: Arc<BridgeDescDownloadConfig>,

    /// People who will be told when `current` changes.
    subscribers: FlagPublisher<BridgeDescEvent>,

    /// Our current idea of our output, which we give out handles onto.
    current: Arc<BridgeDescList>,

    /// Bridges whose descriptors we are currently downloading.
    running: HashMap<BridgeKey, RunningInfo>,

    /// Bridges which we want to download,
    /// but we're waiting for `running` to be less than `effective_parallelism()`.
    queued: VecDeque<QueuedEntry>,

    /// Are we dormant?
    dormancy: Dormancy,

    /// Bridges that we have a descriptor for,
    /// and when they should be refetched due to validity expiry.
    ///
    /// This is indexed by `SystemTime` because that helps avoids undesirable behaviors
    /// when the system clock changes.
    refetch_schedule: BinaryHeap<RefetchEntry<SystemTime, ()>>,

    /// Bridges that failed earlier, and when they should be retried.
    retry_schedule: BinaryHeap<RefetchEntry<Instant, RetryDelay>>,

    /// Earliest time from either `retry_schedule` or `refetch_schedule`
    ///
    /// `None` means "wait indefinitely".
    earliest_timeout: postage::watch::Sender<Option<Instant>>,
}

impl Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Helper to format one bridge entry somewhere
        fn fmt_bridge(
            f: &mut fmt::Formatter,
            b: &BridgeConfig,
            info: &(dyn Display + '_),
        ) -> fmt::Result {
            let info = info.to_string(); // fmt::Formatter doesn't enforce precision, so do this
            writeln!(f, "    {:80.80} | {}", info, b)
        }

        /// Helper to format one of the schedules
        fn fmt_schedule<TT: Ord + Copy + Debug, RD>(
            f: &mut fmt::Formatter,
            summary: &str,
            name: &str,
            schedule: &BinaryHeap<RefetchEntry<TT, RD>>,
        ) -> fmt::Result {
            writeln!(f, "  {}:", name)?;
            for b in schedule {
                fmt_bridge(f, &b.bridge, &format_args!("{} {:?}", summary, &b.when))?;
            }
            Ok(())
        }

        // We are going to have to go multi-line because of the bridge lines,
        // so do completely bespoke formatting rather than `std::fmt::DebugStruct`
        // or a derive.
        writeln!(f, "State {{")?;
        // We'd like to print earliest_timeout but watch::Sender::borrow takes &mut
        writeln!(f, "  earliest_timeout: ???, ..,")?;
        writeln!(f, "  current:")?;
        for (b, v) in &*self.current {
            fmt_bridge(
                f,
                b,
                &match v {
                    Err(e) => Cow::from(format!("C Err {}", e)),
                    Ok(_) => "C Ok".into(),
                },
            )?;
        }
        writeln!(f, "  running:")?;
        for b in self.running.keys() {
            fmt_bridge(f, b, &"R")?;
        }
        writeln!(f, "  queued:")?;
        for qe in &self.queued {
            fmt_bridge(f, &qe.bridge, &"Q")?;
        }
        fmt_schedule(f, "FS", "refetch_schedule", &self.refetch_schedule)?;
        fmt_schedule(f, "TS", "retry_schedule", &self.retry_schedule)?;
        write!(f, "}}")?;

        Ok(())
    }
}

/// Value of the entry in `running`
#[derive(Debug)]
struct RunningInfo {
    /// For cancelling downloads no longer wanted
    join: JoinHandle,

    /// If this previously failed, the persistent retry delay.
    retry_delay: Option<RetryDelay>,
}

/// Entry in `queued`
#[derive(Debug)]
struct QueuedEntry {
    /// The bridge to fetch
    bridge: BridgeKey,

    /// If this previously failed, the persistent retry delay.
    retry_delay: Option<RetryDelay>,
}

/// Entry in one of the `*_schedule`s
///
/// Implements `Ord` and `Eq` but *only looking at the refetch time*.
/// So don't deduplicate by `[Partial]Eq`, or use as a key in a map.
#[derive(Debug)]
struct RefetchEntry<TT, RD> {
    /// When should we requeued this bridge for fetching
    ///
    /// Either [`Instant`] (in `retry_schedule`) or [`SystemTime`] (in `refetch_schedule`).
    when: TT,

    /// The bridge to refetch
    bridge: BridgeKey,

    /// Retry delay
    ///
    /// `RetryDelay` if we previously failed (ie, if this is a retry entry);
    /// otherwise `()`.
    retry_delay: RD,
}

impl<TT: Ord, RD> Ord for RefetchEntry<TT, RD> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.when.cmp(&other.when).reverse()
        // We don't care about the ordering of BridgeConfig or retry_delay.
        // Different BridgeConfig with the same fetch time will be fetched in "some order".
    }
}

impl<TT: Ord, RD> PartialOrd for RefetchEntry<TT, RD> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<TT: Ord, RD> PartialEq for RefetchEntry<TT, RD> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<TT: Ord, RD> Eq for RefetchEntry<TT, RD> {}

/// Dummy task join handle
///
/// We would like to be able to cancel now-redundant downloads
/// using something like `tokio::task::JoinHandle::abort()`.
/// tor-rtcompat doesn't support that so we stub it for now.
///
/// Providing this stub means the place where the cancellation needs to take place
/// already has the appropriate call to our [`JoinHandle::abort`].
#[derive(Debug)]
struct JoinHandle;

impl JoinHandle {
    /// Would abort this async task, if we could do that.
    fn abort(&self) {}
}

impl<R: Runtime> BridgeDescMgr<R> {
    /// Create a new `BridgeDescMgr`
    ///
    /// This is the public constructor.
    //
    // TODO: That this constructor requires a DirMgr is rather odd.
    // In principle there is little reason why you need a DirMgr to make a BridgeDescMgr.
    // However, BridgeDescMgr needs a Store, and currently that is a private trait, and the
    // implementation is constructible only from the dirmgr's config.  This should probably be
    // tidied up somehow, at some point, perhaps by exposing `Store` and its configuration.
    pub fn new(
        config: &BridgeDescDownloadConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<tor_circmgr::CircMgr<R>>,
        dormancy: Dormancy,
    ) -> Result<Self, StartupError> {
        Self::new_internal(runtime, circmgr, store.store, config, dormancy, ())
    }
}

/// If download was successful, what we obtained
///
/// Generated by `process_document`, from a downloaded (or cached) textual descriptor.
#[derive(Debug)]
struct Downloaded {
    /// The bridge descriptor, fully parsed and verified
    desc: BridgeDesc,

    /// When we should start a refresh for this descriptor
    ///
    /// This is derived from the expiry time,
    /// and clamped according to limits in the configuration).
    refetch: SystemTime,
}

impl<R: Runtime, M: Mockable<R>> BridgeDescMgr<R, M> {
    /// Actual constructor, which takes a mockable
    //
    // Allow passing `runtime` by value, which is usual API for this kind of setup function.
    #[allow(clippy::needless_pass_by_value)]
    fn new_internal(
        runtime: R,
        circmgr: M::CircMgr,
        store: Arc<Mutex<DynStore>>,
        config: &BridgeDescDownloadConfig,
        dormancy: Dormancy,
        mockable: M,
    ) -> Result<Self, StartupError> {
        /// Convenience alias
        fn default<T: Default>() -> T {
            Default::default()
        }

        let config = config.clone().into();
        let (earliest_timeout, timeout_update) = postage::watch::channel();

        let state = Mutex::new(State {
            config,
            subscribers: default(),
            current: default(),
            running: default(),
            queued: default(),
            dormancy,
            retry_schedule: default(),
            refetch_schedule: default(),
            earliest_timeout,
        });
        let mgr = Arc::new(Manager {
            state,
            runtime: runtime.clone(),
            circmgr,
            store,
            mockable,
        });

        runtime
            .spawn(timeout_task(
                runtime.clone(),
                Arc::downgrade(&mgr),
                timeout_update,
            ))
            .map_err(|cause| StartupError::Spawn {
                spawning: "timeout task",
                cause: cause.into(),
            })?;

        Ok(BridgeDescMgr { mgr })
    }

    /// Consistency check convenience wrapper
    #[cfg(test)]
    fn check_consistency<'i, I>(&self, input_bridges: Option<I>)
    where
        I: IntoIterator<Item = &'i BridgeKey>,
    {
        self.mgr
            .lock_only()
            .check_consistency(&self.mgr.runtime, input_bridges);
    }

    /// Set whether this `BridgeDescMgr` is active
    // TODO this should instead be handled by a central mechanism; see TODO on Dormancy
    pub fn set_dormancy(&self, dormancy: Dormancy) {
        self.mgr.lock_then_process().dormancy = dormancy;
    }
}

impl<R: Runtime, M: Mockable<R>> BridgeDescProvider for BridgeDescMgr<R, M> {
    fn bridges(&self) -> Arc<BridgeDescList> {
        self.mgr.lock_only().current.clone()
    }

    fn events(&self) -> BoxStream<'static, BridgeDescEvent> {
        let stream = self.mgr.lock_only().subscribers.subscribe();
        Box::pin(stream) as _
    }

    fn set_bridges(&self, new_bridges: &[BridgeConfig]) {
        /// Helper: Called for each bridge that is currently Tracked.
        ///
        /// Checks if `new_bridges` has `bridge`.  If so, removes it from `new_bridges`,
        /// and returns `true`, indicating that this bridge should be kept.
        ///
        /// If not, returns `false`, indicating that this bridge should be removed,
        /// and logs a message.
        fn note_found_keep_p(
            new_bridges: &mut HashSet<BridgeKey>,
            bridge: &BridgeKey,
            was_state: &str,
        ) -> bool {
            let keep = new_bridges.remove(bridge);
            if !keep {
                debug!(r#"forgetting bridge ({}) "{}""#, was_state, bridge);
            }
            keep
        }

        /// Helper: filters `*_schedule` so that it contains only things in `new_bridges`,
        /// removing them as we go.
        fn filter_schedule<TT: Ord + Copy, RD>(
            new_bridges: &mut HashSet<BridgeKey>,
            schedule: &mut BinaryHeap<RefetchEntry<TT, RD>>,
            was_state: &str,
        ) {
            schedule.retain_ext(|b| note_found_keep_p(new_bridges, &b.bridge, was_state));
        }

        let mut state = self.mgr.lock_then_process();
        let state = &mut **state;

        // We go through our own data structures, comparing them with `new_bridges`.
        // Entries in our own structures that aren't in `new_bridges` are removed.
        // Entries that *are* are removed from `new_bridges`.
        // Eventually `new_bridges` is just the list of new bridges to *add*.
        let mut new_bridges: HashSet<_> = new_bridges.iter().cloned().collect();

        // Is there anything in `current` that ought to be deleted?
        if state.current.keys().any(|b| !new_bridges.contains(b)) {
            // Found a bridge In `current` but not `new`
            // We need to remove it (and any others like it) from `current`.
            //
            // Disturbs the invariant *Schedules*:
            // After this maybe the schedules have entries they shouldn't.
            let current: BridgeDescList = state
                .current
                .iter()
                .filter(|(b, _)| new_bridges.contains(&**b))
                .map(|(b, v)| (b.clone(), v.clone()))
                .collect();
            state.set_current_and_notify(current);
        } else {
            // Nothing is being removed, so we can keep `current`.
        }
        // Bridges being newly requested will be added to `current`
        // later, after they have been fetched.

        // Is there anything in running we should abort?
        state.running.retain(|b, ri| {
            let keep = note_found_keep_p(&mut new_bridges, b, "was downloading");
            if !keep {
                ri.join.abort();
            }
            keep
        });

        // Is there anything in queued we should forget about?
        state
            .queued
            .retain(|qe| note_found_keep_p(&mut new_bridges, &qe.bridge, "was queued"));

        // Restore the invariant *Schedules*, that the schedules contain only things in current,
        // by removing the same things from the schedules that we earlier removed from current.
        filter_schedule(
            &mut new_bridges,
            &mut state.retry_schedule,
            "previously failed",
        );
        filter_schedule(
            &mut new_bridges,
            &mut state.refetch_schedule,
            "previously downloaded",
        );

        // OK now we have the list of bridges to add (if any).
        state.queued.extend(new_bridges.into_iter().map(|bridge| {
            debug!(r#" added bridge, queueing for download "{}""#, &bridge);
            QueuedEntry {
                bridge,
                retry_delay: None,
            }
        }));

        // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
        // to make further progress and restore the liveness properties.
    }
}

impl<R: Runtime, M: Mockable<R>> Manager<R, M> {
    /// Obtain a lock on state, for functions that want to disrupt liveness properties
    ///
    /// When `StateGuard` is dropped, the liveness properties will be restored
    /// by making whatever progress is required.
    ///
    /// See [`State`].
    fn lock_then_process<'s>(self: &'s Arc<Self>) -> StateGuard<'s, R, M> {
        StateGuard {
            state: self.lock_only(),
            mgr: self,
        }
    }

    /// Obtains the lock on state.
    ///
    /// Caller ought not to modify state
    /// so as to invalidate invariants or liveness properties.
    /// Callers which are part of the algorithms in this crate
    /// ought to consider [`lock_then_process`](Manager::lock_then_process) instead.
    fn lock_only(&self) -> MutexGuard<State> {
        self.state.lock().expect("bridge desc manager poisoned")
    }
}

/// Writeable reference to [`State`], entitling the holder to disrupt liveness properties.
///
/// The holder must still maintain the invariants.
///
/// Obtained from [`Manager::lock_then_process`].  See [`State`].
#[derive(Educe, Deref, DerefMut)]
#[educe(Debug)]
struct StateGuard<'s, R: Runtime, M: Mockable<R>> {
    /// Reference to the mutable state
    #[deref]
    #[deref_mut]
    state: MutexGuard<'s, State>,

    /// Reference to the outer container
    ///
    /// Allows the holder to obtain a `'static` (owned) handle `Arc<Manager>`,
    /// for use by spawned tasks.
    #[educe(Debug(ignore))]
    mgr: &'s Arc<Manager<R, M>>,
}

impl<R: Runtime, M: Mockable<R>> Drop for StateGuard<'_, R, M> {
    fn drop(&mut self) {
        self.state.process(self.mgr);
    }
}

impl State {
    /// Ensure progress is made, by restoring all the liveness invariants
    ///
    /// This includes launching circuits as needed.
    fn process<R: Runtime, M: Mockable<R>>(&mut self, mgr: &Arc<Manager<R, M>>) {
        // Restore liveness property *Running*
        self.consider_launching(mgr);

        let now_wall = mgr.runtime.wallclock();

        // Mitigate clock warping
        //
        // If the earliest `SystemTime` is more than `max_refetch` away,
        // the clock must have warped.  If that happens we clamp
        // them all to `max_refetch`.
        //
        // (This is not perfect but will mitigate the worst effects by ensuring
        // that we do *something* at least every `max_refetch`, in the worst case,
        // other than just getting completely stuck.)
        let max_refetch_wall = now_wall + self.config.max_refetch;
        if self
            .refetch_schedule
            .peek()
            .map(|re| re.when > max_refetch_wall)
            == Some(true)
        {
            info!("bridge descriptor manager: clock warped, clamping refetch times");
            self.refetch_schedule = self
                .refetch_schedule
                .drain()
                .map(|mut re| {
                    re.when = max_refetch_wall;
                    re
                })
                .collect();
        }

        // Restore liveness property *Timeout**
        // postage::watch will tell up the timeout task about the new wake-up time.
        let new_earliest_timeout = [
            // First retry.  These are std Instant.
            self.retry_schedule.peek().map(|re| re.when),
            // First refetch.  These are SystemTime, so we must convert them.
            self.refetch_schedule.peek().map(|re| {
                // If duration_since gives Err, that means when is before now,
                // ie we should not be waiting: the wait duration should be 0.
                let wait = re.when.duration_since(now_wall).unwrap_or_default();

                mgr.runtime.now() + wait
            }),
        ]
        .into_iter()
        .flatten()
        .min();
        *self.earliest_timeout.borrow_mut() = new_earliest_timeout;
    }

    /// Launch download attempts if we can
    ///
    /// Specifically: if we have things in `queued`, and `running` is shorter than
    /// `effective_parallelism()`, we launch task(s) to attempt download(s).
    ///
    /// Restores liveness invariant *Running*.
    ///
    /// Idempotent.  Forms part of `process`.
    #[allow(clippy::blocks_in_conditions)]
    fn consider_launching<R: Runtime, M: Mockable<R>>(&mut self, mgr: &Arc<Manager<R, M>>) {
        let mut to_remove = vec![];

        while self.running.len() < self.effective_parallelism() {
            let QueuedEntry {
                bridge,
                retry_delay,
            } = match self.queued.pop_front() {
                Some(qe) => qe,
                None => break,
            };
            match mgr
                .runtime
                .spawn({
                    let config = self.config.clone();
                    let bridge = bridge.clone();
                    let inner = mgr.clone();
                    let mockable = inner.mockable.clone();

                    // The task which actually downloads a descriptor.
                    async move {
                        let got =
                            AssertUnwindSafe(inner.download_descriptor(mockable, &bridge, &config))
                                .catch_unwind()
                                .await
                                .unwrap_or_else(|_| {
                                    Err(internal!("download descriptor task panicked!").into())
                                });
                        match &got {
                            Ok(_) => debug!(r#"download succeeded for "{}""#, bridge),
                            Err(err) => debug!(r#"download failed for "{}": {}"#, bridge, err),
                        };
                        let mut state = inner.lock_then_process();
                        state.record_download_outcome(bridge, got);
                        // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
                        // to make further progress and restore the liveness properties.
                    }
                })
                .map(|()| JoinHandle)
            {
                Ok(join) => {
                    self.running
                        .insert(bridge, RunningInfo { join, retry_delay });
                }
                Err(_) => {
                    // Spawn failed.
                    //
                    // We are going to forget about this bridge.
                    // And we're going to do that without notifying anyone.
                    // We *do* want to remove it from `current` because simply forgetting
                    // about a refetch could leave expired data there.
                    // We amortize this, so we don't do a lot of O(n^2) work on shutdown.
                    to_remove.push(bridge);
                }
            }
        }

        if !to_remove.is_empty() {
            self.modify_current(|current| {
                for bridge in to_remove {
                    current.remove(&bridge);
                }
            });
        }
    }

    /// Modify `current` and notify subscribers
    ///
    /// Helper function which modifies only `current`, not any of the rest of the state.
    /// it is the caller's responsibility to ensure that the invariants are upheld.
    ///
    /// The implementation actually involves cloning `current`,
    /// so it is best to amortize calls to this function.
    fn modify_current<T, F: FnOnce(&mut BridgeDescList) -> T>(&mut self, f: F) -> T {
        let mut current = (*self.current).clone();
        let r = f(&mut current);
        self.set_current_and_notify(current);
        r
    }

    /// Set `current` to a value and notify
    ///
    /// Helper function which modifies only `current`, not any of the rest of the state.
    /// it is the caller's responsibility to ensure that the invariants are upheld.
    fn set_current_and_notify<BDL: Into<Arc<BridgeDescList>>>(&mut self, new: BDL) {
        self.current = new.into();
        self.subscribers.publish(BridgeDescEvent::SomethingChanged);
    }

    /// Obtain the currently-desired level of parallelism
    ///
    /// Helper function.  The return value depends the mutable state and also the `config`.
    ///
    /// This is how we implement dormancy.
    fn effective_parallelism(&self) -> usize {
        match self.dormancy {
            Dormancy::Active => usize::from(u8::from(self.config.parallelism)),
            Dormancy::Dormant => 0,
        }
    }
}

impl<R: Runtime, M: Mockable<R>> StateGuard<'_, R, M> {
    /// Record a download outcome.
    ///
    /// Final act of the the descriptor download task.
    /// `got` is from [`download_descriptor`](Manager::download_descriptor).
    fn record_download_outcome(&mut self, bridge: BridgeKey, got: Result<Downloaded, Error>) {
        let RunningInfo { retry_delay, .. } = match self.running.remove(&bridge) {
            Some(ri) => ri,
            None => {
                debug!("bridge descriptor download completed for no-longer-configured bridge");
                return;
            }
        };

        let insert = match got {
            Ok(Downloaded { desc, refetch }) => {
                // Successful download.  Schedule the refetch, and we'll insert Ok.

                self.refetch_schedule.push(RefetchEntry {
                    when: refetch,
                    bridge: bridge.clone(),
                    retry_delay: (),
                });

                Ok(desc)
            }
            Err(err) => {
                // Failed.  Schedule the retry, and we'll insert Err.

                let mut retry_delay =
                    retry_delay.unwrap_or_else(|| RetryDelay::from_duration(self.config.retry));

                let retry = err.retry_time();
                // We retry at least as early as
                let now = self.mgr.runtime.now();
                let retry = retry.absolute(now, || retry_delay.next_delay(&mut rand::thread_rng()));
                // Retry at least as early as max_refetch.  That way if a bridge is
                // misconfigured we will see it be fixed eventually.
                let retry = {
                    let earliest = now;
                    let latest = || now + self.config.max_refetch;
                    match retry {
                        AbsRetryTime::Immediate => earliest,
                        AbsRetryTime::Never => latest(),
                        AbsRetryTime::At(i) => i.clamp(earliest, latest()),
                    }
                };
                self.retry_schedule.push(RefetchEntry {
                    when: retry,
                    bridge: bridge.clone(),
                    retry_delay,
                });

                Err(Box::new(err) as _)
            }
        };

        self.modify_current(|current| current.insert(bridge, insert));
    }
}

impl<R: Runtime, M: Mockable<R>> Manager<R, M> {
    /// Downloads a descriptor.
    ///
    /// The core of the descriptor download task
    /// launched by `State::consider_launching`.
    ///
    /// Uses Mockable::download to actually get the document.
    /// So most of this function is parsing and checking.
    ///
    /// The returned value is precisely the `got` input to
    /// [`record_download_outcome`](StateGuard::record_download_outcome).
    async fn download_descriptor(
        &self,
        mockable: M,
        bridge: &BridgeConfig,
        config: &BridgeDescDownloadConfig,
    ) -> Result<Downloaded, Error> {
        // convenience alias, capturing the usual parameters from our variables.
        let process_document = |text| process_document(&self.runtime, config, text);

        let store = || {
            self.store
                .lock()
                .map_err(|_| internal!("bridge descriptor store poisoned"))
        };

        let cache_entry: Option<CachedBridgeDescriptor> = (|| store()?.lookup_bridgedesc(bridge))()
            .unwrap_or_else(|err| {
                error_report!(
                    err,
                    r#"bridge descriptor cache lookup failed, for "{}""#,
                    sensitive(bridge),
                );
                None
            });

        let now = self.runtime.wallclock();
        let cached_good: Option<Downloaded> = if let Some(cached) = &cache_entry {
            if cached.fetched > now {
                // was fetched "in the future"
                None
            } else {
                // let's see if it's any use
                match process_document(&cached.document) {
                    Err(err) => {
                        // We had a doc in the cache but our attempt to use it failed
                        // We wouldn't have written a bad cache entry.
                        // So one of the following must be true:
                        //  * We were buggy or are stricter now or something
                        //  * The document was valid but its validity time has expired
                        // In any case we can't reuse it.
                        // (This happens in normal operation, when a document expires.)
                        trace!(r#"cached document for "{}" invalid: {}"#, &bridge, err);
                        None
                    }
                    Ok(got) => {
                        // The cached document looks valid.
                        // But how long ago did we fetch it?
                        // We need to enforce max_refresh even for still-valid documents.
                        if now.duration_since(cached.fetched).ok() <= Some(config.max_refetch) {
                            // Was fetched recently, too.  We can just reuse it.
                            return Ok(got);
                        }
                        Some(got)
                    }
                }
            }
        } else {
            None
        };

        // If cached_good is Some, we found a plausible cache entry; if we got here, it was
        // past its max_refresh.  So in that case we want to send a request with
        // if-modified-since.  If we get Not Modified, we can reuse it (and update the fetched time).
        let if_modified_since = cached_good
            .as_ref()
            .map(|got| got.desc.as_ref().published());

        debug!(
            r#"starting download for "{}"{}"#,
            bridge,
            match if_modified_since {
                Some(ims) => format!(
                    " if-modified-since {}",
                    humantime::format_rfc3339_seconds(ims),
                ),
                None => "".into(),
            }
        );

        let text = mockable
            .clone()
            .download(&self.runtime, &self.circmgr, bridge, if_modified_since)
            .await?;

        let (document, got) = if let Some(text) = text {
            let got = process_document(&text)?;
            (text, got)
        } else if let Some(cached) = cached_good {
            (
                cache_entry
                    .expect("cached_good but not cache_entry")
                    .document,
                cached,
            )
        } else {
            return Err(internal!("download gave None but no if-modified-since").into());
        };

        // IEFI catches cache store errors, which we log but don't do anything else with
        (|| {
            let cached = CachedBridgeDescriptor {
                document,
                fetched: now, // this is from before we started the fetch, which is correct
            };

            // Calculate when the cache should forget about this.
            // We want to add a bit of slop for the purposes of mild clock skew handling,
            // etc., and the prefetch time is a good proxy for that.
            let until = got
                .refetch
                .checked_add(config.prefetch)
                .unwrap_or(got.refetch /*uh*/);

            store()?.store_bridgedesc(bridge, cached, until)?;
            Ok(())
        })()
        .unwrap_or_else(|err: crate::Error| {
            error_report!(err, "failed to cache downloaded bridge descriptor",);
        });

        Ok(got)
    }
}

/// Processes and analyses a textual descriptor document into a `Downloaded`
///
/// Parses it, checks the signature, checks the document validity times,
/// and if that's all good, calculates when will want to refetch it.
fn process_document<R: Runtime>(
    runtime: &R,
    config: &BridgeDescDownloadConfig,
    text: &str,
) -> Result<Downloaded, Error> {
    let desc = RouterDesc::parse(text)?;

    // We *could* just trust this because we have trustworthy provenance
    // we know that the channel machinery authenticated the identity keys in `bridge`.
    // But let's do some cross-checking anyway.
    // `check_signature` checks the self-signature.
    let desc = desc.check_signature().map_err(Arc::new)?;

    let now = runtime.wallclock();
    desc.is_valid_at(&now)?;

    // Justification that use of "dangerously" is correct:
    // 1. We have checked this just above, so it is valid now.
    // 2. We are extracting the timeout and implement our own refetch logic using expires.
    let (desc, (_, expires)) = desc.dangerously_into_parts();

    // Our refetch schedule, and enforcement of descriptor expiry, is somewhat approximate.
    // The following situations can result in a nominally-expired descriptor being used:
    //
    // 1. We primarily enforce the timeout by looking at the expiry time,
    //    subtracting a configured constant, and scheduling the start of a refetch then.
    //    If it takes us longer to do the retry, than the prefetch constant,
    //    we'll still be providing the old descriptor to consumers in the meantime.
    //
    // 2. We apply a minimum time before we will refetch a descriptor.
    //    So if the validity time is unreasonably short, we'll use it beyond that time.
    //
    // 3. Clock warping could confuse this algorithm.  This is inevitable because we
    //    are relying on calendar times (SystemTime) in the descriptor, and because
    //    we don't have a mechanism for being told about clock warps rather than the
    //    passage of time.
    //
    // We think this is all OK given that a bridge descriptor is used for trying to
    // connect to the bridge itself.  In particular, we don't want to completely trust
    // bridges to control our retry logic.
    let refetch = match expires {
        ops::Bound::Included(expires) | ops::Bound::Excluded(expires) => expires
            .checked_sub(config.prefetch)
            .ok_or(Error::ExtremeValidityTime)?,

        ops::Bound::Unbounded => now
            .checked_add(config.max_refetch)
            .ok_or(Error::ExtremeValidityTime)?,
    };
    let refetch = refetch.clamp(now + config.min_refetch, now + config.max_refetch);

    let desc = BridgeDesc::new(Arc::new(desc));

    Ok(Downloaded { desc, refetch })
}

/// Task which waits for the timeout, and requeues bridges that need to be refetched
///
/// This task's job is to execute the wakeup instructions provided via `updates`.
///
/// `updates` is the receiving end of [`State`]'s `earliest_timeout`,
/// which is maintained to be the earliest time any of the schedules says we should wake up
/// (liveness property *Timeout*).
async fn timeout_task<R: Runtime, M: Mockable<R>>(
    runtime: R,
    inner: Weak<Manager<R, M>>,
    update: postage::watch::Receiver<Option<Instant>>,
) {
    /// Requeue things in `*_schedule` whose time for action has arrived
    ///
    /// `retry_delay_map` converts `retry_delay` from the schedule (`RetryDelay` or `()`)
    /// into the `Option` which appears in [`QueuedEntry`].
    ///
    /// Helper function.  Idempotent.
    fn requeue_as_required<TT: Ord + Copy + Debug, RD, RDM: Fn(RD) -> Option<RetryDelay>>(
        queued: &mut VecDeque<QueuedEntry>,
        schedule: &mut BinaryHeap<RefetchEntry<TT, RD>>,
        now: TT,
        retry_delay_map: RDM,
    ) {
        while let Some(ent) = schedule.peek() {
            if ent.when > now {
                break;
            }
            let re = schedule.pop().expect("schedule became empty!");
            let bridge = re.bridge;
            let retry_delay = retry_delay_map(re.retry_delay);

            queued.push_back(QueuedEntry {
                bridge,
                retry_delay,
            });
        }
    }

    let mut next_wakeup = Some(runtime.now());
    let mut update = update.fuse();
    loop {
        select! {
            // Someone modified the schedules, and sent us a new earliest timeout
            changed = update.next() => {
                // changed is Option<Option< >>.
                // The outer Option is from the Stream impl for watch::Receiver - None means EOF.
                // The inner Option is Some(wakeup_time), or None meaning "wait indefinitely"
                next_wakeup = if let Some(changed) = changed {
                    changed
                } else {
                    // Oh, actually, the watch::Receiver is EOF - we're to shut down
                    break
                }
            },

            // Wait until the specified earliest wakeup time
            () = async {
                if let Some(next_wakeup) = next_wakeup {
                    let now = runtime.now();
                    if next_wakeup > now {
                        let duration = next_wakeup - now;
                        runtime.sleep(duration).await;
                    }
                } else {
                    #[allow(clippy::semicolon_if_nothing_returned)] // rust-clippy/issues/9729
                    { future::pending().await }
                }
            }.fuse() => {
                // We have reached the pre-programmed time.  Check what needs doing.

                let inner = if let Some(i) = inner.upgrade() { i } else { break; };
                let mut state = inner.lock_then_process();
                let state = &mut **state; // Do the DerefMut once so we can borrow fields

                requeue_as_required(
                    &mut state.queued,
                    &mut state.refetch_schedule,
                    runtime.wallclock(),
                    |()| None,
                );

                requeue_as_required(
                    &mut state.queued,
                    &mut state.retry_schedule,
                    runtime.now(),
                    Some,
                );

                // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
                // to make further progress and restore the liveness properties.
            }
        }
    }
}

/// Error which occurs during bridge descriptor manager startup
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    /// No circuit manager in the directory manager
    #[error(
        "tried to create bridge descriptor manager from directory manager with no circuit manager"
    )]
    MissingCircMgr,

    /// Unable to spawn task
    //
    // TODO lots of our Errors have a variant exactly like this.
    // Maybe we should make a struct tor_error::SpawnError.
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use StartupError as SE;
        match self {
            SE::MissingCircMgr => EK::Internal,
            SE::Spawn { cause, .. } => cause.kind(),
        }
    }
}

/// An error which occurred trying to obtain the descriptor for a particular bridge
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Couldn't establish a circuit to the bridge
    #[error("Failed to establish circuit")]
    CircuitFailed(#[from] tor_circmgr::Error),

    /// Couldn't establish a directory stream to the bridge
    #[error("Failed to establish directory stream")]
    StreamFailed(#[source] tor_proto::Error),

    /// Directory request failed
    #[error("Directory request failed")]
    RequestFailed(#[from] tor_dirclient::RequestFailedError),

    /// Failed to parse descriptor in response
    #[error("Failed to parse descriptor in response")]
    ParseFailed(#[from] tor_netdoc::Error),

    /// Signature check failed
    #[error("Signature check failed")]
    SignatureCheckFailed(#[from] Arc<signature::Error>),

    /// Obtained descriptor but it is outside its validity time
    #[error("Descriptor is outside its validity time, as supplied")]
    BadValidityTime(#[from] tor_checkable::TimeValidityError),

    /// A bridge descriptor has very extreme validity times
    /// such that our refetch time calculations overflow.
    #[error("Descriptor validity time range is too extreme for us to cope with")]
    ExtremeValidityTime,

    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error")]
    Bug(#[from] tor_error::Bug),

    /// Error used for testing
    #[cfg(test)]
    #[error("Error for testing, {0:?}, retry at {1:?}")]
    TestError(&'static str, RetryTime),
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        let bridge_protocol_violation = EK::TorAccessFailed;
        match self {
            // We trust that tor_circmgr returns TorAccessFailed when it ought to.
            E::CircuitFailed(e) => e.kind(),
            E::StreamFailed(e) => e.kind(),
            E::RequestFailed(e) => e.kind(),
            E::ParseFailed(..) => bridge_protocol_violation,
            E::SignatureCheckFailed(..) => bridge_protocol_violation,
            E::ExtremeValidityTime => bridge_protocol_violation,
            E::BadValidityTime(..) => EK::ClockSkew,
            E::Bug(e) => e.kind(),
            #[cfg(test)]
            E::TestError(..) => EK::Internal,
        }
    }
}

impl HasRetryTime for Error {
    fn retry_time(&self) -> RetryTime {
        use Error as E;
        use RetryTime as R;
        match self {
            // Errors with their own retry times
            E::CircuitFailed(e) => e.retry_time(),

            // Remote misbehavior, maybe the network is being strange?
            E::StreamFailed(..) => R::AfterWaiting,
            E::RequestFailed(..) => R::AfterWaiting,

            // Remote misconfiguration, detected *after* we successfully made the channel
            // (so not a network problem).  We'll say "never" for RetryTime,
            // even though actually we will in fact retry in at most `max_refetch`.
            E::ParseFailed(..) => R::Never,
            E::SignatureCheckFailed(..) => R::Never,
            E::BadValidityTime(..) => R::Never,
            E::ExtremeValidityTime => R::Never,

            // Probably, things are broken here, rather than remotely.
            E::Bug(..) => R::Never,

            #[cfg(test)]
            E::TestError(_, retry) => *retry,
        }
    }
}

impl BridgeDescError for Error {}

impl State {
    /// Consistency check (for testing)
    ///
    /// `input` should be what was passed to `set_bridges` (or `None` if not known).
    ///
    /// Does not make any changes.
    /// Only takes `&mut` because postage::watch::Sender::borrow` wants it.
    #[cfg(test)]
    fn check_consistency<'i, R, I>(&mut self, runtime: &R, input: Option<I>)
    where
        R: Runtime,
        I: IntoIterator<Item = &'i BridgeKey>,
    {
        /// Where we found a thing was Tracked
        #[derive(Debug, Clone, Copy, Eq, PartialEq)]
        enum Where {
            /// Found in `running`
            Running,
            /// Found in `queued`
            Queued,
            /// Found in the schedule `sch`
            Schedule {
                sch_name: &'static str,
                /// Starts out as `false`, set to `true` when we find this in `current`
                found_in_current: bool,
            },
        }

        /// Records the expected input from `input`, and what we have found so far
        struct Tracked {
            /// Were we told what the last `set_bridges` call got as input?
            known_input: bool,
            /// `Some` means we have seen this bridge in one our records (other than `current`)
            tracked: HashMap<BridgeKey, Option<Where>>,
            /// Earliest instant found in any schedule
            earliest: Option<Instant>,
        }

        let mut tracked = if let Some(input) = input {
            let tracked = input.into_iter().map(|b| (b.clone(), None)).collect();
            Tracked {
                tracked,
                known_input: true,
                earliest: None,
            }
        } else {
            Tracked {
                tracked: HashMap::new(),
                known_input: false,
                earliest: None,
            }
        };

        impl Tracked {
            /// Note that `bridge` is Tracked
            fn note(&mut self, where_: Where, b: &BridgeKey) {
                match self.tracked.get(b) {
                    // Invariant *Tracked* - ie appears at most once
                    Some(Some(prev_where)) => {
                        panic!("duplicate {:?} {:?} {:?}", prev_where, where_, b);
                    }
                    // Invariant *Input (every tracked bridge is was in input)*
                    None if self.known_input => {
                        panic!("unexpected {:?} {:?}", where_, b);
                    }
                    // OK, we've not seen it before, note it as being here
                    _ => {
                        self.tracked.insert(b.clone(), Some(where_));
                    }
                }
            }
        }

        /// Walk `schedule` and update `tracked` (including `tracked.earliest`)
        ///
        /// Check invariant *Tracked* and *Schedule* wrt this schedule.
        #[cfg(test)]
        fn walk_sch<TT: Ord + Copy + Debug, RD, CT: Fn(TT) -> Instant>(
            tracked: &mut Tracked,
            sch_name: &'static str,
            schedule: &BinaryHeap<RefetchEntry<TT, RD>>,
            conv_time: CT,
        ) {
            let where_ = Where::Schedule {
                sch_name,
                found_in_current: false,
            };

            if let Some(first) = schedule.peek() {
                // Of course this is a heap, so this ought to be a wasteful scan,
                // but, indirectly,this tests our implementation of `Ord` for `RefetchEntry`.
                for re in schedule {
                    tracked.note(where_, &re.bridge);
                }

                let scanned = schedule
                    .iter()
                    .map(|re| re.when)
                    .min()
                    .expect("schedule empty!");
                assert_eq!(scanned, first.when);
                tracked.earliest = Some(
                    [tracked.earliest, Some(conv_time(scanned))]
                        .into_iter()
                        .flatten()
                        .min()
                        .expect("flatten of chain Some was empty"),
                );
            }
        }

        // *Timeout* (prep)
        //
        // This will fail if there is clock skew, but won't mind if
        // the earliest refetch time is in the past.
        let now_wall = runtime.wallclock();
        let now_mono = runtime.now();
        let adj_wall = |wallclock: SystemTime| {
            // Good grief what a palaver!
            if let Ok(ahead) = wallclock.duration_since(now_wall) {
                now_mono + ahead
            } else if let Ok(behind) = now_wall.duration_since(wallclock) {
                now_mono
                    .checked_sub(behind)
                    .expect("time subtraction underflow")
            } else {
                panic!("times should be totally ordered!")
            }
        };

        // *Tracked*
        //
        // We walk our data structures in turn

        for b in self.running.keys() {
            tracked.note(Where::Running, b);
        }
        for qe in &self.queued {
            tracked.note(Where::Queued, &qe.bridge);
        }

        walk_sch(&mut tracked, "refetch", &self.refetch_schedule, adj_wall);
        walk_sch(&mut tracked, "retry", &self.retry_schedule, |t| t);

        // *Current*
        for b in self.current.keys() {
            let found = tracked
                .tracked
                .get_mut(b)
                .and_then(Option::as_mut)
                .unwrap_or_else(|| panic!("current but untracked {:?}", b));
            if let Where::Schedule {
                found_in_current, ..
            } = found
            {
                *found_in_current = true;
            }
        }

        // *Input (sense: every input bridge is tracked)*
        //
        // (Will not cope if spawn ever failed, since that violates the invariant.)
        for (b, where_) in &tracked.tracked {
            match where_ {
                None => panic!("missing {}", &b),
                Some(Where::Schedule {
                    sch_name,
                    found_in_current,
                }) => {
                    assert!(found_in_current, "not-Schedule {} {}", &b, sch_name);
                }
                _ => {}
            }
        }

        // *Limit*
        let parallelism = self.effective_parallelism();
        assert!(self.running.len() <= parallelism);

        // *Running*
        assert!(self.running.len() == parallelism || self.queued.is_empty());

        // *Timeout* (final)
        assert_eq!(tracked.earliest, *self.earliest_timeout.borrow());
    }
}
