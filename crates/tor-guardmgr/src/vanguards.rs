//! Experimental support for vanguards.
//!
//! For more information, see the [vanguards spec].
//!
//! [vanguards spec]: https://spec.torproject.org/vanguards-spec/index.html.

pub mod config;
mod set;

use std::collections::BinaryHeap;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime};

use futures::task::{SpawnError, SpawnExt as _};
use futures::{future, FutureExt as _};
use futures::{select_biased, StreamExt as _};
use rand::RngCore;

use tor_basic_utils::RngExt as _;
use tor_config::ReconfigureError;
use tor_error::{error_report, internal, into_internal, ErrorKind, HasKind};
use tor_linkspec::{RelayIdSet, RelayIds};
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness};
use tor_persist::StateMgr;
use tor_relay_selection::{RelayExclusion, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;
use tracing::{debug, trace};

use crate::{RetireCircuits, VanguardMode};

use set::{TimeBoundVanguard, VanguardSet};

pub use config::{VanguardConfig, VanguardConfigBuilder, VanguardParams};
pub use set::Vanguard;

/// The vanguard manager.
#[allow(unused)] // TODO HS-VANGUARDS
pub struct VanguardMgr<R: Runtime> {
    /// The mutable state.
    inner: RwLock<Inner>,
    /// The runtime.
    runtime: R,
}

/// The mutable inner state of [`VanguardMgr`].
#[allow(unused)] // TODO HS-VANGUARDS
struct Inner {
    /// Whether to use full, lite, or no vanguards.
    mode: VanguardMode,
    /// Configuration parameters read from the consensus parameters.
    params: VanguardParams,
    /// The L2 vanguards.
    ///
    /// This is a view of the L2 vanguards from the `vanguards` heap.
    l2_vanguards: VanguardSet,
    /// The L3 vanguards.
    ///
    /// This is a view of the L3 vanguards from the `vanguards` heap.
    ///
    /// The L3 vanguards are only used if we are running in
    /// [`Full`](VanguardMode::Full) vanguard mode.
    /// Otherwise, this set is not populated, or read from.
    l3_vanguards: VanguardSet,
    /// A binary heap with all our vanguards.
    /// It contains both the `l2_vanguards` and the `l3_vanguards`.
    ///
    /// Storing the vanguards in a min-heap is convenient
    /// because we need to periodically remove the expired vanguards,
    /// and determine which vanguard will expire next.
    ///
    /// Removing a vanguard from the heap causes it to expire and to be removed
    /// from its corresponding [`VanguardSet`].
    vanguards: BinaryHeap<Arc<TimeBoundVanguard>>,
    /// The most up-to-date netdir we have.
    ///
    /// This starts out as `None` and is initialized and kept up to date
    /// by the [`VanguardMgr::maintain_vanguard_sets`] task.
    netdir: Option<Arc<NetDir>>,
}

/// Whether the [`VanguardMgr::maintain_vanguard_sets`] task
/// should continue running or shut down.
///
/// Returned from [`VanguardMgr::run_once`].
#[derive(Copy, Clone, Debug)]
enum ShutdownStatus {
    /// Continue calling `run_once`.
    Continue,
    /// The `VanguardMgr` was dropped, terminate the task.
    Terminate,
}

/// An error coming from the vanguards subsystem.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VanguardMgrError {
    /// Could not find a suitable relay to use for the specifier layer.
    #[error("No suitable relays")]
    NoSuitableRelay(Layer),

    /// Could not get timely network directory.
    #[error("Unable to get timely network directory")]
    NetDir(#[from] tor_netdir::Error),

    /// Could not spawn a task.
    #[error("Unable to spawn a task")]
    Spawn(#[source] Arc<SpawnError>),

    /// An internal error occurred.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for VanguardMgrError {
    fn kind(&self) -> ErrorKind {
        match self {
            // TODO HS-VANGUARDS: this is not right
            VanguardMgrError::NoSuitableRelay(_) => ErrorKind::Other,
            VanguardMgrError::NetDir(e) => e.kind(),
            VanguardMgrError::Spawn(e) => e.kind(),
            VanguardMgrError::Bug(e) => e.kind(),
        }
    }
}

impl<R: Runtime> VanguardMgr<R> {
    /// Create a new `VanguardMgr`.
    ///
    /// The `state_mgr` handle is used for persisting the "vanguards-full" guard pools to disk.
    #[allow(clippy::needless_pass_by_value)] // TODO HS-VANGUARDS
    pub fn new<S>(
        config: &VanguardConfig,
        runtime: R,
        _state_mgr: S,
    ) -> Result<Self, VanguardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        let VanguardConfig { mode } = config;
        // Note: we start out with default vanguard params, but we adjust them
        // as soon as we obtain a NetDir (see Self::run_once()).
        let params = VanguardParams::default();
        let l2_vanguards = VanguardSet::new(params.l2_pool_size());
        let l3_vanguards = VanguardSet::new(params.l3_pool_size());
        let vanguards = BinaryHeap::new();

        let inner = Inner {
            mode: *mode,
            // TODO HS-VANGUARDS: read the params from the consensus
            params,
            l2_vanguards,
            l3_vanguards,
            vanguards,
            netdir: None,
        };

        // TODO HS-VANGUARDS: read the vanguards from disk if mode == VanguardsMode::Full
        Ok(Self {
            inner: RwLock::new(inner),
            runtime,
        })
    }

    /// Launch the vanguard pool management tasks.
    ///
    /// This spawns [`VanguardMgr::maintain_vanguard_sets`]
    /// which runs until the `VanguardMgr` is dropped.
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        netdir_provider: &Arc<dyn NetDirProvider>,
    ) -> Result<(), VanguardMgrError>
    where
        R: Runtime,
    {
        let netdir_provider = Arc::clone(netdir_provider);
        self.runtime
            .spawn(Self::maintain_vanguard_sets(
                Arc::downgrade(self),
                netdir_provider,
            ))
            .map_err(|e| VanguardMgrError::Spawn(Arc::new(e)))?;

        Ok(())
    }

    /// Replace the configuration in this `VanguardMgr` with the specified `config`.
    pub fn reconfigure(&self, config: &VanguardConfig) -> Result<RetireCircuits, ReconfigureError> {
        let VanguardConfig { mode } = config;

        let mut inner = self.inner.write().expect("poisoned lock");
        if *mode != inner.mode {
            inner.mode = *mode;
            return Ok(RetireCircuits::All);
        }

        Ok(RetireCircuits::None)
    }

    /// Return a [`Vanguard`] relay for use in the specified layer.
    ///
    /// The `neighbor_exclusion` must contain the relays that would neighbor this vanguard
    /// in the path.
    ///
    /// Specifically, it should contain
    ///   * the last relay in the path (the one immediately preceding the vanguard): the same relay
    ///     cannot be used in consecutive positions in the path (a relay won't let you extend the
    ///     circuit to itself).
    ///   * the penultimate relay of the path, if there is one: relays don't allow extending the
    ///     circuit to their previous hop
    ///
    /// If [`Full`](VanguardMode::Full) vanguards are in use, this function can be used
    /// for selecting both [`Layer2`](Layer::Layer2) and [`Layer3`](Layer::Layer3) vanguards.
    ///
    /// If [`Lite`](VanguardMode::Lite) vanguards are in use, this function can only be used
    /// for selecting [`Layer2`](Layer::Layer2) vanguards.
    /// It will return an error if a [`Layer3`](Layer::Layer3) is requested.
    ///
    /// Returns an error is vanguards are disabled.
    ///
    ///  ### Example
    ///
    ///  If the partially built path is of the form `G - L2` and we are selecting the L3 vanguard,
    ///  the `RelayExclusion` should contain `G` and `L2` (to prevent building a path of the form
    ///  `G - L2 - G`, or `G - L2 - L2`).
    ///
    ///  If the path only contains the L1 guard (`G`), then the `RelayExclusion` should only
    ///  exclude `G`.
    pub fn select_vanguard<'a, Rng: RngCore>(
        &self,
        rng: &mut Rng,
        netdir: &'a NetDir,
        layer: Layer,
        neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Result<Vanguard<'a>, VanguardMgrError> {
        use VanguardMode::*;

        let mut inner = self.inner.write().expect("poisoned lock");

        // TODO HS-VANGUARDS: code smell.
        //
        // If select_vanguards() is called before maintain_vanguard_sets() has obtained a netdir
        // and populated the vanguard sets, this will return a NoSuitableRelay error (because all
        // our vanguard sets are empty).
        //
        // However, in practice, I don't think this can ever happen, because we don't attempt to
        // build paths until we're done bootstrapping.
        //
        // If it turns out this can actually happen in practice, we can work around it by calling
        // inner.replenish_vanguards(&self.runtime, netdir)? here (using the netdir arg rather than
        // the one we obtained ourselves), but at that point we might as well abolish the
        // maintain_vanguard_sets task and do everything synchronously in this function...

        // TODO HS-VANGUARDS: come up with something with better UX
        let vanguard_set = match (layer, inner.mode) {
            (Layer::Layer2, Full) | (Layer::Layer2, Lite) => &mut inner.l2_vanguards,
            (Layer::Layer3, Full) => &mut inner.l3_vanguards,
            // TODO HS-VANGUARDS: perhaps we need a dedicated error variant for this
            _ => {
                return Err(internal!(
                    "vanguards for layer {layer} are supported in mode {})",
                    inner.mode
                )
                .into())
            }
        };

        vanguard_set
            .pick_relay(rng, netdir, neighbor_exclusion)
            .ok_or(VanguardMgrError::NoSuitableRelay(layer))
    }

    /// The vanguard set management task.
    ///
    /// This is a background task that:
    /// * removes vanguards from the `vanguards` heap when they expire
    /// * ensures the [`VanguardSet`]s are repopulated with new vanguards
    ///   when the number of vanguards drops below a certain threshold
    /// * handles `NetDir` changes, updating the vanguard set sizes as needed
    async fn maintain_vanguard_sets(mgr: Weak<Self>, netdir_provider: Arc<dyn NetDirProvider>) {
        loop {
            match Self::run_once(Weak::clone(&mgr), Arc::clone(&netdir_provider)).await {
                Ok(ShutdownStatus::Continue) => continue,
                Ok(ShutdownStatus::Terminate) => {
                    debug!("Vanguard manager is shutting down");
                    break;
                }
                Err(e) => {
                    error_report!(e, "Vanguard manager crashed");
                    break;
                }
            }
        }
    }

    /// Wait until a vanguard expires or until there is a new [`NetDir`].
    ///
    /// This keeps `inner`'s `NetDir` up to date, removes any expired vanguards from the heap,
    /// and replenishes the heap and `VanguardSet`s with new vanguards.
    async fn run_once(
        mgr: Weak<Self>,
        netdir_provider: Arc<dyn NetDirProvider>,
    ) -> Result<ShutdownStatus, VanguardMgrError> {
        let mut netdir_events = netdir_provider.events().fuse();
        let Some(mgr) = mgr.upgrade() else {
            return Ok(ShutdownStatus::Terminate);
        };

        let now = mgr.runtime.wallclock();
        let next_to_expire = mgr.remove_expired(now)?;
        // A future that sleeps until the next vanguard expires
        let sleep_fut = async {
            if let Some(dur) = next_to_expire {
                let () = mgr.runtime.sleep(dur).await;
            } else {
                future::pending::<()>().await;
            }
        };

        // If we have a NetDir, replenish the vanguard sets that don't have enough vanguards.
        mgr.inner
            .write()
            .expect("poisoned lock")
            .try_replenish_vanguards(&mgr.runtime)?;

        select_biased! {
            event = netdir_events.next() => {
                if let Some(DirEvent::NewConsensus) = event {
                    let netdir = netdir_provider.netdir(Timeliness::Timely)?;
                    mgr.inner.write().expect("poisoned lock")
                        .handle_netdir_update(&mgr.runtime, &netdir)?;
                }

                Ok(ShutdownStatus::Continue)
            },
            () = sleep_fut.fuse() => {
                // A vanguard expired, time to run the cleanup
                Ok(ShutdownStatus::Continue)
            },
        }
    }

    /// Remove any expired vanguards from the heap,
    /// returning how long until the next vanguard will expire,
    /// or `None` if the heap is empty.
    ///
    /// The `vanguards` heap contains the only strong references to the vanguards,
    /// so removing them causes the weak references from the VanguardSets to become
    /// dangling (the dangling references are lazily removed).
    fn remove_expired(&self, now: SystemTime) -> Result<Option<Duration>, VanguardMgrError> {
        let mut inner = self.inner.write().expect("poisoned lock");
        let inner = &mut *inner;

        while let Some(vanguard) = inner.vanguards.peek() {
            if now >= vanguard.when {
                inner.vanguards.pop();
            } else {
                let duration = vanguard
                    .when
                    .duration_since(now)
                    .map_err(|_| internal!("when > now, but now is later than when?!"))?;

                return Ok(Some(duration));
            }
        }

        // The heap is empty
        Ok(None)
    }

    /// Get the current [`VanguardMode`].
    pub fn mode(&self) -> VanguardMode {
        self.inner.read().expect("poisoned lock").mode
    }

    /// Flush the vanguard sets to storage, if the mode is "vanguards-full".
    #[allow(unused)] // TODO HS-VANGUARDS
    fn flush_to_storage(&self) -> Result<(), VanguardMgrError> {
        let mode = self.inner.read().expect("poisoned lock").mode;
        match mode {
            VanguardMode::Lite | VanguardMode::Disabled => Ok(()),
            VanguardMode::Full => todo!(),
        }
    }
}

impl Inner {
    /// If we have a `NetDir`, replenish the vanguard sets if needed.
    fn try_replenish_vanguards<R: Runtime>(&mut self, runtime: &R) -> Result<(), VanguardMgrError> {
        match &self.netdir {
            Some(netdir) => {
                // Clone the netdir to appease the borrow checker
                // (otherwsise we end up borrowing self both as immutable and as mutable)
                let netdir = Arc::clone(netdir);
                self.replenish_vanguards(runtime, &netdir)?;
            }
            None => {
                trace!("unable to replenish vanguard sets (netdir unavailable)");
            }
        }

        Ok(())
    }

    /// Handle potential vanguard parameter changes.
    ///
    /// This sets our most up-to-date `NetDir` to `netdir`,
    /// and updates the [`VanguardSet`]s based on the [`VanguardParams`]
    /// derived from the new `NetDir`.
    ///
    /// NOTE: if the new `VanguardParams` specify different lifetime ranges
    /// than the previous `VanguardParams`, the new lifetime requirements only
    /// apply to newly selected vanguards. They are **not** retroactively applied
    /// to our existing vanguards.
    //
    // TODO(#1352): we might want to revisit this decision.
    // We could, for example, adjust the lifetime of our existing vanguards
    // to comply with the new lifetime requirements.
    fn handle_netdir_update<R: Runtime>(
        &mut self,
        runtime: &R,
        netdir: &Arc<NetDir>,
    ) -> Result<(), VanguardMgrError> {
        self.netdir = Some(Arc::clone(netdir));
        self.remove_unlisted(netdir);
        self.replenish_vanguards(runtime, netdir)?;

        Ok(())
    }

    /// Remove the vanguards that are no longer listed in `netdir`
    fn remove_unlisted(&mut self, netdir: &Arc<NetDir>) {
        self.vanguards
            .retain(|v| netdir.ids_listed(&v.id) != Some(false));
    }

    /// Replenish the vanguard sets if necessary, using the directory information
    /// from the specified [`NetDir`].
    fn replenish_vanguards<R: Runtime>(
        &mut self,
        runtime: &R,
        netdir: &NetDir,
    ) -> Result<(), VanguardMgrError> {
        trace!("replenishing vanguard sets");

        let params = VanguardParams::try_from(netdir.params())
            .map_err(into_internal!("invalid NetParameters"))?;

        // Resize the vanguard sets if necessary.
        self.l2_vanguards.update_target(params.l2_pool_size());

        // TODO HS-VANGUARDS: It would be nice to make this mockable. It will involve adding an
        // M: MocksForVanguards parameter to VanguardMgr, which will have to propagated throughout
        // tor-circmgr too.
        let mut rng = rand::thread_rng();
        Self::replenish_set(
            runtime,
            &mut rng,
            netdir,
            &mut self.l2_vanguards,
            &mut self.vanguards,
            params.l2_lifetime_min(),
            params.l2_lifetime_max(),
        )?;

        if self.mode == VanguardMode::Full {
            self.l3_vanguards.update_target(params.l3_pool_size());
            Self::replenish_set(
                runtime,
                &mut rng,
                netdir,
                &mut self.l3_vanguards,
                &mut self.vanguards,
                params.l3_lifetime_min(),
                params.l3_lifetime_max(),
            )?;
        }

        Ok(())
    }

    /// Replenish a single `VanguardSet` with however many vanguards it is short of.
    fn replenish_set<R: Runtime, Rng: RngCore>(
        runtime: &R,
        rng: &mut Rng,
        netdir: &NetDir,
        vanguard_set: &mut VanguardSet,
        vanguards: &mut BinaryHeap<Arc<TimeBoundVanguard>>,
        min_lifetime: Duration,
        max_lifetime: Duration,
    ) -> Result<(), VanguardMgrError> {
        let deficit = vanguard_set.deficit();
        if deficit > 0 {
            // Exclude the relays that are already in this vanguard set.
            let exclude_ids = RelayIdSet::from(&*vanguard_set);
            let exclude = RelayExclusion::exclude_identities(exclude_ids);
            // Pick some vanguards to add to the heap.
            let new_vanguards = Self::add_n_vanguards(
                runtime,
                rng,
                netdir,
                deficit,
                exclude,
                min_lifetime,
                max_lifetime,
            )?;
            // The VanguardSet is populated with weak references
            // to the vanguards we add to the heap.
            for v in new_vanguards {
                vanguard_set.add_vanguard(Arc::downgrade(&v));
                vanguards.push(v);
            }
        }

        Ok(())
    }

    /// Select `n` relays to use as vanguards.
    ///
    /// Each selected vanguard will have a random lifetime
    /// between `min_lifetime` and `max_lifetime`.
    fn add_n_vanguards<R: Runtime, Rng: RngCore>(
        runtime: &R,
        rng: &mut Rng,
        netdir: &NetDir,
        n: usize,
        exclude: RelayExclusion,
        min_lifetime: Duration,
        max_lifetime: Duration,
    ) -> Result<Vec<Arc<TimeBoundVanguard>>, VanguardMgrError> {
        trace!(relay_count = n, "selecting relays to use as vanguards");

        // TODO(#1364): use RelayUsage::vanguard instead
        let vanguard_sel = RelaySelector::new(RelayUsage::middle_relay(None), exclude);

        let (relays, _outcome) = vanguard_sel.select_n_relays(rng, n, netdir);

        relays
            .into_iter()
            .map(|relay| {
                // Pick an expiration for this vanguard.
                let duration = select_lifetime(rng, min_lifetime, max_lifetime)?;
                let when = runtime.wallclock() + duration;

                Ok(Arc::new(TimeBoundVanguard {
                    id: RelayIds::from_relay_ids(&relay),
                    when,
                }))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Randomly select the lifetime of a vanguard from the `max(X,X)` distribution,
/// where `X` is a uniform random value between `min_lifetime` and `max_lifetime`.
///
/// This ensures we are biased towards longer lifetimes.
///
/// See
/// <https://spec.torproject.org/vanguards-spec/vanguards-stats.html>
//
// TODO(#1352): we may not want the same bias for the L2 vanguards
fn select_lifetime<Rng: RngCore>(
    rng: &mut Rng,
    min_lifetime: Duration,
    max_lifetime: Duration,
) -> Result<Duration, VanguardMgrError> {
    let err = || internal!("invalid consensus: vanguard min_lifetime > max_lifetime");

    let l1 = rng
        .gen_range_checked(min_lifetime..=max_lifetime)
        .ok_or_else(err)?;

    let l2 = rng
        .gen_range_checked(min_lifetime..=max_lifetime)
        .ok_or_else(err)?;

    Ok(std::cmp::max(l1, l2))
}

/// The vanguard layer.
#[allow(unused)] // TODO HS-VANGUARDS
#[derive(Debug, Clone, Copy, PartialEq)] //
#[derive(derive_more::Display)] //
#[non_exhaustive]
pub enum Layer {
    /// L2 vanguard.
    #[display(fmt = "layer 2")]
    Layer2,
    /// L3 vanguard.
    #[display(fmt = "layer 3")]
    Layer3,
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

    use std::fmt;

    use super::*;

    use tor_basic_utils::test_rng::testing_rng;
    use tor_linkspec::HasRelayIds;
    use tor_netdir::{testnet, testprovider::TestNetDirProvider};
    use tor_persist::TestingStateMgr;
    use tor_rtmock::MockRuntime;
    use Layer::*;

    use itertools::Itertools;

    impl fmt::Debug for Vanguard<'_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Vanguard").finish()
        }
    }

    /// Create a new VanguardMgr for testing.
    fn new_vanguard_mgr<R: Runtime>(rt: &R) -> Arc<VanguardMgr<R>> {
        let config = Default::default();
        let statemgr = TestingStateMgr::new();
        Arc::new(VanguardMgr::new(&config, rt.clone(), statemgr).unwrap())
    }

    /// Look up the vanguard in the VanguardMgr heap.
    fn find_in_heap<R: Runtime>(
        vanguard: &Vanguard<'_>,
        mgr: &VanguardMgr<R>,
    ) -> Option<Weak<TimeBoundVanguard>> {
        let inner = mgr.inner.read().unwrap();
        inner
            .vanguards
            .iter()
            .find(|v| {
                let relay_ids = RelayIds::from_relay_ids(vanguard.relay());
                v.id == relay_ids
            })
            .map(Arc::downgrade)
    }

    /// Look up the vanguard in the specified VanguardSet.
    fn find_in_set<R: Runtime>(
        vanguard: &Vanguard<'_>,
        mgr: &VanguardMgr<R>,
        layer: Layer,
    ) -> Option<Weak<TimeBoundVanguard>> {
        let inner = mgr.inner.read().unwrap();

        let vanguard_set = match layer {
            Layer2 => &inner.l2_vanguards,
            Layer3 => &inner.l3_vanguards,
        };

        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        let relay_ids = RelayIds::from_relay_ids(vanguard.relay());
        vanguard_set
            .vanguards()
            .iter()
            .find(|v| v.upgrade().map(|v| v.id == relay_ids).unwrap_or_default())
            .cloned()
    }

    /// Get the total number of vanguard entries (L2 + L3).
    fn vanguard_count<R: Runtime>(mgr: &VanguardMgr<R>) -> usize {
        let inner = mgr.inner.read().unwrap();
        inner.vanguards.len()
    }

    /// Return a `Duration` representing how long until this vanguard expires.
    fn duration_until_expiry<R: Runtime>(
        vanguard: &Vanguard<'_>,
        mgr: &VanguardMgr<R>,
        runtime: &R,
        layer: Layer,
    ) -> Duration {
        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        let vanguard = find_in_set(vanguard, mgr, layer)
            .unwrap()
            .upgrade()
            .unwrap();

        vanguard
            .when
            .duration_since(runtime.wallclock())
            .unwrap_or_default()
    }

    /// Assert the lifetime of the specified `vanguard` is within the bounds of its `layer`.
    fn assert_expiry_in_bounds<R: Runtime>(
        vanguard: &Vanguard<'_>,
        mgr: &VanguardMgr<R>,
        runtime: &R,
        params: &VanguardParams,
        layer: Layer,
    ) {
        let (min, max) = match layer {
            Layer2 => (params.l2_lifetime_min(), params.l2_lifetime_max()),
            Layer3 => (params.l3_lifetime_min(), params.l3_lifetime_max()),
        };

        // This is not exactly the lifetime of the vanguard,
        // but rather the time left until it expires (but it's close enough for our purposes).
        let lifetime = duration_until_expiry(vanguard, mgr, runtime, layer);

        assert!(
            lifetime >= min && lifetime <= max,
            "lifetime {lifetime:?} not between {min:?} and {max:?}",
        );
    }

    /// Assert that the vanguard manager's pools are empty.
    fn assert_sets_empty<R: Runtime>(vanguardmgr: &VanguardMgr<R>, params: &VanguardParams) {
        let inner = vanguardmgr.inner.read().unwrap();
        // The sets are initially empty
        assert_eq!(inner.l2_vanguards.deficit(), params.l2_pool_size());
        assert_eq!(inner.l3_vanguards.deficit(), params.l3_pool_size());
        assert_eq!(vanguard_count(vanguardmgr), 0);
    }

    /// Assert that the vanguard manager's pools have been filled.
    fn assert_sets_filled<R: Runtime>(vanguardmgr: &VanguardMgr<R>, params: &VanguardParams) {
        let inner = vanguardmgr.inner.read().unwrap();
        let l2_pool_size = params.l2_pool_size();
        // The sets are initially empty
        assert_eq!(inner.l2_vanguards.deficit(), 0);

        if inner.mode == VanguardMode::Full {
            assert_eq!(inner.l3_vanguards.deficit(), 0);
            let l3_pool_size = params.l3_pool_size();
            assert_eq!(vanguard_count(vanguardmgr), l2_pool_size + l3_pool_size);
        }
    }

    /// Assert the target size of the specified vanguard set matches the target from `params`.
    fn assert_set_targets_match_params<R: Runtime>(mgr: &VanguardMgr<R>, params: &VanguardParams) {
        let inner = mgr.inner.read().unwrap();
        assert_eq!(inner.l2_vanguards.target(), params.l2_pool_size());
        if inner.mode == VanguardMode::Full {
            assert_eq!(inner.l3_vanguards.target(), params.l3_pool_size());
        }
    }

    /// Wait until the vanguardmgr has populated its vanguard sets.
    async fn init_vanguard_sets(
        runtime: MockRuntime,
        netdir: NetDir,
        vanguardmgr: Arc<VanguardMgr<MockRuntime>>,
    ) -> Arc<TestNetDirProvider> {
        let netdir_provider = Arc::new(TestNetDirProvider::new());
        vanguardmgr
            .launch_background_tasks(&(netdir_provider.clone() as Arc<dyn NetDirProvider>))
            .unwrap();
        runtime.progress_until_stalled().await;

        // Call set_netdir_and_notify to trigger an event
        netdir_provider
            .set_netdir_and_notify(Arc::new(netdir.clone()))
            .await;

        // Wait until the vanguard mgr has finished handling the netdir event.
        runtime.progress_until_stalled().await;

        netdir_provider
    }

    #[test]
    fn full_vanguards_disabled() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = new_vanguard_mgr(&rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();
            let exclusion = RelayExclusion::no_relays_excluded();

            // Cannot select an L3 vanguard when running in "Lite" mode.
            let err = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer3, &exclusion)
                .unwrap_err();
            assert!(matches!(err, VanguardMgrError::Bug(_)), "{err:?}");
        });
    }

    #[test]
    fn background_task_not_spawned() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = new_vanguard_mgr(&rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let mut rng = testing_rng();
            let exclusion = RelayExclusion::no_relays_excluded();

            // The sets are initially empty
            assert_sets_empty(&vanguardmgr, &params);

            // VanguardMgr::launch_background tasks was not called, so select_vanguard will return
            // an error (because the vanguard sets are empty)
            let err = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &exclusion)
                .unwrap_err();

            assert!(
                matches!(err, VanguardMgrError::NoSuitableRelay(Layer2)),
                "{err:?}"
            );
        });
    }

    #[test]
    fn select_vanguards() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = new_vanguard_mgr(&rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let mut rng = testing_rng();
            let exclusion = RelayExclusion::no_relays_excluded();

            // The sets are initially empty
            assert_sets_empty(&vanguardmgr, &params);

            // Wait until the vanguard manager has bootstrapped
            let _netdir_provider =
                init_vanguard_sets(rt.clone(), netdir.clone(), Arc::clone(&vanguardmgr)).await;

            assert_sets_filled(&vanguardmgr, &params);

            let vanguard1 = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &exclusion)
                .unwrap();
            assert_expiry_in_bounds(&vanguard1, &vanguardmgr, &rt, &params, Layer2);

            let exclusion = RelayExclusion::exclude_identities(
                vanguard1
                    .relay()
                    .identities()
                    .map(|id| id.to_owned())
                    .collect(),
            );

            // TODO HS-VANGUARDS: use Layer3 once full vanguard support is implemented.
            let vanguard2 = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &exclusion)
                .unwrap();

            assert_expiry_in_bounds(&vanguard2, &vanguardmgr, &rt, &params, Layer2);
            // Ensure we didn't select the same vanguard twice
            assert_ne!(
                vanguard1.relay().identities().collect_vec(),
                vanguard2.relay().identities().collect_vec()
            );
        });
    }

    /// Override the vanguard params from the netdir, returning the new VanguardParams.
    ///
    /// This also waits until the vanguard manager has had a chance to process the changes.
    async fn install_new_params(
        rt: &MockRuntime,
        netdir_provider: &TestNetDirProvider,
        params: impl IntoIterator<Item = (&str, i32)>,
    ) -> VanguardParams {
        let new_netdir = testnet::construct_custom_netdir_with_params(|_, _| {}, params, None)
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let new_params = VanguardParams::try_from(new_netdir.params()).unwrap();

        netdir_provider.set_netdir_and_notify(new_netdir).await;

        // Wait until the vanguard mgr has finished handling the new netdir.
        rt.progress_until_stalled().await;

        new_params
    }

    #[test]
    fn override_vanguard_set_size() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = new_vanguard_mgr(&rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            // Wait until the vanguard manager has bootstrapped
            let netdir_provider =
                init_vanguard_sets(rt.clone(), netdir.clone(), Arc::clone(&vanguardmgr)).await;

            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let old_size = params.l2_pool_size();
            assert_set_targets_match_params(&vanguardmgr, &params);

            const PARAMS: [[(&str, i32); 2]; 2] = [
                [("guard-hs-l2-number", 1), ("guard-hs-l3-number", 10)],
                [("guard-hs-l2-number", 10), ("guard-hs-l3-number", 10)],
            ];

            for params in PARAMS {
                let new_params = install_new_params(&rt, &netdir_provider, params).await;

                // Ensure the target size was updated.
                assert_set_targets_match_params(&vanguardmgr, &new_params);
                {
                    let inner = vanguardmgr.inner.read().unwrap();
                    let l2_vanguards = inner.l2_vanguards.vanguards();
                    let l3_vanguards = inner.l3_vanguards.vanguards();
                    let new_l2_size = params[0].1 as usize;
                    if new_l2_size < old_size {
                        // The actual size of the set hasn't changed: it's OK to have more vanguards than
                        // needed in the set (they extraneous ones will eventually expire).
                        assert_eq!(l2_vanguards.len(), old_size);
                    } else {
                        // The new size is greater, so we have more L2 vanguards now.
                        assert_eq!(l2_vanguards.len(), new_l2_size);
                    }
                    // There are no L3 vanguards because full vanguards are not in use.
                    assert_eq!(l3_vanguards.len(), 0);
                }
            }
        });
    }

    #[test]
    fn expire_vanguards() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = new_vanguard_mgr(&rt);
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let mut rng = testing_rng();
            let exclusion = RelayExclusion::no_relays_excluded();

            // Wait until the vanguard manager has bootstrapped
            let _netdir_provider =
                init_vanguard_sets(rt.clone(), netdir.clone(), Arc::clone(&vanguardmgr)).await;
            assert_eq!(vanguard_count(&vanguardmgr), params.l2_pool_size());

            let vanguard = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &exclusion)
                .unwrap();

            let lifetime = duration_until_expiry(&vanguard, &vanguardmgr, &rt, Layer2);
            let heap_entry = find_in_heap(&vanguard, &vanguardmgr).unwrap();
            let set_entry = find_in_set(&vanguard, &vanguardmgr, Layer2).unwrap();

            // The entry hasn't expired yet
            assert!(heap_entry.upgrade().is_some());
            assert!(set_entry.upgrade().is_some());

            // Wait until this vanguard expires
            rt.advance_by(lifetime).await.unwrap();
            rt.progress_until_stalled().await;

            // The entry has expired: it no longer exists in the heap, or in the L2 vanguard set
            assert!(heap_entry.upgrade().is_none());
            assert!(set_entry.upgrade().is_none());

            // Check that we replaced the expired vanguard with a new one:
            assert_eq!(vanguard_count(&vanguardmgr), params.l2_pool_size());

            {
                let inner = vanguardmgr.inner.read().unwrap();
                let l2_vanguards = inner.l2_vanguards.vanguards();

                assert_eq!(l2_vanguards.len(), params.l2_pool_size());
            }
        });
    }
}
