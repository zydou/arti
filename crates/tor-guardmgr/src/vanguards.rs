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
use tor_error::{error_report, internal, ErrorKind, HasKind};
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness};
use tor_persist::StateMgr;
use tor_relay_selection::RelayExclusion;
use tor_rtcompat::Runtime;
use tracing::debug;

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
        // TODO HS-VANGUARDS: read the params from the consensus
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

        // TODO HS-VANGUARDS: we might've just removed some vanguards, so we need to check if we
        // need to replenish any of our vanguard sets

        select_biased! {
            event = netdir_events.next() => {
                if let Some(DirEvent::NewConsensus) = event {
                    mgr.remove_unlisted(&netdir_provider.netdir(Timeliness::Timely)?);
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

    /// Remove the vanguards that are no longer listed in `netdir`
    fn remove_unlisted(&self, netdir: &Arc<NetDir>) {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.vanguards.retain(|v| netdir.by_ids(&v.id).is_some());
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
