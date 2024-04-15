//! Experimental support for vanguards.
//!
//! For more information, see the [vanguards spec].
//!
//! [vanguards spec]: https://spec.torproject.org/vanguards-spec/index.html.

pub mod config;
mod set;

use std::cmp;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime};

use futures::stream::BoxStream;
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
    /// The current vanguard parameters.
    params: VanguardParams,
    /// The L2 vanguards.
    l2_vanguards: VanguardSet,
    /// The L3 vanguards.
    ///
    /// The L3 vanguards are only used if we are running in
    /// [`Full`](VanguardMode::Full) vanguard mode.
    /// Otherwise, this set is not populated, or read from.
    l3_vanguards: VanguardSet,
    /// Whether we're running an onion service.
    ///
    /// Used for deciding whether to use the `vanguards_hs_service` or the
    /// `vanguards_enabled` [`NetParameter`](tor_netdir::params::NetParameter).
    has_onion_svc: bool,
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
        _config: &VanguardConfig,
        runtime: R,
        _state_mgr: S,
        has_onion_svc: bool,
    ) -> Result<Self, VanguardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        // Note: we start out with default vanguard params, but we adjust them
        // as soon as we obtain a NetDir (see Self::run_once()).
        let params = VanguardParams::default();
        let l2_vanguards = VanguardSet::new(params.l2_pool_size());
        let l3_vanguards = VanguardSet::new(params.l3_pool_size());

        let inner = Inner {
            params,
            l2_vanguards,
            l3_vanguards,
            has_onion_svc,
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
                Arc::downgrade(&netdir_provider),
            ))
            .map_err(|e| VanguardMgrError::Spawn(Arc::new(e)))?;

        Ok(())
    }

    /// Replace the configuration in this `VanguardMgr` with the specified `config`.
    pub fn reconfigure(
        &self,
        _config: &VanguardConfig,
    ) -> Result<RetireCircuits, ReconfigureError> {
        // TODO: there is no VanguardConfig.
        // TODO: update has_onion_svc if the new config enables onion svc usage
        //
        // Perhaps we should always escalate to Full if we start running an onion service,
        // but not decessarily downgrade to lite if we stop.
        // See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2083#note_3018173>
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

        let inner = self.inner.read().expect("poisoned lock");

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
        let vanguard_set = match (layer, inner.mode()) {
            (Layer::Layer2, Full) | (Layer::Layer2, Lite) => &inner.l2_vanguards,
            (Layer::Layer3, Full) => &inner.l3_vanguards,
            // TODO HS-VANGUARDS: perhaps we need a dedicated error variant for this
            _ => {
                return Err(internal!(
                    "vanguards for layer {layer} are not supported in mode {})",
                    inner.mode()
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
    /// * removes vanguards from the L2 and L3 [`VanguardSet`]s when they expire
    /// * ensures the [`VanguardSet`]s are repopulated with new vanguards
    ///   when the number of vanguards drops below a certain threshold
    /// * handles `NetDir` changes, updating the vanguard set sizes as needed
    async fn maintain_vanguard_sets(mgr: Weak<Self>, netdir_provider: Weak<dyn NetDirProvider>) {
        let mut netdir_events = match netdir_provider.upgrade() {
            Some(provider) => provider.events(),
            None => {
                return;
            }
        };

        loop {
            match Self::run_once(
                Weak::clone(&mgr),
                Weak::clone(&netdir_provider),
                &mut netdir_events,
            )
            .await
            {
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
    /// This populates the L2 and L3 [`VanguardSet`]s,
    /// and rotates the vanguards when their lifetime expires.
    ///
    /// Note: the L3 set is only populated with vanguards if
    /// [`Full`](VanguardMode::Full) vanguards are enabled.
    async fn run_once(
        mgr: Weak<Self>,
        netdir_provider: Weak<dyn NetDirProvider>,
        netdir_events: &mut BoxStream<'static, DirEvent>,
    ) -> Result<ShutdownStatus, VanguardMgrError> {
        let (mgr, netdir_provider) = match (mgr.upgrade(), netdir_provider.upgrade()) {
            (Some(mgr), Some(netdir_provider)) => (mgr, netdir_provider),
            _ => return Ok(ShutdownStatus::Terminate),
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

        if let Some(netdir) = Self::timely_netdir(&netdir_provider)? {
            // If we have a NetDir, replenish the vanguard sets that don't have enough vanguards.
            let params = VanguardParams::try_from(netdir.params())
                .map_err(into_internal!("invalid NetParameters"))?;
            mgr.inner
                .write()
                .expect("poisoned lock")
                .replenish_vanguards(&mgr.runtime, &netdir, &params)?;
        }

        select_biased! {
            event = netdir_events.next().fuse() => {
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

    /// Return a timely `NetDir`, if one is available.
    ///
    /// Returns `None` if no directory information is available.
    fn timely_netdir(
        netdir_provider: &Arc<dyn NetDirProvider>,
    ) -> Result<Option<Arc<NetDir>>, VanguardMgrError> {
        use tor_netdir::Error as NetDirError;

        match netdir_provider.netdir(Timeliness::Timely) {
            Ok(netdir) => Ok(Some(netdir)),
            Err(NetDirError::NoInfo) | Err(NetDirError::NotEnoughInfo) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove the vanguards that have expired,
    /// returning how long until the next vanguard will expire,
    /// or `None` if there are no vanguards in any of our sets.
    fn remove_expired(&self, now: SystemTime) -> Result<Option<Duration>, VanguardMgrError> {
        let mut inner = self.inner.write().expect("poisoned lock");
        let inner = &mut *inner;

        inner.l2_vanguards.remove_expired(now);
        inner.l3_vanguards.remove_expired(now);

        let l2_expiry = inner.l2_vanguards.next_expiry();
        let l3_expiry = inner.l3_vanguards.next_expiry();
        let expiry = match (l2_expiry, l3_expiry) {
            (Some(e), None) | (None, Some(e)) => e,
            (Some(e1), Some(e2)) => cmp::min(e1, e2),
            (None, None) => {
                // Both vanguard sets are empty
                return Ok(None);
            }
        };

        expiry
            .duration_since(now)
            .map_err(|_| internal!("when > now, but now is later than when?!").into())
            .map(Some)
    }

    /// Get the current [`VanguardMode`].
    pub fn mode(&self) -> VanguardMode {
        self.inner.read().expect("poisoned lock").mode()
    }

    /// Flush the vanguard sets to storage, if the mode is "vanguards-full".
    #[allow(unused)] // TODO HS-VANGUARDS
    fn flush_to_storage(&self) -> Result<(), VanguardMgrError> {
        let mode = self.inner.read().expect("poisoned lock").mode();
        match mode {
            VanguardMode::Lite | VanguardMode::Disabled => Ok(()),
            VanguardMode::Full => todo!(),
        }
    }
}

impl Inner {
    /// Handle potential vanguard parameter changes.
    ///
    /// This updates the [`VanguardSet`]s based on the [`VanguardParams`]
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
        self.remove_unlisted(netdir);

        let params = VanguardParams::try_from(netdir.params())
            .map_err(into_internal!("invalid NetParameters"))?;

        // Update our params with the new values.
        self.update_params(params.clone());

        self.replenish_vanguards(runtime, netdir, &params)?;

        Ok(())
    }

    /// Remove the vanguards that are no longer listed in `netdir`
    fn remove_unlisted(&mut self, netdir: &Arc<NetDir>) {
        self.l2_vanguards.remove_unlisted(netdir);
        self.l3_vanguards.remove_unlisted(netdir);
    }

    /// Replenish the vanguard sets if necessary, using the directory information
    /// from the specified [`NetDir`].
    ///
    /// Note: the L3 set is only replenished if [`Full`](VanguardMode::Full) vanguards are enabled.
    fn replenish_vanguards<R: Runtime>(
        &mut self,
        runtime: &R,
        netdir: &NetDir,
        params: &VanguardParams,
    ) -> Result<(), VanguardMgrError> {
        trace!("replenishing vanguard sets");

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
            params.l2_lifetime_min(),
            params.l2_lifetime_max(),
        )?;

        if self.mode() == VanguardMode::Full {
            self.l3_vanguards.update_target(params.l3_pool_size());
            Self::replenish_set(
                runtime,
                &mut rng,
                netdir,
                &mut self.l3_vanguards,
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
        min_lifetime: Duration,
        max_lifetime: Duration,
    ) -> Result<(), VanguardMgrError> {
        let deficit = vanguard_set.deficit();
        if deficit > 0 {
            // Exclude the relays that are already in this vanguard set.
            let exclude_ids = RelayIdSet::from(&*vanguard_set);
            let exclude = RelayExclusion::exclude_identities(exclude_ids);
            // Pick some vanguards to add to the vanguard_set.
            let new_vanguards = Self::add_n_vanguards(
                runtime,
                rng,
                netdir,
                deficit,
                exclude,
                min_lifetime,
                max_lifetime,
            )?;

            for v in new_vanguards {
                vanguard_set.add_vanguard(v);
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
    ) -> Result<Vec<TimeBoundVanguard>, VanguardMgrError> {
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

                Ok(TimeBoundVanguard {
                    id: RelayIds::from_relay_ids(&relay),
                    when,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Update our vanguard params.
    fn update_params(&mut self, new_params: VanguardParams) {
        self.params = new_params;
    }

    /// Get the current [`VanguardMode`].
    ///
    /// If we are not running an onion service, we use the `vanguards_enabled` mode.
    ///
    /// If we *are* running an onion service, we use whichever of `vanguards_hs_service`
    /// and `vanguards_enabled` is higher for all our onion service circuits.
    fn mode(&self) -> VanguardMode {
        if self.has_onion_svc {
            std::cmp::max(
                self.params.vanguards_enabled(),
                self.params.vanguards_hs_service(),
            )
        } else {
            self.params.vanguards_enabled()
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
        Arc::new(VanguardMgr::new(&config, rt.clone(), statemgr, false).unwrap())
    }

    /// Look up the vanguard in the specified VanguardSet.
    fn find_in_set<R: Runtime>(
        relay_ids: &RelayIds,
        mgr: &VanguardMgr<R>,
        layer: Layer,
    ) -> Option<TimeBoundVanguard> {
        let inner = mgr.inner.read().unwrap();

        let vanguard_set = match layer {
            Layer2 => &inner.l2_vanguards,
            Layer3 => &inner.l3_vanguards,
        };

        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        vanguard_set
            .vanguards()
            .iter()
            .find(|v| v.id == *relay_ids)
            .cloned()
    }

    /// Get the total number of vanguard entries (L2 + L3).
    fn vanguard_count<R: Runtime>(mgr: &VanguardMgr<R>) -> usize {
        let inner = mgr.inner.read().unwrap();
        inner.l2_vanguards.vanguards().len() + inner.l3_vanguards.vanguards().len()
    }

    /// Return a `Duration` representing how long until this vanguard expires.
    fn duration_until_expiry<R: Runtime>(
        relay_ids: &RelayIds,
        mgr: &VanguardMgr<R>,
        runtime: &R,
        layer: Layer,
    ) -> Duration {
        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        let vanguard = find_in_set(relay_ids, mgr, layer).unwrap();

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

        let vanguard = RelayIds::from_relay_ids(vanguard.relay());
        // This is not exactly the lifetime of the vanguard,
        // but rather the time left until it expires (but it's close enough for our purposes).
        let lifetime = duration_until_expiry(&vanguard, mgr, runtime, layer);

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

        if inner.mode() == VanguardMode::Full {
            assert_eq!(inner.l3_vanguards.deficit(), 0);
            let l3_pool_size = params.l3_pool_size();
            assert_eq!(vanguard_count(vanguardmgr), l2_pool_size + l3_pool_size);
        }
    }

    /// Assert the target size of the specified vanguard set matches the target from `params`.
    fn assert_set_targets_match_params<R: Runtime>(mgr: &VanguardMgr<R>, params: &VanguardParams) {
        let inner = mgr.inner.read().unwrap();
        assert_eq!(inner.l2_vanguards.target(), params.l2_pool_size());
        if inner.mode() == VanguardMode::Full {
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
            let initial_l2_number = params.l2_pool_size();

            // Wait until the vanguard manager has bootstrapped
            let netdir_provider =
                init_vanguard_sets(rt.clone(), netdir.clone(), Arc::clone(&vanguardmgr)).await;
            assert_eq!(vanguard_count(&vanguardmgr), params.l2_pool_size());

            // Find the RelayIds of the vanguard that is due to expire next
            let vanguard_id = {
                let inner = vanguardmgr.inner.read().unwrap();
                let next_expiry = inner.l2_vanguards.next_expiry().unwrap();
                inner
                    .l2_vanguards
                    .vanguards()
                    .iter()
                    .find(|v| v.when == next_expiry)
                    .cloned()
                    .unwrap()
                    .id
            };

            const FEWER_VANGUARDS_PARAM: [(&str, i32); 1] = [("guard-hs-l2-number", 1)];
            // Set the number of L2 vanguards to a lower value to ensure the vanguard that is about
            // to expire is not replaced. This allows us to test that it has indeed expired
            // (we can't simply check that the relay is no longer is the set,
            // because it's possible for the set to get replenished with the same relay).
            let new_params = install_new_params(&rt, &netdir_provider, FEWER_VANGUARDS_PARAM).await;

            // The vanguard has not expired yet.
            let timebound_vanguard = find_in_set(&vanguard_id, &vanguardmgr, Layer2);
            assert!(timebound_vanguard.is_some());
            assert_eq!(vanguard_count(&vanguardmgr), initial_l2_number);

            let lifetime = duration_until_expiry(&vanguard_id, &vanguardmgr, &rt, Layer2);
            // Wait until this vanguard expires
            rt.advance_by(lifetime).await.unwrap();
            rt.progress_until_stalled().await;

            let timebound_vanguard = find_in_set(&vanguard_id, &vanguardmgr, Layer2);

            // The vanguard expired, but was not replaced.
            assert!(timebound_vanguard.is_none());
            assert_eq!(vanguard_count(&vanguardmgr), initial_l2_number - 1);

            // Wait until more vanguards expire. This will reduce the set size to 1
            // (the new target size we set by overriding the params).
            rt.advance_until_stalled().await;
            assert_eq!(vanguard_count(&vanguardmgr), new_params.l2_pool_size());

            // Update the L2 set size again, to force the vanguard manager to replenish the L2 set.
            const MORE_VANGUARDS_PARAM: [(&str, i32); 1] = [("guard-hs-l2-number", 5)];
            // Set the number of L2 vanguards to a lower value to ensure the vanguard that is about
            // to expire is not replaced. This allows us to test that it has indeed expired
            // (we can't simply check that the relay is no longer is the set,
            // because it's possible for the set to get replenished with the same relay).
            let new_params = install_new_params(&rt, &netdir_provider, MORE_VANGUARDS_PARAM).await;

            // Check that we replaced the expired vanguard with a new one:
            assert_eq!(vanguard_count(&vanguardmgr), new_params.l2_pool_size());

            {
                let inner = vanguardmgr.inner.read().unwrap();
                let l2_count = inner.l2_vanguards.vanguards().len();
                assert_eq!(l2_count, new_params.l2_pool_size());
            }
        });
    }
}
