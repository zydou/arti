//! Manage a pool of circuits for usage with onion services.
//
// TODO HS TEST: We need tests here. First, though, we need a testing strategy.
mod pool;

use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use crate::{timeouts, CircMgr, Error, Result};
use futures::{task::SpawnExt, StreamExt, TryFutureExt};
use once_cell::sync::OnceCell;
use tor_error::debug_report;
use tor_error::{bad_api_usage, internal};
use tor_linkspec::{CircTarget, OwnedCircTarget};
use tor_netdir::{NetDir, NetDirProvider, Relay, SubnetConfig};
use tor_proto::circuit::{self, ClientCirc};
use tor_rtcompat::{
    scheduler::{TaskHandle, TaskSchedule},
    Runtime, SleepProviderExt,
};
use tracing::warn;

/// The (onion-service-related) purpose for which a given circuit is going to be
/// used.
///
/// We will use this to tell how the path for a given circuit is to be
/// constructed.
#[cfg(feature = "hs-common")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum HsCircKind {
    /// Circuit from an onion service to an HsDir.
    SvcHsDir,
    /// Circuit from an onion service to an Introduction Point.
    SvcIntro,
    /// Circuit from an onion service to a Rendezvous Point.
    SvcRend,
    /// Circuit from an onion service client to an HsDir.
    ClientHsDir,
    /// Circuit from an onion service client to an Introduction Point.
    ClientIntro,
    /// Circuit from an onion service client to a Rendezvous Point.
    ClientRend,
}

/// An object to provide circuits for implementing onion services.
pub struct HsCircPool<R: Runtime> {
    /// An underlying circuit manager, used for constructing circuits.
    circmgr: Arc<CircMgr<R>>,
    /// A task handle for making the background circuit launcher fire early.
    //
    // TODO: I think we may want to move this into the same Mutex as Pool
    // eventually.  But for now, this is fine, since it's just an implementation
    // detail.
    launcher_handle: OnceCell<TaskHandle>,
    /// The mutable state of this pool.
    inner: Mutex<Inner>,
}

/// The mutable state of an [`HsCircPool`]
struct Inner {
    /// A collection of pre-constructed circuits.
    pool: pool::Pool,
}

impl<R: Runtime> HsCircPool<R> {
    /// Create a new `HsCircPool`.
    ///
    /// This will not work properly before "launch_background_tasks" is called.
    pub fn new(circmgr: &Arc<CircMgr<R>>) -> Arc<Self> {
        let circmgr = Arc::clone(circmgr);
        let pool = pool::Pool::default();
        Arc::new(Self {
            circmgr,
            launcher_handle: OnceCell::new(),
            inner: Mutex::new(Inner { pool }),
        })
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        runtime: &R,
        netdir_provider: &Arc<dyn NetDirProvider + 'static>,
    ) -> Result<Vec<TaskHandle>> {
        let handle = self.launcher_handle.get_or_try_init(|| {
            runtime
                .spawn(remove_unusable_circuits(
                    Arc::downgrade(self),
                    Arc::downgrade(netdir_provider),
                ))
                .map_err(|e| Error::from_spawn("preemptive onion circuit expiration task", e))?;

            let (schedule, handle) = TaskSchedule::new(runtime.clone());
            runtime
                .spawn(launch_hs_circuits_as_needed(
                    Arc::downgrade(self),
                    Arc::downgrade(netdir_provider),
                    schedule,
                ))
                .map_err(|e| Error::from_spawn("preemptive onion circuit builder task", e))?;

            Result::<TaskHandle>::Ok(handle)
        })?;

        Ok(vec![handle.clone()])
    }

    /// Create a circuit suitable for use as a rendezvous circuit by a client.
    ///
    /// Return the circuit, along with a [`Relay`] from `netdir` representing its final hop.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    pub async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> Result<(Arc<ClientCirc>, Relay<'a>)> {
        // For rendezvous points, clients use 3-hop circuits.
        // Note that we aren't using any special rules for the last hop here; we
        // are relying on the fact that:
        //   * all suitable middle relays that we use in these stub circuits are
        //     suitable renedezvous points, and
        //   * the weighting rules for selecting rendezvous points are the same
        //     as those for selecting an arbitrary middle relay.
        let circ = self
            .take_or_launch_stub_circuit::<OwnedCircTarget>(netdir, None)
            .await?;
        let path = circ.path_ref();
        match path.hops().last() {
            Some(ent) => {
                let Some(ct) = ent.as_chan_target() else {
                    return Err(
                        internal!("HsPool gave us a circuit with a virtual last hop!?").into(),
                    );
                };
                match netdir.by_ids(ct) {
                    Some(relay) => Ok((circ, relay)),
                    // This can't happen, since launch_hs_unmanaged() only takes relays from the netdir
                    // it is given, and circuit_compatible_with_target() ensures that
                    // every relay in the circuit is listed.
                    //
                    // TODO: Still, it's an ugly place in our API; maybe we should return the last hop
                    // from take_or_launch_stub_circuit()?  But in many cases it won't be needed...
                    None => Err(internal!("Got circuit with unknown last hop!?").into()),
                }
            }
            None => Err(internal!("Circuit with an empty path!?").into()),
        }
    }

    /// Create a circuit suitable for use for `kind`, ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    pub async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<Arc<ClientCirc>>
    where
        T: CircTarget,
    {
        // The kind makes no difference yet, but it will at some point in the future.
        match kind {
            HsCircKind::ClientRend => {
                return Err(
                    bad_api_usage!("get_or_launch_specific with ClientRend circuit!?").into(),
                )
            }
            HsCircKind::SvcIntro => {
                // TODO HS-VANGUARDS: In this case we will want to add an extra hop, once we have vanguards.
                // When this happens, the whole match statement will want to become
                // let extra_hop = match kind {...}
            }
            HsCircKind::SvcHsDir
            | HsCircKind::SvcRend
            | HsCircKind::ClientHsDir
            | HsCircKind::ClientIntro => {}
        }

        // For most* of these circuit types, we want to build our circuit with
        // an extra hop, since the target hop is under somebody else's control.
        //
        // * The exceptions are ClientRend, which we handle in a different
        //   method, and SvcIntro, where we will eventually  want an extra hop
        //   to avoid vanguard discovery attacks.

        // Get an unfinished circuit that's compatible with our target.
        let circ = self
            .take_or_launch_stub_circuit(netdir, Some(&target))
            .await?;

        // Estimate how long it will take to extend it one more hop, and
        // construct a timeout as appropriate.
        let n_hops = circ.n_hops();
        let (extend_timeout, _) = self.circmgr.mgr.peek_builder().estimator().timeouts(
            &crate::timeouts::Action::ExtendCircuit {
                initial_length: n_hops,
                final_length: n_hops + 1,
            },
        );

        // Make a future to extend the circuit.
        let params = crate::DirInfo::from(netdir).circ_params();
        let extend_future = circ
            .extend_ntor(&target, &params)
            .map_err(|error| Error::Protocol {
                action: "extending to chosen HS hop",
                peer: None, // Either party could be to blame.
                error,
            });

        // Wait up to the timeout for the future to complete.
        self.circmgr
            .mgr
            .peek_runtime()
            .timeout(extend_timeout, extend_future)
            .await
            .map_err(|_| Error::CircTimeout(Some(circ.unique_id())))??;

        // With any luck, return the circuit.
        Ok(circ)
    }

    /// Take and return a circuit from our pool suitable for being extended to `avoid_target`.
    ///
    /// If there is no such circuit, build and return a new one.
    async fn take_or_launch_stub_circuit<T>(
        &self,
        netdir: &NetDir,
        avoid_target: Option<&T>,
    ) -> Result<Arc<ClientCirc>>
    where
        T: CircTarget,
    {
        // First, look for a circuit that is already built, if any is suitable.
        let subnet_config = self.circmgr.builder().path_config().subnet_config();
        let owned_avoid_target = avoid_target.map(OwnedCircTarget::from_circ_target);
        let target = owned_avoid_target.as_ref().map(|target| TargetInfo {
            target,
            relay: netdir.by_ids(target),
        });
        let found_usable_circ = {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let found_usable_circ = inner.pool.take_one_where(&mut rand::thread_rng(), |circ| {
                circuit_compatible_with_target(netdir, subnet_config, circ, target.as_ref())
            });

            // Tell the background task to fire immediately if we have very few circuits
            // circuits left, or if we found nothing.
            if inner.pool.very_low() || found_usable_circ.is_none() {
                let handle = self.launcher_handle.get().ok_or_else(|| {
                    Error::from(bad_api_usage!("The circuit launcher wasn't initialized"))
                })?;
                handle.fire();
            }
            found_usable_circ
        };
        // Return the circuit we found before, if any.
        if let Some(circuit) = found_usable_circ {
            return Ok(circuit);
        }

        // TODO: There is a possible optimization here. Instead of only waiting
        // for the circuit we launch below to finish, we could also wait for any
        // of our in-progress preemptive circuits to finish.  That would,
        // however, complexify our logic quite a bit.

        // TODO: We could in launch multiple circuits in parallel here?
        self.circmgr.launch_hs_unmanaged(avoid_target, netdir).await
    }

    /// Internal: Remove every closed circuit from this pool.
    fn remove_closed(&self) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.pool.retain(|circ| !circ.is_closing());
    }

    /// Internal: Remove every circuit form this pool for which any relay is not
    /// listed in `netdir`.
    fn remove_unlisted(&self, netdir: &NetDir) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner
            .pool
            .retain(|circ| circuit_still_useable(netdir, circ, |_relay| true));
    }

    /// Return an estimate-based delay for how long a given
    /// [`Action`](timeouts::Action) should be allowed to complete.
    ///
    /// This function has the same semantics as
    /// [`CircMgr::estimate_timeout`].
    /// See the notes there.
    ///
    /// In particular **you do not need to use this function** in order to get
    /// reasonable timeouts for the circuit-building operations provided by `HsCircPool`.
    //
    // In principle we could have made this available by making `HsCircPool` `Deref`
    // to `CircMgr`, but we don't want to do that because `CircMgr` has methods that
    // operate on *its* pool which is separate from the pool maintained by `HsCircPool`.
    //
    // We *might* want to provide a method to access the underlying `CircMgr`
    // but that has the same issues, albeit less severely.
    pub fn estimate_timeout(&self, timeout_action: &timeouts::Action) -> std::time::Duration {
        self.circmgr.estimate_timeout(timeout_action)
    }
}

/// Wrapper around a target final hop, and any information about that target we
/// were able to find from the directory.
///
/// We don't use this for _extending_ to the final hop, since it contains an
/// OwnedCircTarget, which may not preserve all the
/// [`LinkSpec`](tor_linkspec::LinkSpec)s in the right order.  We only use it
/// for assessing circuit compatibility.
///
/// TODO: This is possibly a bit redundant with path::MaybeOwnedRelay.  We
/// should consider merging them someday, once we have a better sense of what we
/// truly want here.
struct TargetInfo<'a> {
    /// The target to be used as a final hop.
    //
    // TODO: Perhaps this should be a generic &dyn CircTarget? I'm not sure we
    // win anything there, though.
    target: &'a OwnedCircTarget,
    /// A Relay reference for the targe, if we found one.
    relay: Option<Relay<'a>>,
}

impl<'a> TargetInfo<'a> {
    /// Return true if, according to the rules of `subnet_config`, this target can share a circuit with `r`.
    fn may_share_circuit_with(&self, r: &Relay<'_>, subnet_config: SubnetConfig) -> bool {
        // TODO #504
        // TODO 768
        if let Some(this_r) = &self.relay {
            if this_r.in_same_family(r) {
                return false;
            }
            // TODO: When bridge families are finally implemented (likely via
            // proposal `321-happy-families.md`), we should move family
            // functionality into CircTarget.
        }

        !subnet_config.any_addrs_in_same_subnet(self.target, r)
    }
}

/// Return true if we can extend a pre-built circuit `circ` to `target`.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that no hop in the circuit shares a family with
/// `target`.
fn circuit_compatible_with_target(
    netdir: &NetDir,
    subnet_config: SubnetConfig,
    circ: &ClientCirc,
    target: Option<&TargetInfo<'_>>,
) -> bool {
    circuit_still_useable(netdir, circ, |relay| match target {
        Some(t) => t.may_share_circuit_with(relay, subnet_config),
        None => true,
    })
}

/// Return true if we can still use a given pre-build circuit.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that `relay_okay` returns true for every hop on the
/// circuit.
fn circuit_still_useable<F>(netdir: &NetDir, circ: &ClientCirc, relay_okay: F) -> bool
where
    F: Fn(&Relay<'_>) -> bool,
{
    if circ.is_closing() {
        return false;
    }

    let path = circ.path_ref();
    // (We have to use a binding here to appease borrowck.)
    let all_compatible = path.iter().all(|ent: &circuit::PathEntry| {
        let Some(c) = ent.as_chan_target() else {
            // This is a virtual hop; it's necessarily compatible with everything.
            return true;
        };
        let Some(relay) = netdir.by_ids(c) else {
            // We require that every relay in this circuit is still listed; an
            // unlisted relay means "reject".
            return false;
        };
        // Now it's all down to the predicate.
        relay_okay(&relay)
    });
    all_compatible
}

/// Background task to launch onion circuits as needed.
async fn launch_hs_circuits_as_needed<R: Runtime>(
    pool: Weak<HsCircPool<R>>,
    netdir_provider: Weak<dyn NetDirProvider + 'static>,
    mut schedule: TaskSchedule<R>,
) {
    /// Default delay when not told to fire explicitly. Chosen arbitrarily.
    const DELAY: Duration = Duration::from_secs(30);

    while schedule.next().await.is_some() {
        let (pool, provider) = match (pool.upgrade(), netdir_provider.upgrade()) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                break;
            }
        };
        let now = pool.circmgr.mgr.peek_runtime().now();
        pool.remove_closed();
        let mut n_to_launch = {
            let mut inner = pool.inner.lock().expect("poisioned_lock");
            inner.pool.update_target_size(now);
            inner.pool.n_to_launch()
        };
        let mut max_attempts = n_to_launch * 2;
        'inner: while n_to_launch > 1 {
            max_attempts -= 1;
            if max_attempts == 0 {
                // We want to avoid retrying over and over in a tight loop if all our attempts
                // are failing.
                warn!("Too many preemptive onion service circuits failed; waiting a while.");
                break 'inner;
            }
            if let Ok(netdir) = provider.netdir(tor_netdir::Timeliness::Timely) {
                // We want to launch a circuit, and we have a netdir that we can use
                // to launch it.
                //
                // TODO: Possibly we should be doing this in a background task, and
                // launching several of these in parallel.  If we do, we should think about
                // whether taking the fastest will expose us to any attacks.
                let no_target: Option<&OwnedCircTarget> = None;
                // TODO HS: We should catch panics, here or in launch_hs_unmanaged.
                match pool.circmgr.launch_hs_unmanaged(no_target, &netdir).await {
                    Ok(circ) => {
                        pool.inner.lock().expect("poisoned lock").pool.insert(circ);
                        n_to_launch -= 1;
                    }
                    Err(err) => {
                        debug_report!(err, "Unable to build preemptive circuit for onion services");
                    }
                }
            } else {
                // We'd like to launch a circuit, but we don't have a netdir that we
                // can use.
                //
                // TODO HS possibly instead of a fixed delay we want to wait for more
                // netdir info?
                break 'inner;
            }
        }

        // We have nothing to launch now, so we'll try after a while.
        schedule.fire_in(DELAY);
    }
}

/// Background task to remove unusable circuits whenever the directory changes.
async fn remove_unusable_circuits<R: Runtime>(
    pool: Weak<HsCircPool<R>>,
    netdir_provider: Weak<dyn NetDirProvider + 'static>,
) {
    let mut event_stream = match netdir_provider.upgrade() {
        Some(nd) => nd.events(),
        None => return,
    };

    // Note: We only look at the event stream here, not any kind of TaskSchedule.
    // That's fine, since this task only wants to fire when the directory changes,
    // and the directory will not change while we're dormant.
    //
    // Removing closed circuits is also handled above in launch_hs_circuits_as_needed.
    while event_stream.next().await.is_some() {
        let (pool, provider) = match (pool.upgrade(), netdir_provider.upgrade()) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                break;
            }
        };
        pool.remove_closed();
        if let Ok(netdir) = provider.netdir(tor_netdir::Timeliness::Timely) {
            pool.remove_unlisted(&netdir);
        }
    }
}
