//! Manage a pool of circuits for usage with onion services.
//
// TODO HS TEST: We need tests here. First, though, we need a testing strategy.
mod config;
mod pool;

use std::{
    ops::Deref,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use crate::{timeouts, CircMgr, Error, Result};
use futures::{task::SpawnExt, StreamExt, TryFutureExt};
use once_cell::sync::OnceCell;
use tor_error::debug_report;
use tor_error::{bad_api_usage, internal};
use tor_linkspec::{CircTarget, OwnedCircTarget};
use tor_netdir::{NetDir, NetDirProvider, Relay};
use tor_proto::circuit::{self, ClientCirc};
use tor_relay_selection::{LowLevelRelayPredicate, RelayExclusion};
use tor_rtcompat::{
    scheduler::{TaskHandle, TaskSchedule},
    Runtime, SleepProviderExt,
};
use tracing::{debug, trace, warn};

use std::result::Result as StdResult;

pub use config::HsCircPoolConfig;

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

impl HsCircKind {
    /// Return the [`HsCircStubKind`] needed to build this type of circuit.
    fn stub_kind(&self) -> HsCircStubKind {
        match self {
            HsCircKind::ClientRend | HsCircKind::SvcIntro => HsCircStubKind::Stub,
            HsCircKind::SvcHsDir => {
                // TODO HS-VANGUARDS: we might want this to be STUB+
                HsCircStubKind::Stub
            }
            HsCircKind::SvcRend | HsCircKind::ClientHsDir | HsCircKind::ClientIntro => {
                HsCircStubKind::Extended
            }
        }
    }
}

/// A hidden service circuit stub.
///
/// This represents a hidden service circuit that has not yet been extended to a target.
///
/// See [HsCircStubKind].
pub(crate) struct HsCircStub {
    /// The circuit.
    pub(crate) circ: Arc<ClientCirc>,
    /// Whether the circuit is STUB or STUB+.
    pub(crate) kind: HsCircStubKind,
}

impl Deref for HsCircStub {
    type Target = Arc<ClientCirc>;

    fn deref(&self) -> &Self::Target {
        &self.circ
    }
}

impl HsCircStub {
    /// Check if this circuit stub is of the specified `kind`
    /// or can be extended to become that kind.
    ///
    /// Returns `true` if this `HsCircStub`'s kind is equal to `other`,
    /// or if its kind is [`Stub`](HsCircStubKind::Stub)
    /// and `other` is [`Extended`](HsCircStubKind::Extended).
    pub(crate) fn can_become(&self, other: HsCircStubKind) -> bool {
        use HsCircStubKind::*;

        match (self.kind, other) {
            (Stub, Stub) | (Extended, Extended) | (Stub, Extended) => true,
            (Extended, Stub) => false,
        }
    }
}

/// A kind of hidden service circuit stub.
///
/// See [hspath](crate::path::hspath) docs for more information.
///
/// The structure of a stub circuit depends on whether vanguards are enabled:
///
///   * with vanguards disabled:
///      ```text
///         STUB  = G -> M -> M
///         STUB+ = G -> M -> M
///      ```
///
///   * with lite vanguards enabled:
///      ```text
///         STUB  = G -> L2 -> M
///         STUB+ = G -> L2 -> M
///      ```
///
///   * with full vanguards enabled:
///      ```text
///         STUB  = G -> L2 -> L3
///         STUB+ = G -> L2 -> L3 -> M
///      ```
#[derive(Copy, Clone, Debug, PartialEq, derive_more::Display)]
pub(crate) enum HsCircStubKind {
    /// A stub circuit (STUB).
    #[display(fmt = "STUB")]
    Stub,
    /// An extended stub circuit (STUB+).
    #[display(fmt = "STUB+")]
    Extended,
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
            .take_or_launch_stub_circuit::<OwnedCircTarget>(netdir, None, HsCircStubKind::Stub)
            .await?;

        if self.vanguards_enabled() && circ.kind != HsCircStubKind::Stub {
            return Err(internal!("wanted a STUB circuit, but got STUB+?!").into());
        }

        let path = circ.path_ref();
        match path.hops().last() {
            Some(ent) => {
                let Some(ct) = ent.as_chan_target() else {
                    return Err(
                        internal!("HsPool gave us a circuit with a virtual last hop!?").into(),
                    );
                };
                match netdir.by_ids(ct) {
                    Some(relay) => Ok((circ.circ, relay)),
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
        if kind == HsCircKind::ClientRend {
            return Err(bad_api_usage!("get_or_launch_specific with ClientRend circuit!?").into());
        }
        // TODO HS-VANGUARDS: the kind makes no difference yet, but it will at some point in the future.
        let wanted_kind = kind.stub_kind();

        // For most* of these circuit types, we want to build our circuit with
        // an extra hop, since the target hop is under somebody else's control.
        //
        // * The exceptions are ClientRend, which we handle in a different
        //   method, and SvcIntro, where we will eventually  want an extra hop
        //   to avoid vanguard discovery attacks.

        // Get an unfinished circuit that's compatible with our target.
        let circ = self
            .take_or_launch_stub_circuit(netdir, Some(&target), wanted_kind)
            .await?;

        if self.vanguards_enabled() && circ.kind != wanted_kind {
            return Err(internal!(
                "take_or_launch_stub_circuit() returned {:?}, but we need {wanted_kind:?}",
                circ.kind
            )
            .into());
        }

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
                unique_id: Some(circ.unique_id()),
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
        Ok(circ.circ)
    }

    /// Try to change our configuration to `new_config`.
    ///
    /// Actual behavior will depend on the value of `how`.
    pub fn reconfigure<CFG: HsCircPoolConfig>(
        &self,
        new_config: &CFG,
        _how: tor_config::Reconfigure,
    ) -> StdResult<(), tor_config::ReconfigureError> {
        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        self.inner
            .lock()
            .expect("poisoned lock")
            .pool
            .reconfigure_vanguards(new_config.vanguard_config())?;

        Ok(())
    }

    /// Take and return a circuit from our pool suitable for being extended to `avoid_target`.
    ///
    /// If vanguards are enabled, this will try to build a circuit stub of the specified
    /// [`HsCircStubKind`].
    ///
    /// If vanguards are disabled, `kind` is unused.
    ///
    /// If there is no such circuit, build and return a new one.
    async fn take_or_launch_stub_circuit<T>(
        &self,
        netdir: &NetDir,
        avoid_target: Option<&T>,
        kind: HsCircStubKind,
    ) -> Result<HsCircStub>
    where
        // TODO #504: It would be better if this were a type that had to include
        // family info.
        T: CircTarget,
    {
        // First, look for a circuit that is already built, if any is suitable.

        let target_exclusion = {
            let path_cfg = self.circmgr.builder().path_config();
            let cfg = path_cfg.relay_selection_config();
            match avoid_target {
                // TODO #504: This is an unaccompanied RelayExclusion, and is therefore a
                // bit suspect.  We should consider whether we like this behavior.
                Some(ct) => RelayExclusion::exclude_channel_target_family(&cfg, ct, netdir),
                None => RelayExclusion::no_relays_excluded(),
            }
        };

        let found_usable_circ = {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let vanguards_enabled = inner.pool.vanguards_enabled();

            let restrictions = |circ: &HsCircStub| {
                // If vanguards are enabled, we no longer apply same-family or same-subnet
                // restrictions, and we allow the guard to appear as either of the last
                // two hope of the circuit.
                if vanguards_enabled {
                    // TODO HS-VANGUARDS: check if the circuit is still usable using
                    // circuit_still_useable
                    //
                    // TODO HS-VANGUARDS: this is suboptimal. If we need a STUB+
                    // circuit, we need to prefer STUB+ circuits over STUB
                    circ.can_become(kind)
                } else {
                    circuit_compatible_with_target(netdir, circ, &target_exclusion)
                }
            };

            let found_usable_circ = inner
                .pool
                .take_one_where(&mut rand::thread_rng(), restrictions);

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
            return self.maybe_extend_stub_circuit(circuit, kind);
        }

        // TODO: There is a possible optimization here. Instead of only waiting
        // for the circuit we launch below to finish, we could also wait for any
        // of our in-progress preemptive circuits to finish.  That would,
        // however, complexify our logic quite a bit.

        // TODO: We could in launch multiple circuits in parallel here?
        let circ = self
            .circmgr
            .launch_hs_unmanaged(avoid_target, netdir, kind)
            .await?;

        Ok(HsCircStub { circ, kind })
    }

    /// Return a circuit of the specified `kind`, built from `circuit`.
    fn maybe_extend_stub_circuit(
        &self,
        mut circuit: HsCircStub,
        kind: HsCircStubKind,
    ) -> Result<HsCircStub> {
        if !self.vanguards_enabled() {
            return Ok(circuit);
        }

        match (circuit.kind, kind) {
            (HsCircStubKind::Stub, HsCircStubKind::Extended) => {
                // TODO HS-VANGUARDS: if full vanguards are enabled and the circuit we got is STUB,
                // we need to extend it by another hop to make it STUB+ before returning it
                circuit.kind = kind;

                Ok(circuit)
            }
            (HsCircStubKind::Extended, HsCircStubKind::Stub) => {
                Err(internal!("wanted a STUB circuit, but got STUB+?!").into())
            }
            _ => {
                // Nothing to do: the circuit stub we got is of the kind we wanted
                Ok(circuit)
            }
        }
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

    /// Returns `true` if vanguards are enabled.
    fn vanguards_enabled(&self) -> bool {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "vanguards", feature = "hs-common"))] {
                let inner = self.inner.lock().expect("lock poisoned");
                inner.pool.vanguards_enabled()
            } else {
                false
            }
        }
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

/// Return true if we can extend a pre-built circuit `circ` to `target`.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that no hop in the circuit shares a family with
/// `target`.
fn circuit_compatible_with_target(
    netdir: &NetDir,
    circ: &HsCircStub,
    exclude_target: &RelayExclusion,
) -> bool {
    // NOTE, TODO #504:
    // This uses a RelayExclusion directly, when we would be better off
    // using a RelaySelector to make sure that we had checked every relevant
    // property.
    //
    // The behavior is okay, since we already checked all the properties of the
    // circuit's relays when we first constructed the circuit.  Still, it would
    // be better to use refactor and a RelaySelector instead.
    circuit_still_useable(netdir, circ, |relay| {
        exclude_target.low_level_predicate_permits_relay(relay)
    })
}

/// Return true if we can still use a given pre-build circuit.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that `relay_okay` returns true for every hop on the
/// circuit.
fn circuit_still_useable<F>(netdir: &NetDir, circ: &HsCircStub, relay_okay: F) -> bool
where
    F: Fn(&Relay<'_>) -> bool,
{
    let circ = &circ.circ;
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
        let mut circs_to_launch = {
            let mut inner = pool.inner.lock().expect("poisioned_lock");
            inner.pool.update_target_size(now);
            inner.pool.circs_to_launch()
        };
        let n_to_launch = circs_to_launch.n_to_launch();
        let mut max_attempts = n_to_launch * 2;

        debug!(
            "launching {} STUB and {} STUB+ circuits",
            circs_to_launch.stub(),
            circs_to_launch.ext_stub()
        );

        'inner: while circs_to_launch.n_to_launch() > 0 {
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

                // TODO HS-VANGUARDS: we will need to launch N STUB circuits and M STUB+
                // circuits, for some N, M.
                //
                // We will need Pool to have two different targets, one for STUB circuits and
                // another for STUB+. Otherwise, if we only know the overall circuit target, each
                // time the pool is low on circuits we'll have no choice but to spawn both kinds of
                // stub circuits (in a ratio of N/M), even if we don't necessarily need the deficit
                // to be replenished in the N/M ratio. IOW, if the pool's overall target number of
                // circuits is T = N + M, and the actual number of circuits in the pool is
                // L = T - D, we'll need to spawn D circuits that consist of X STUBs and Y
                // STUB+s, where X/Y is not necessarily N/M (but the overall STUB/STUB+ ratio
                // *is* N/M).
                let for_launch = circs_to_launch.for_launch();

                // TODO HS: We should catch panics, here or in launch_hs_unmanaged.
                match pool
                    .circmgr
                    .launch_hs_unmanaged(no_target, &netdir, for_launch.kind())
                    .await
                {
                    Ok(circ) => {
                        let kind = for_launch.kind();
                        let circ = HsCircStub {
                            circ,
                            kind,
                        };
                        pool.inner.lock().expect("poisoned lock").pool.insert(circ);
                        trace!("successfully launched {kind} circuit");
                        for_launch.note_circ_launched();
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
