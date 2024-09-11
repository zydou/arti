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

use crate::{
    build::CircuitBuilder, mgr::AbstractCircBuilder, timeouts, AbstractCirc, CircMgr, CircMgrInner,
    Error, Result,
};
use futures::{task::SpawnExt, StreamExt, TryFutureExt};
use once_cell::sync::OnceCell;
use tor_error::{bad_api_usage, internal};
use tor_error::{debug_report, Bug};
use tor_guardmgr::VanguardMode;
use tor_linkspec::{
    CircTarget, HasRelayIds as _, IntoOwnedChanTarget, OwnedChanTarget, OwnedCircTarget,
};
use tor_netdir::{NetDir, NetDirProvider, Relay};
use tor_proto::circuit::{self, CircParameters, ClientCirc};
use tor_relay_selection::{LowLevelRelayPredicate, RelayExclusion};
use tor_rtcompat::{
    scheduler::{TaskHandle, TaskSchedule},
    Runtime, SleepProviderExt,
};
use tracing::{debug, trace, warn};

use std::result::Result as StdResult;

pub use config::HsCircPoolConfig;

use self::pool::HsCircPrefs;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use crate::path::hspath::select_middle_for_vanguard_circ;

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
    /// Return the [`HsCircStemKind`] needed to build this type of circuit.
    fn stub_kind(&self) -> HsCircStemKind {
        match self {
            HsCircKind::ClientRend | HsCircKind::SvcIntro => HsCircStemKind::Short,
            HsCircKind::SvcHsDir => {
                // TODO: we might want this to be GUARDED
                HsCircStemKind::Short
            }
            HsCircKind::SvcRend | HsCircKind::ClientHsDir | HsCircKind::ClientIntro => {
                HsCircStemKind::Extended
            }
        }
    }
}

/// A hidden service circuit stub.
///
/// This represents a hidden service circuit that has not yet been extended to a target.
///
/// See [HsCircStemKind].
pub(crate) struct HsCircStem<C: AbstractCirc> {
    /// The circuit.
    pub(crate) circ: Arc<C>,
    /// Whether the circuit is NAIVE  or GUARDED.
    pub(crate) kind: HsCircStemKind,
}

impl<C: AbstractCirc> HsCircStem<C> {
    /// Whether this circuit satisfies _all_ the [`HsCircPrefs`].
    ///
    /// Returns `false` if any of the `prefs` are not satisfied.
    fn satisfies_prefs(&self, prefs: &HsCircPrefs) -> bool {
        let HsCircPrefs { kind_prefs } = prefs;

        match kind_prefs {
            Some(kind) => *kind == self.kind,
            None => true,
        }
    }
}

impl<C: AbstractCirc> Deref for HsCircStem<C> {
    type Target = Arc<C>;

    fn deref(&self) -> &Self::Target {
        &self.circ
    }
}

impl<C: AbstractCirc> HsCircStem<C> {
    /// Check if this circuit stub is of the specified `kind`
    /// or can be extended to become that kind.
    ///
    /// Returns `true` if this `HsCircStem`'s kind is equal to `other`,
    /// or if its kind is [`Short`](HsCircStemKind::Short)
    /// and `other` is [`Extended`](HsCircStemKind::Extended).
    pub(crate) fn can_become(&self, other: HsCircStemKind) -> bool {
        use HsCircStemKind::*;

        match (self.kind, other) {
            (Short, Short) | (Extended, Extended) | (Short, Extended) => true,
            (Extended, Short) => false,
        }
    }
}

#[allow(rustdoc::private_intra_doc_links)]
/// A kind of hidden service circuit stub.
///
/// See [hspath](crate::path::hspath) docs for more information.
///
/// The structure of a stub circuit depends on whether vanguards are enabled:
///
///   * with vanguards disabled:
///      ```text
///         NAIVE   = G -> M -> M
///         GUARDED = G -> M -> M
///      ```
///
///   * with lite vanguards enabled:
///      ```text
///         NAIVE   = G -> L2 -> M
///         GUARDED = G -> L2 -> M
///      ```
///
///   * with full vanguards enabled:
///      ```text
///         NAIVE    = G -> L2 -> L3
///         GUARDED = G -> L2 -> L3 -> M
///      ```
#[derive(Copy, Clone, Debug, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub(crate) enum HsCircStemKind {
    /// A short stub circuit.
    ///
    /// Used for building circuits to a final hop that an adversary cannot easily control,
    /// for example if the final hop is is randomly chosen by us.
    #[display("NAIVE")]
    Short,
    /// An extended stub circuit.
    ///
    /// Used for building circuits to a final hop that an adversary can easily control,
    /// for example if the final hop is not chosen by us.
    #[display("GUARDED")]
    Extended,
}

impl HsCircStemKind {
    /// Return the number of hops this `HsCircKind` ought to have when using the specified
    /// [`VanguardMode`].
    pub(crate) fn num_hops(&self, mode: VanguardMode) -> StdResult<usize, Bug> {
        use HsCircStemKind::*;
        use VanguardMode::*;

        let len = match (mode, self) {
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Lite, _) => 3,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Full, Short) => 3,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Full, Extended) => 4,
            (Disabled, _) => 3,
            (_, _) => {
                return Err(internal!("Unsupported vanguard mode {mode}"));
            }
        };

        Ok(len)
    }
}

/// An object to provide circuits for implementing onion services.
pub struct HsCircPool<R: Runtime>(Arc<HsCircPoolInner<CircuitBuilder<R>, R>>);

impl<R: Runtime> HsCircPool<R> {
    /// Create a new `HsCircPool`.
    ///
    /// This will not work properly before "launch_background_tasks" is called.
    pub fn new(circmgr: &Arc<CircMgr<R>>) -> Self {
        Self(Arc::new(HsCircPoolInner::new(circmgr)))
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
        T: CircTarget + std::marker::Sync,
    {
        self.0.get_or_launch_specific(netdir, kind, target).await
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
        self.0.get_or_launch_client_rend(netdir).await
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
        self.0.estimate_timeout(timeout_action)
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        runtime: &R,
        netdir_provider: &Arc<dyn NetDirProvider + 'static>,
    ) -> Result<Vec<TaskHandle>> {
        HsCircPoolInner::launch_background_tasks(&self.0.clone(), runtime, netdir_provider)
    }

    /// Retire the circuits in this pool.
    ///
    /// This is used for handling vanguard configuration changes:
    /// if the [`VanguardMode`] changes, we need to empty the pool and rebuild it,
    /// because the old circuits are no longer suitable for use.
    pub fn retire_all_circuits(&self) -> StdResult<(), tor_config::ReconfigureError> {
        self.0.retire_all_circuits()
    }
}

/// An object to provide circuits for implementing onion services.
pub(crate) struct HsCircPoolInner<B: AbstractCircBuilder<R> + 'static, R: Runtime> {
    /// An underlying circuit manager, used for constructing circuits.
    circmgr: Arc<CircMgrInner<B, R>>,
    /// A task handle for making the background circuit launcher fire early.
    //
    // TODO: I think we may want to move this into the same Mutex as Pool
    // eventually.  But for now, this is fine, since it's just an implementation
    // detail.
    launcher_handle: OnceCell<TaskHandle>,
    /// The mutable state of this pool.
    inner: Mutex<Inner<B::Circ>>,
}

/// The mutable state of an [`HsCircPool`]
struct Inner<C: AbstractCirc> {
    /// A collection of pre-constructed circuits.
    pool: pool::Pool<C>,
}

impl<R: Runtime> HsCircPoolInner<CircuitBuilder<R>, R> {
    /// Internal implementation for [`HsCircPool::new`].
    pub(crate) fn new(circmgr: &CircMgr<R>) -> Self {
        Self::new_internal(&circmgr.0)
    }
}

impl<B: AbstractCircBuilder<R> + 'static, R: Runtime> HsCircPoolInner<B, R> {
    /// Create a new [`HsCircPoolInner`] from a [`CircMgrInner`].
    pub(crate) fn new_internal(circmgr: &Arc<CircMgrInner<B, R>>) -> Self {
        let circmgr = Arc::clone(circmgr);
        let pool = pool::Pool::default();
        Self {
            circmgr,
            launcher_handle: OnceCell::new(),
            inner: Mutex::new(Inner { pool }),
        }
    }

    /// Internal implementation for [`HsCircPool::launch_background_tasks`].
    pub(crate) fn launch_background_tasks(
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

    /// Internal implementation for [`HsCircPool::get_or_launch_client_rend`].
    pub(crate) async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> Result<(Arc<B::Circ>, Relay<'a>)> {
        // For rendezvous points, clients use 3-hop circuits.
        // Note that we aren't using any special rules for the last hop here; we
        // are relying on the fact that:
        //   * all suitable middle relays that we use in these stub circuits are
        //     suitable renedezvous points, and
        //   * the weighting rules for selecting rendezvous points are the same
        //     as those for selecting an arbitrary middle relay.
        let circ = self
            .take_or_launch_stub_circuit::<OwnedCircTarget>(netdir, None, HsCircStemKind::Extended)
            .await?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        if matches!(
            self.vanguard_mode(),
            VanguardMode::Full | VanguardMode::Lite
        ) && circ.kind != HsCircStemKind::Extended
        {
            return Err(internal!("wanted a GUARDED circuit, but got NAIVE?!").into());
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

    /// Internal implementation for [`HsCircPool::get_or_launch_specific`].
    pub(crate) async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<Arc<B::Circ>>
    where
        T: CircTarget + std::marker::Sync,
    {
        if kind == HsCircKind::ClientRend {
            return Err(bad_api_usage!("get_or_launch_specific with ClientRend circuit!?").into());
        }

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

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        if matches!(
            self.vanguard_mode(),
            VanguardMode::Full | VanguardMode::Lite
        ) && circ.kind != wanted_kind
        {
            return Err(internal!(
                "take_or_launch_stub_circuit() returned {:?}, but we need {wanted_kind:?}",
                circ.kind
            )
            .into());
        }

        let params = crate::DirInfo::from(netdir).circ_params();
        self.extend_circ(circ, params, target).await
    }

    /// Try to extend a circuit to the specified target hop.
    async fn extend_circ<T>(
        &self,
        circ: HsCircStem<B::Circ>,
        params: CircParameters,
        target: T,
    ) -> Result<Arc<B::Circ>>
    where
        T: CircTarget + std::marker::Sync,
    {
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

    /// Internal implementation for [`HsCircPool::retire_all_circuits`].
    pub(crate) fn retire_all_circuits(&self) -> StdResult<(), tor_config::ReconfigureError> {
        self.inner
            .lock()
            .expect("poisoned lock")
            .pool
            .retire_all_circuits()?;

        Ok(())
    }

    /// Take and return a circuit from our pool suitable for being extended to `avoid_target`.
    ///
    /// If vanguards are enabled, this will try to build a circuit stub of the specified
    /// [`HsCircStemKind`].
    ///
    /// If vanguards are disabled, `kind` is unused.
    ///
    /// If there is no such circuit, build and return a new one.
    async fn take_or_launch_stub_circuit<T>(
        &self,
        netdir: &NetDir,
        avoid_target: Option<&T>,
        kind: HsCircStemKind,
    ) -> Result<HsCircStem<B::Circ>>
    where
        // TODO #504: It would be better if this were a type that had to include
        // family info.
        T: CircTarget + std::marker::Sync,
    {
        let vanguard_mode = self.vanguard_mode();
        trace!(
            vanguards=%vanguard_mode,
            kind=%kind,
            "selecting HS circuit stub"
        );

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

            let restrictions = |circ: &HsCircStem<B::Circ>| {
                // If vanguards are enabled, we no longer apply same-family or same-subnet
                // restrictions, and we allow the guard to appear as either of the last
                // two hope of the circuit.
                match vanguard_mode {
                    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                    VanguardMode::Lite | VanguardMode::Full => {
                        vanguards_circuit_compatible_with_target(netdir, circ, kind, avoid_target)
                    }
                    VanguardMode::Disabled => {
                        circuit_compatible_with_target(netdir, circ, &target_exclusion)
                    }
                    _ => {
                        warn!("unknown vanguard mode {vanguard_mode}");
                        false
                    }
                }
            };

            let mut prefs = HsCircPrefs::default();

            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            if matches!(vanguard_mode, VanguardMode::Full | VanguardMode::Lite) {
                prefs.preferred_stub_kind(kind);
            }

            let found_usable_circ =
                inner
                    .pool
                    .take_one_where(&mut rand::thread_rng(), restrictions, &prefs);

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
            let circuit = self
                .maybe_extend_stub_circuit(netdir, circuit, avoid_target, kind)
                .await?;
            self.ensure_suitable_circuit(&circuit, avoid_target, kind)?;
            return Ok(circuit);
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

        self.ensure_suitable_circuit(&circ, avoid_target, kind)?;

        Ok(HsCircStem { circ, kind })
    }

    /// Return a circuit of the specified `kind`, built from `circuit`.
    async fn maybe_extend_stub_circuit<T>(
        &self,
        netdir: &NetDir,
        circuit: HsCircStem<B::Circ>,
        avoid_target: Option<&T>,
        kind: HsCircStemKind,
    ) -> Result<HsCircStem<B::Circ>>
    where
        T: CircTarget + std::marker::Sync,
    {
        match self.vanguard_mode() {
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            VanguardMode::Full => {
                // NAIVE circuit stubs need to be extended by one hop to become GUARDED stubs
                // if we're using full vanguards.
                self.extend_full_vanguards_circuit(netdir, circuit, avoid_target, kind)
                    .await
            }
            _ => {
                let HsCircStem { circ, kind: _ } = circuit;

                Ok(HsCircStem { circ, kind })
            }
        }
    }

    /// Extend the specified full vanguard circuit if necessary.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    async fn extend_full_vanguards_circuit<T>(
        &self,
        netdir: &NetDir,
        circuit: HsCircStem<B::Circ>,
        avoid_target: Option<&T>,
        kind: HsCircStemKind,
    ) -> Result<HsCircStem<B::Circ>>
    where
        T: CircTarget + std::marker::Sync,
    {
        match (circuit.kind, kind) {
            (HsCircStemKind::Short, HsCircStemKind::Extended) => {
                debug!("Wanted GUARDED circuit, but got NAIVE; extending by 1 hop...");
                let params = CircParameters::default();
                let circ_path = circuit.circ.path_ref();

                // A NAIVE circuit is a 3-hop circuit.
                debug_assert_eq!(circ_path.hops().len(), 3);

                let target_exclusion = if let Some(target) = &avoid_target {
                    RelayExclusion::exclude_identities(
                        target.identities().map(|id| id.to_owned()).collect(),
                    )
                } else {
                    RelayExclusion::no_relays_excluded()
                };
                let hops = circ_path
                    .iter()
                    .flat_map(|hop| hop.as_chan_target())
                    .map(IntoOwnedChanTarget::to_owned)
                    .collect::<Vec<OwnedChanTarget>>();
                let extra_hop = select_middle_for_vanguard_circ(
                    &hops,
                    netdir,
                    &target_exclusion,
                    &mut rand::thread_rng(),
                )?;

                // Since full vanguards are enabled and the circuit we got is NAIVE,
                // we need to extend it by another hop to make it GUARDED before returning it
                let circ = self.extend_circ(circuit, params, extra_hop).await?;

                Ok(HsCircStem { circ, kind })
            }
            (HsCircStemKind::Extended, HsCircStemKind::Short) => {
                Err(internal!("wanted a NAIVE circuit, but got GUARDED?!").into())
            }
            _ => {
                trace!("Wanted {kind} circuit, got {}", circuit.kind);
                // Nothing to do: the circuit stub we got is of the kind we wanted
                Ok(circuit)
            }
        }
    }

    /// Ensure `circ` is compatible with `target`, and has the correct length for its `kind`.
    fn ensure_suitable_circuit<T>(
        &self,
        circ: &Arc<B::Circ>,
        target: Option<&T>,
        kind: HsCircStemKind,
    ) -> StdResult<(), Bug>
    where
        T: CircTarget + std::marker::Sync,
    {
        Self::ensure_circuit_compatible_with_target(circ, target)?;
        self.ensure_circuit_length_valid(circ, kind)?;

        Ok(())
    }

    /// Ensure the specified circuit of type `kind` has the right length.
    fn ensure_circuit_length_valid(
        &self,
        circ: &Arc<B::Circ>,
        kind: HsCircStemKind,
    ) -> StdResult<(), Bug> {
        let circ_path_len = circ.path_ref().n_hops();
        let mode = self.vanguard_mode();

        // TODO(#1457): somehow unify the path length checks
        let expected_len = kind.num_hops(mode)?;

        if circ_path_len != expected_len {
            return Err(internal!(
                "invalid path length for {} {mode}-vanguard circuit (expected {} hops, got {})",
                kind,
                expected_len,
                circ_path_len
            ));
        }

        Ok(())
    }

    /// Ensure `circ` is compatible with `target`.
    ///
    /// Returns an error if either of the last 2 hops of the circuit are the same as `target`,
    /// because:
    ///   * a relay won't let you extend the circuit to itself
    ///   * relays won't let you extend the circuit to their previous hop
    fn ensure_circuit_compatible_with_target<T>(
        circ: &Arc<B::Circ>,
        target: Option<&T>,
    ) -> StdResult<(), Bug>
    where
        T: CircTarget + std::marker::Sync,
    {
        if let Some(target) = target {
            let take_n = 2;
            if let Some(hop) = circ
                .path_ref()
                .hops()
                .iter()
                .rev()
                .take(take_n)
                .flat_map(|hop| hop.as_chan_target())
                .find(|hop| hop.has_any_relay_id_from(target))
            {
                return Err(internal!(
                    "invalid path: circuit target {} appears as one of the last 2 hops (matches hop {})",
                    target.display_relay_ids(),
                    hop.display_relay_ids()
                ));
            }
        }

        Ok(())
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

    /// Returns the current [`VanguardMode`].
    fn vanguard_mode(&self) -> VanguardMode {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "vanguards", feature = "hs-common"))] {
                self
                    .circmgr
                    .mgr
                    .peek_builder()
                    .vanguardmgr()
                    .mode()
            } else {
                VanguardMode::Disabled
            }
        }
    }

    /// Internal implementation for [`HsCircPool::estimate_timeout`].
    pub(crate) fn estimate_timeout(
        &self,
        timeout_action: &timeouts::Action,
    ) -> std::time::Duration {
        self.circmgr.estimate_timeout(timeout_action)
    }
}

/// Return true if we can extend a pre-built circuit `circ` to `target`.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that no hop in the circuit shares a family with
/// `target`.
fn circuit_compatible_with_target<C: AbstractCirc>(
    netdir: &NetDir,
    circ: &HsCircStem<C>,
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

/// Return true if we can extend a pre-built vanguards circuit `circ` to `target`.
///
/// We require that the circuit is open, that it can become the specified
/// kind of [`HsCircStem`], that every hop in the circuit is listed in `netdir`,
/// and that the last two hops are different from the specified target.
fn vanguards_circuit_compatible_with_target<C: AbstractCirc, T>(
    netdir: &NetDir,
    circ: &HsCircStem<C>,
    kind: HsCircStemKind,
    avoid_target: Option<&T>,
) -> bool
where
    T: CircTarget + std::marker::Sync,
{
    if let Some(target) = avoid_target {
        let circ_path = circ.circ.path_ref();
        // The last 2 hops of the circuit must be different from the circuit target, because:
        //   * a relay won't let you extend the circuit to itself
        //   * relays won't let you extend the circuit to their previous hop
        let take_n = 2;
        if circ_path
            .hops()
            .iter()
            .rev()
            .take(take_n)
            .flat_map(|hop| hop.as_chan_target())
            .any(|hop| hop.has_any_relay_id_from(target))
        {
            return false;
        }
    }

    circ.can_become(kind) && circuit_still_useable(netdir, circ, |_relay| true)
}

/// Return true if we can still use a given pre-build circuit.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that `relay_okay` returns true for every hop on the
/// circuit.
fn circuit_still_useable<C, F>(netdir: &NetDir, circ: &HsCircStem<C>, relay_okay: F) -> bool
where
    C: AbstractCirc,
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
async fn launch_hs_circuits_as_needed<B: AbstractCircBuilder<R> + 'static, R: Runtime>(
    pool: Weak<HsCircPoolInner<B, R>>,
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

        if n_to_launch > 0 {
            debug!(
                "launching {} NAIVE  and {} GUARDED circuits",
                circs_to_launch.stub(),
                circs_to_launch.guarded_stub()
            );
        }

        // TODO: refactor this to launch the circuits in parallel
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
                let for_launch = circs_to_launch.for_launch();

                // TODO HS: We should catch panics, here or in launch_hs_unmanaged.
                match pool
                    .circmgr
                    .launch_hs_unmanaged(no_target, &netdir, for_launch.kind())
                    .await
                {
                    Ok(circ) => {
                        let kind = for_launch.kind();
                        let circ = HsCircStem { circ, kind };
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
async fn remove_unusable_circuits<B: AbstractCircBuilder<R> + 'static, R: Runtime>(
    pool: Weak<HsCircPoolInner<B, R>>,
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
    #![allow(clippy::cognitive_complexity)]

    use tor_config::ExplicitOrAuto;
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    use tor_guardmgr::VanguardConfigBuilder;
    use tor_guardmgr::VanguardMode;
    use tor_memquota::ArcMemoryQuotaTrackerExt as _;
    use tor_proto::memquota::ToplevelAccount;
    use tor_rtmock::MockRuntime;

    use super::*;
    use crate::{CircMgrInner, TestConfig};

    /// Create a `CircMgr` with an underlying `VanguardMgr` that runs in the specified `mode`.
    fn circmgr_with_vanguards<R: Runtime>(
        runtime: R,
        mode: VanguardMode,
    ) -> Arc<CircMgrInner<crate::build::CircuitBuilder<R>, R>> {
        let chanmgr = tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &Default::default(),
            tor_chanmgr::Dormancy::Dormant,
            &Default::default(),
            ToplevelAccount::new_noop(),
        );
        let guardmgr = tor_guardmgr::GuardMgr::new(
            runtime.clone(),
            tor_persist::TestingStateMgr::new(),
            &tor_guardmgr::TestConfig::default(),
        )
        .unwrap();

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let vanguard_config = VanguardConfigBuilder::default()
            .mode(ExplicitOrAuto::Explicit(mode))
            .build()
            .unwrap();

        let config = TestConfig {
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            vanguard_config,
            ..Default::default()
        };

        CircMgrInner::new(
            &config,
            tor_persist::TestingStateMgr::new(),
            &runtime,
            Arc::new(chanmgr),
            &guardmgr,
        )
        .unwrap()
        .into()
    }

    // Prevents TROVE-2024-005 (arti#1424)
    #[test]
    fn pool_with_vanguards_disabled() {
        MockRuntime::test_with_various(|runtime| async move {
            let circmgr = circmgr_with_vanguards(runtime, VanguardMode::Disabled);
            let circpool = HsCircPoolInner::new_internal(&circmgr);
            assert!(circpool.vanguard_mode() == VanguardMode::Disabled);
        });
    }

    #[test]
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    fn pool_with_vanguards_enabled() {
        MockRuntime::test_with_various(|runtime| async move {
            for mode in [VanguardMode::Lite, VanguardMode::Full] {
                let circmgr = circmgr_with_vanguards(runtime.clone(), mode);
                let circpool = HsCircPoolInner::new_internal(&circmgr);
                assert!(circpool.vanguard_mode() == mode);
            }
        });
    }
}
