#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

use build::CircuitBuilder;
use mgr::{AbstractCirc, AbstractCircBuilder};
use tor_basic_utils::retry::RetryDelay;
use tor_chanmgr::ChanMgr;
use tor_error::{error_report, warn_report};
use tor_guardmgr::RetireCircuits;
use tor_linkspec::ChanTarget;
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness};
use tor_proto::circuit::{CircParameters, ClientCirc, UniqId};
use tor_rtcompat::Runtime;

#[cfg(any(feature = "specific-relay", feature = "hs-common"))]
use tor_linkspec::IntoOwnedChanTarget;

use futures::task::SpawnExt;
use futures::StreamExt;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

#[cfg(feature = "testing")]
pub use config::test_config::TestConfig;

pub mod build;
mod config;
mod err;
#[cfg(feature = "hs-common")]
pub mod hspool;
mod impls;
pub mod isolation;
mod mgr;
#[cfg(test)]
mod mocks;
pub(crate) mod path;
mod preemptive;
pub mod timeouts;
mod usage;

pub use err::Error;
pub use isolation::IsolationToken;
use tor_guardmgr::fallback::FallbackList;
pub use tor_guardmgr::{ClockSkewEvents, GuardMgrConfig, SkewEstimate};
pub use usage::{TargetPort, TargetPorts};

pub use config::{
    CircMgrConfig, CircuitTiming, CircuitTimingBuilder, PathConfig, PathConfigBuilder,
    PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
};

use crate::isolation::StreamIsolation;
use crate::mgr::CircProvenance;
use crate::preemptive::PreemptiveCircuitPredictor;
use usage::TargetCircUsage;

use safelog::sensitive as sv;
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
pub use tor_guardmgr::{ExternalActivity, FirstHopId};
use tor_persist::StateMgr;
use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};

#[cfg(feature = "hs-common")]
use crate::hspool::HsCircStubKind;
#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::VanguardMgr;

/// A Result type as returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Type alias for dynamic StorageHandle that can handle our timeout state.
type TimeoutStateHandle = tor_persist::DynStorageHandle<timeouts::pareto::ParetoTimeoutState>;

/// Key used to load timeout state information.
const PARETO_TIMEOUT_DATA_KEY: &str = "circuit_timeouts";

/// Represents what we know about the Tor network.
///
/// This can either be a complete directory, or a list of fallbacks.
///
/// Not every DirInfo can be used to build every kind of circuit:
/// if you try to build a path with an inadequate DirInfo, you'll get a
/// NeedConsensus error.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DirInfo<'a> {
    /// A list of fallbacks, for use when we don't know a network directory.
    Fallbacks(&'a FallbackList),
    /// A complete network directory
    Directory(&'a NetDir),
    /// No information: we can only build one-hop paths: and that, only if the
    /// guard manager knows some guards or fallbacks.
    Nothing,
}

impl<'a> From<&'a FallbackList> for DirInfo<'a> {
    fn from(v: &'a FallbackList) -> DirInfo<'a> {
        DirInfo::Fallbacks(v)
    }
}
impl<'a> From<&'a NetDir> for DirInfo<'a> {
    fn from(v: &'a NetDir) -> DirInfo<'a> {
        DirInfo::Directory(v)
    }
}
impl<'a> DirInfo<'a> {
    /// Return a set of circuit parameters for this DirInfo.
    fn circ_params(&self) -> CircParameters {
        use crate::build::circparameters_from_netparameters;
        use tor_netdir::params::NetParameters;
        // We use a common function for both cases here to be sure that
        // we look at the defaults from NetParameters code.
        match self {
            DirInfo::Directory(d) => circparameters_from_netparameters(d.params()),
            _ => circparameters_from_netparameters(&NetParameters::default()),
        }
    }
}

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
///
/// This is a "handle"; clones of it share state.
pub struct CircMgr<R: Runtime>(Arc<CircMgrInner<build::CircuitBuilder<R>, R>>);

impl<R: Runtime> CircMgr<R> {
    /// Construct a new circuit manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `CircMgr::launch_background_tasks`.
    pub fn new<SM, CFG: CircMgrConfig>(
        config: &CFG,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
    ) -> Result<Self>
    where
        SM: tor_persist::StateMgr + Clone + Send + Sync + 'static,
    {
        Ok(Self(Arc::new(CircMgrInner::new(
            config, storage, runtime, chanmgr, guardmgr,
        )?)))
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<ClientCirc>> {
        self.0.get_or_launch_dir(netdir).await
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    ///
    /// If the list of ports is empty, then the chosen circuit will
    /// still end at _some_ exit.
    pub async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>, // TODO: This has to be a NetDir.
        ports: &[TargetPort],
        isolation: StreamIsolation,
        // TODO GEOIP: this cannot be stabilised like this, since Cargo features need to be
        //             additive. The function should be refactored to be builder-like.
        #[cfg(feature = "geoip")] country_code: Option<CountryCode>,
    ) -> Result<Arc<ClientCirc>> {
        self.0
            .get_or_launch_exit(
                netdir,
                ports,
                isolation,
                #[cfg(feature = "geoip")]
                country_code,
            )
            .await
    }

    /// Return a circuit to a specific relay, suitable for using for direct
    /// (one-hop) directory downloads.
    ///
    /// This could be used, for example, to download a descriptor for a bridge.
    #[cfg_attr(docsrs, doc(cfg(feature = "specific-relay")))]
    #[cfg(feature = "specific-relay")]
    pub async fn get_or_launch_dir_specific<T: IntoOwnedChanTarget>(
        &self,
        target: T,
    ) -> Result<Arc<ClientCirc>> {
        self.0.get_or_launch_dir_specific(target).await
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    //
    // NOTE(eta): The ?Sized on D is so we can pass a trait object in.
    pub fn launch_background_tasks<D, S>(
        self: &Arc<Self>,
        runtime: &R,
        dir_provider: &Arc<D>,
        state_mgr: S,
    ) -> Result<Vec<TaskHandle>>
    where
        D: NetDirProvider + 'static + ?Sized,
        S: StateMgr + std::marker::Send + 'static,
    {
        CircMgrInner::launch_background_tasks(&self.0.clone(), runtime, dir_provider, state_mgr)
    }

    /// Return true if `netdir` has enough information to be used for this
    /// circuit manager.
    ///
    /// (This will check whether the netdir is missing any primary guard
    /// microdescriptors)
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        self.0.netdir_is_sufficient(netdir)
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub fn retire_circ(&self, circ_id: &UniqId) {
        self.0.retire_circ(circ_id);
    }

    /// Record that a failure occurred on a circuit with a given guard, in a way
    /// that makes us unwilling to use that guard for future circuits.
    ///
    pub fn note_external_failure(
        &self,
        target: &impl ChanTarget,
        external_failure: ExternalActivity,
    ) {
        self.0.note_external_failure(target, external_failure);
    }

    /// Record that a success occurred on a circuit with a given guard, in a way
    /// that makes us possibly willing to use that guard for future circuits.
    pub fn note_external_success(
        &self,
        target: &impl ChanTarget,
        external_activity: ExternalActivity,
    ) {
        self.0.note_external_success(target, external_activity);
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub fn skew_events(&self) -> ClockSkewEvents {
        self.0.skew_events()
    }

    /// Try to change our configuration settings to `new_config`.
    ///
    /// The actual behavior here will depend on the value of `how`.
    ///
    /// Returns whether any of the circuit pools should be cleared.
    pub fn reconfigure<CFG: CircMgrConfig>(
        &self,
        new_config: &CFG,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<RetireCircuits, tor_config::ReconfigureError> {
        self.0.reconfigure(new_config, how)
    }

    /// Return an estimate-based delay for how long a given
    /// [`Action`](timeouts::Action) should be allowed to complete.
    ///
    /// Note that **you do not need to use this function** in order to get
    /// reasonable timeouts for the circuit-building operations provided by the
    /// `tor-circmgr` crate: those, unless specifically noted, always use these
    /// timeouts to cancel circuit operations that have taken too long.
    ///
    /// Instead, you should only use this function when you need to estimate how
    /// long some _other_ operation should take to complete.  For example, if
    /// you are sending a request over a 3-hop circuit and waiting for a reply,
    /// you might choose to wait for `estimate_timeout(Action::RoundTrip {
    /// length: 3 })`.
    ///
    /// Note also that this function returns a _timeout_ that the operation
    /// should be permitted to complete, not an estimated Duration that the
    /// operation _will_ take to complete. Timeouts are chosen to ensure that
    /// most operations will complete, but very slow ones will not.  So even if
    /// we expect that a circuit will complete in (say) 3 seconds, we might
    /// still allow a timeout of 4.5 seconds, to ensure that most circuits can
    /// complete.
    ///
    /// Estimate-based timeouts may change over time, given observations on the
    /// actual amount of time needed for circuits to complete building.  If not
    /// enough information has been gathered, a reasonable default will be used.
    pub fn estimate_timeout(&self, timeout_action: &timeouts::Action) -> std::time::Duration {
        self.0.estimate_timeout(timeout_action)
    }

    /// Return a reference to the associated CircuitBuilder that this CircMgr
    /// will use to create its circuits.
    #[cfg(feature = "experimental-api")]
    pub fn builder(&self) -> &CircuitBuilder<R> {
        CircMgrInner::builder(&self.0)
    }
}

/// Internal object used to implement CircMgr, which allows for mocking.
#[derive(Clone)]
pub(crate) struct CircMgrInner<B: AbstractCircBuilder<R> + 'static, R: Runtime> {
    /// The underlying circuit manager object that implements our behavior.
    mgr: Arc<mgr::AbstractCircMgr<B, R>>,
    /// A preemptive circuit predictor, for, uh, building circuits preemptively.
    predictor: Arc<Mutex<PreemptiveCircuitPredictor>>,
}

impl<R: Runtime> CircMgrInner<CircuitBuilder<R>, R> {
    /// Construct a new circuit manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `CircMgr::launch_background_tasks`.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn new<SM, CFG: CircMgrConfig>(
        config: &CFG,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
    ) -> Result<Self>
    where
        SM: tor_persist::StateMgr + Clone + Send + Sync + 'static,
    {
        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let vanguardmgr = {
            // TODO(#1382): we need a way of checking if this arti instance
            // is running an onion service or not.
            //
            // Perhaps this information should be provided by CircMgrConfig.
            let has_onion_svc = false;
            VanguardMgr::new(
                config.vanguard_config(),
                runtime.clone(),
                storage.clone(),
                has_onion_svc,
            )?
        };

        let storage_handle = storage.create_handle(PARETO_TIMEOUT_DATA_KEY);

        let builder = build::CircuitBuilder::new(
            runtime.clone(),
            chanmgr,
            config.path_rules().clone(),
            storage_handle,
            guardmgr.clone(),
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            vanguardmgr,
        );

        Ok(Self::new_generic(config, runtime, guardmgr, builder))
    }
}

impl<B: AbstractCircBuilder<R> + 'static, R: Runtime> CircMgrInner<B, R> {
    /// Generic implementation for [`CircMgrInner::new`]
    pub(crate) fn new_generic<CFG: CircMgrConfig>(
        config: &CFG,
        runtime: &R,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
        builder: B,
    ) -> Self {
        let preemptive = Arc::new(Mutex::new(PreemptiveCircuitPredictor::new(
            config.preemptive_circuits().clone(),
        )));

        guardmgr.set_filter(config.path_rules().build_guard_filter());

        let mgr =
            mgr::AbstractCircMgr::new(builder, runtime.clone(), config.circuit_timing().clone());

        CircMgrInner {
            mgr: Arc::new(mgr),
            predictor: preemptive,
        }
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    //
    // NOTE(eta): The ?Sized on D is so we can pass a trait object in.
    pub(crate) fn launch_background_tasks<D, S>(
        self: &Arc<Self>,
        runtime: &R,
        dir_provider: &Arc<D>,
        state_mgr: S,
    ) -> Result<Vec<TaskHandle>>
    where
        D: NetDirProvider + 'static + ?Sized,
        S: StateMgr + std::marker::Send + 'static,
    {
        let mut ret = vec![];

        runtime
            .spawn(Self::keep_circmgr_params_updated(
                dir_provider.events(),
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("circmgr parameter updater", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::update_persistent_state(
                sched,
                Arc::downgrade(self),
                state_mgr,
            ))
            .map_err(|e| Error::from_spawn("persistent state updater", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::continually_launch_timeout_testing_circuits(
                sched,
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("timeout-probe circuit launcher", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::continually_preemptively_build_circuits(
                sched,
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("preemptive circuit launcher", e))?;

        self.mgr
            .peek_builder()
            .guardmgr()
            .install_netdir_provider(&dir_provider.clone().upcast_arc())?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        {
            let () = self
                .mgr
                .peek_builder()
                .vanguardmgr()
                .launch_background_tasks(&dir_provider.clone().upcast_arc())?;
        }

        Ok(ret)
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub(crate) async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<B::Circ>> {
        self.expire_circuits();
        let usage = TargetCircUsage::Dir;
        self.mgr.get_or_launch(&usage, netdir).await.map(|(c, _)| c)
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    ///
    /// If the list of ports is empty, then the chosen circuit will
    /// still end at _some_ exit.
    pub(crate) async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>, // TODO: This has to be a NetDir.
        ports: &[TargetPort],
        isolation: StreamIsolation,
        // TODO GEOIP: this cannot be stabilised like this, since Cargo features need to be
        //             additive. The function should be refactored to be builder-like.
        #[cfg(feature = "geoip")] country_code: Option<CountryCode>,
    ) -> Result<Arc<B::Circ>> {
        self.expire_circuits();
        let time = Instant::now();
        {
            let mut predictive = self.predictor.lock().expect("preemptive lock poisoned");
            if ports.is_empty() {
                predictive.note_usage(None, time);
            } else {
                for port in ports.iter() {
                    predictive.note_usage(Some(*port), time);
                }
            }
        }
        let require_stability = ports.iter().any(|p| {
            self.mgr
                .peek_builder()
                .path_config()
                .long_lived_ports
                .contains(&p.port)
        });
        let ports = ports.iter().map(Clone::clone).collect();
        #[cfg(not(feature = "geoip"))]
        let country_code = None;
        let usage = TargetCircUsage::Exit {
            ports,
            isolation,
            country_code,
            require_stability,
        };
        self.mgr.get_or_launch(&usage, netdir).await.map(|(c, _)| c)
    }

    /// Return a circuit to a specific relay, suitable for using for direct
    /// (one-hop) directory downloads.
    ///
    /// This could be used, for example, to download a descriptor for a bridge.
    #[cfg_attr(docsrs, doc(cfg(feature = "specific-relay")))]
    #[cfg(feature = "specific-relay")]
    pub(crate) async fn get_or_launch_dir_specific<T: IntoOwnedChanTarget>(
        &self,
        target: T,
    ) -> Result<Arc<B::Circ>> {
        self.expire_circuits();
        let usage = TargetCircUsage::DirSpecificTarget(target.to_owned());
        self.mgr
            .get_or_launch(&usage, DirInfo::Nothing)
            .await
            .map(|(c, _)| c)
    }

    /// Try to change our configuration settings to `new_config`.
    ///
    /// The actual behavior here will depend on the value of `how`.
    ///
    /// Returns whether any of the circuit pools should be cleared.
    pub(crate) fn reconfigure<CFG: CircMgrConfig>(
        &self,
        new_config: &CFG,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<RetireCircuits, tor_config::ReconfigureError> {
        let old_path_rules = self.mgr.peek_builder().path_config();
        let predictor = self.predictor.lock().expect("poisoned lock");
        let preemptive_circuits = predictor.config();
        if preemptive_circuits.initial_predicted_ports
            != new_config.preemptive_circuits().initial_predicted_ports
        {
            // This change has no effect, since the list of ports was _initial_.
            how.cannot_change("preemptive_circuits.initial_predicted_ports")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(RetireCircuits::None);
        }

        let retire_because_of_guardmgr =
            self.mgr.peek_builder().guardmgr().reconfigure(new_config)?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let retire_because_of_vanguardmgr = self
            .mgr
            .peek_builder()
            .vanguardmgr()
            .reconfigure(new_config.vanguard_config())?;

        let new_reachable = &new_config.path_rules().reachable_addrs;
        if new_reachable != &old_path_rules.reachable_addrs {
            let filter = new_config.path_rules().build_guard_filter();
            self.mgr.peek_builder().guardmgr().set_filter(filter);
        }

        let discard_all_circuits = !new_config
            .path_rules()
            .at_least_as_permissive_as(&old_path_rules)
            || retire_because_of_guardmgr != tor_guardmgr::RetireCircuits::None;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let discard_all_circuits = discard_all_circuits
            || retire_because_of_vanguardmgr != tor_guardmgr::RetireCircuits::None;

        self.mgr
            .peek_builder()
            .set_path_config(new_config.path_rules().clone());
        self.mgr
            .set_circuit_timing(new_config.circuit_timing().clone());
        predictor.set_config(new_config.preemptive_circuits().clone());

        if discard_all_circuits {
            // TODO(nickm): Someday, we might want to take a more lenient approach, and only
            // retire those circuits that do not conform to the new path rules,
            // or do not conform to the new guard configuration.
            info!("Path configuration has become more restrictive: retiring existing circuits.");
            self.retire_all_circuits();
            return Ok(RetireCircuits::All);
        }
        Ok(RetireCircuits::None)
    }

    /// Whenever a [`DirEvent::NewConsensus`] arrives on `events`, update
    /// `circmgr` with the consensus parameters from `dirmgr`.
    ///
    /// Exit when `events` is closed, or one of `circmgr` or `dirmgr` becomes
    /// dangling.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    async fn keep_circmgr_params_updated<D>(
        mut events: impl futures::Stream<Item = DirEvent> + Unpin,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        use DirEvent::*;
        while let Some(event) = events.next().await {
            if matches!(event, NewConsensus) {
                if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                    if let Ok(netdir) = dm.netdir(Timeliness::Timely) {
                        cm.update_network_parameters(netdir.params());
                    }
                } else {
                    debug!("Circmgr or dirmgr has disappeared; task exiting.");
                    break;
                }
            }
        }
    }

    /// Reconfigure this circuit manager using the latest set of
    /// network parameters.
    fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.mgr.update_network_parameters(p);
        self.mgr.peek_builder().update_network_parameters(p);
    }

    /// Run indefinitely, launching circuits as needed to get a good
    /// estimate for our circuit build timeouts.
    ///
    /// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    async fn continually_launch_timeout_testing_circuits<D>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        while sched.next().await.is_some() {
            if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                if let Ok(netdir) = dm.netdir(Timeliness::Unchecked) {
                    if let Err(e) = cm.launch_timeout_testing_circuit_if_appropriate(&netdir) {
                        warn_report!(e, "Problem launching a timeout testing circuit");
                    }
                    let delay = netdir
                        .params()
                        .cbt_testing_delay
                        .try_into()
                        .expect("Out-of-bounds value from BoundedInt32");

                    drop((cm, dm));
                    sched.fire_in(delay);
                } else {
                    // wait for the provider to announce some event, which will probably be
                    // NewConsensus; this is therefore a decent yardstick for rechecking
                    let _ = dm.events().next().await;
                    sched.fire();
                }
            } else {
                return;
            }
        }
    }

    /// If we need to launch a testing circuit to judge our circuit
    /// build timeouts timeouts, do so.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from
    /// `continually_launch_timeout_testing_circuits`.
    fn launch_timeout_testing_circuit_if_appropriate(&self, netdir: &NetDir) -> Result<()> {
        if !self.mgr.peek_builder().learning_timeouts() {
            return Ok(());
        }
        // We expire any too-old circuits here, so they don't get
        // counted towards max_circs.
        self.expire_circuits();
        let max_circs: u64 = netdir
            .params()
            .cbt_max_open_circuits_for_testing
            .try_into()
            .expect("Out-of-bounds result from BoundedInt32");
        if (self.mgr.n_circs() as u64) < max_circs {
            // Actually launch the circuit!
            let usage = TargetCircUsage::TimeoutTesting;
            let dirinfo = netdir.into();
            let mgr = Arc::clone(&self.mgr);
            debug!("Launching a circuit to test build times.");
            let receiver = mgr.launch_by_usage(&usage, dirinfo)?;
            // We don't actually care when this circuit is done,
            // so it's okay to drop the Receiver without awaiting it.
            drop(receiver);
        }

        Ok(())
    }

    /// Run forever, periodically telling `circmgr` to update its persistent
    /// state.
    ///
    /// Exit when we notice that `circmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    async fn update_persistent_state<S>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        statemgr: S,
    ) where
        S: StateMgr + std::marker::Send,
    {
        while sched.next().await.is_some() {
            if let Some(circmgr) = Weak::upgrade(&circmgr) {
                use tor_persist::LockStatus::*;

                match statemgr.try_lock() {
                    Err(e) => {
                        error_report!(e, "Problem with state lock file");
                        break;
                    }
                    Ok(NewlyAcquired) => {
                        info!("We now own the lock on our state files.");
                        if let Err(e) = circmgr.upgrade_to_owned_persistent_state() {
                            error_report!(e, "Unable to upgrade to owned state files");
                            break;
                        }
                    }
                    Ok(AlreadyHeld) => {
                        if let Err(e) = circmgr.store_persistent_state() {
                            error_report!(e, "Unable to flush circmgr state");
                            break;
                        }
                    }
                    Ok(NoLock) => {
                        if let Err(e) = circmgr.reload_persistent_state() {
                            error_report!(e, "Unable to reload circmgr state");
                            break;
                        }
                    }
                }
            } else {
                debug!("Circmgr has disappeared; task exiting.");
                return;
            }
            // TODO(nickm): This delay is probably too small.
            //
            // Also, we probably don't even want a fixed delay here.  Instead,
            // we should be updating more frequently when the data is volatile
            // or has important info to save, and not at all when there are no
            // changes.
            sched.fire_in(Duration::from_secs(60));
        }

        debug!("State update task exiting (potentially due to handle drop).");
    }

    /// Switch from having an unowned persistent state to having an owned one.
    ///
    /// Requires that we hold the lock on the state files.
    pub(crate) fn upgrade_to_owned_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().upgrade_to_owned_state()?;
        Ok(())
    }

    /// Reload state from the state manager.
    ///
    /// We only call this method if we _don't_ have the lock on the state
    /// files.  If we have the lock, we only want to save.
    pub(crate) fn reload_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().reload_state()?;
        Ok(())
    }

    /// Run indefinitely, launching circuits where the preemptive circuit
    /// predictor thinks it'd be a good idea to have them.
    ///
    /// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    ///
    /// # Note
    ///
    /// This would be better handled entirely within `tor-circmgr`, like
    /// other daemon tasks.
    async fn continually_preemptively_build_circuits<D>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        let base_delay = Duration::from_secs(10);
        let mut retry = RetryDelay::from_duration(base_delay);

        while sched.next().await.is_some() {
            if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                if let Ok(netdir) = dm.netdir(Timeliness::Timely) {
                    let result = cm
                        .launch_circuits_preemptively(DirInfo::Directory(&netdir))
                        .await;

                    let delay = match result {
                        Ok(()) => {
                            retry.reset();
                            base_delay
                        }
                        Err(_) => retry.next_delay(&mut rand::thread_rng()),
                    };

                    sched.fire_in(delay);
                } else {
                    // wait for the provider to announce some event, which will probably be
                    // NewConsensus; this is therefore a decent yardstick for rechecking
                    let _ = dm.events().next().await;
                    sched.fire();
                }
            } else {
                return;
            }
        }
    }

    /// Launch circuits preemptively, using the preemptive circuit predictor's
    /// predictions.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from
    /// `continually_preemptively_build_circuits()`.
    async fn launch_circuits_preemptively(
        &self,
        netdir: DirInfo<'_>,
    ) -> std::result::Result<(), err::PreemptiveCircError> {
        trace!("Checking preemptive circuit predictions.");
        let (circs, threshold) = {
            let path_config = self.mgr.peek_builder().path_config();
            let preemptive = self.predictor.lock().expect("preemptive lock poisoned");
            let threshold = preemptive.config().disable_at_threshold;
            (preemptive.predict(&path_config), threshold)
        };

        if self.mgr.n_circs() >= threshold {
            return Ok(());
        }
        let mut n_created = 0_usize;
        let mut n_errors = 0_usize;

        let futures = circs
            .iter()
            .map(|usage| self.mgr.get_or_launch(usage, netdir));
        let results = futures::future::join_all(futures).await;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok((_, CircProvenance::NewlyCreated)) => {
                    debug!("Preeemptive circuit was created for {:?}", circs[i]);
                    n_created += 1;
                }
                Ok((_, CircProvenance::Preexisting)) => {
                    trace!("Circuit already existed created for {:?}", circs[i]);
                }
                Err(e) => {
                    warn_report!(e, "Failed to build preemptive circuit {:?}", sv(&circs[i]));
                    n_errors += 1;
                }
            }
        }

        if n_created > 0 || n_errors == 0 {
            // Either we successfully made a circuit, or we didn't have any
            // failures while looking for preexisting circuits.  Progress was
            // made, so there's no need to back off.
            Ok(())
        } else {
            // We didn't build any circuits and we hit at least one error:
            // We'll call this unsuccessful.
            Err(err::PreemptiveCircError)
        }
    }

    /// Create and return a new (typically anonymous) circuit for use as an
    /// onion service circuit of type `kind`.
    ///
    /// This circuit is guaranteed not to have been used for any traffic
    /// previously, and it will not be given out for any other requests in the
    /// future unless explicitly re-registered with a circuit manager.
    ///
    /// If `planned_target` is provided, then the circuit will be built so that
    /// it does not share any family members with the provided target.  (The
    /// circuit _will not be_ extended to that target itself!)
    ///
    /// Used to implement onion service clients and services.
    #[cfg(feature = "hs-common")]
    pub(crate) async fn launch_hs_unmanaged<T>(
        &self,
        planned_target: Option<T>,
        dir: &NetDir,
        kind: HsCircStubKind,
    ) -> Result<Arc<B::Circ>>
    where
        T: IntoOwnedChanTarget,
    {
        let usage = TargetCircUsage::HsCircBase {
            compatible_with_target: planned_target.map(IntoOwnedChanTarget::to_owned),
            kind,
        };
        let (_, client_circ) = self.mgr.launch_unmanaged(&usage, dir.into()).await?;
        Ok(client_circ)
    }

    /// Return true if `netdir` has enough information to be used for this
    /// circuit manager.
    ///
    /// (This will check whether the netdir is missing any primary guard
    /// microdescriptors)
    pub(crate) fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        self.mgr
            .peek_builder()
            .guardmgr()
            .netdir_is_sufficient(netdir)
    }

    /// Internal implementation for [`CircMgr::estimate_timeout`].
    pub(crate) fn estimate_timeout(
        &self,
        timeout_action: &timeouts::Action,
    ) -> std::time::Duration {
        let (timeout, _abandon) = self.mgr.peek_builder().estimator().timeouts(timeout_action);
        timeout
    }

    /// Internal implementation for [`CircMgr::builder`].
    pub(crate) fn builder(&self) -> &B {
        self.mgr.peek_builder()
    }

    /// Flush state to the state manager, if there is any unsaved state and
    /// we have the lock.
    ///
    /// Return true if we saved something; false if we didn't have the lock.
    pub(crate) fn store_persistent_state(&self) -> Result<bool> {
        self.mgr.peek_builder().save_state()
    }

    /// Expire every circuit that has been dirty for too long.
    ///
    /// Expired circuits are not closed while they still have users,
    /// but they are no longer given out for new requests.
    fn expire_circuits(&self) {
        // TODO: I would prefer not to call this at every request, but
        // it should be fine for now.  (At some point we may no longer
        // need this, or might not need to call it so often, now that
        // our circuit expiration runs on scheduled timers via
        // spawn_expiration_task.)
        let now = self.mgr.peek_runtime().now();
        self.mgr.expire_circs(now);
    }

    /// Mark every circuit that we have launched so far as unsuitable for
    /// any future requests.  This won't close existing circuits that have
    /// streams attached to them, but it will prevent any future streams from
    /// being attached.
    ///
    /// TODO: we may want to expose this eventually.  If we do, we should
    /// be very clear that you don't want to use it haphazardly.
    pub(crate) fn retire_all_circuits(&self) {
        self.mgr.retire_all_circuits();
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub(crate) fn retire_circ(&self, circ_id: &<B::Circ as AbstractCirc>::Id) {
        let _ = self.mgr.take_circ(circ_id);
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub(crate) fn skew_events(&self) -> ClockSkewEvents {
        self.mgr.peek_builder().guardmgr().skew_events()
    }

    /// Record that a failure occurred on a circuit with a given guard, in a way
    /// that makes us unwilling to use that guard for future circuits.
    ///
    pub(crate) fn note_external_failure(
        &self,
        target: &impl ChanTarget,
        external_failure: ExternalActivity,
    ) {
        self.mgr
            .peek_builder()
            .guardmgr()
            .note_external_failure(target, external_failure);
    }

    /// Record that a success occurred on a circuit with a given guard, in a way
    /// that makes us possibly willing to use that guard for future circuits.
    pub(crate) fn note_external_success(
        &self,
        target: &impl ChanTarget,
        external_activity: ExternalActivity,
    ) {
        self.mgr
            .peek_builder()
            .guardmgr()
            .note_external_success(target, external_activity);
    }
}

impl<B: AbstractCircBuilder<R> + 'static, R: Runtime> Drop for CircMgrInner<B, R> {
    fn drop(&mut self) {
        match self.store_persistent_state() {
            Ok(true) => info!("Flushed persistent state at exit."),
            Ok(false) => debug!("Lock not held; no state to flush."),
            Err(e) => error_report!(e, "Unable to flush state on circuit manager drop"),
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
    use mocks::FakeBuilder;
    use tor_guardmgr::GuardMgr;
    use tor_linkspec::OwnedChanTarget;
    use tor_netdir::testprovider::TestNetDirProvider;
    use tor_persist::TestingStateMgr;

    use super::*;

    #[test]
    fn get_params() {
        use tor_netdir::{MdReceiver, PartialNetDir};
        use tor_netdoc::doc::netstatus::NetParams;
        // If it's just fallbackdir, we get the default parameters.
        let fb = FallbackList::from([]);
        let di: DirInfo<'_> = (&fb).into();

        let p1 = di.circ_params();
        assert!(!p1.extend_by_ed25519_id());
        assert_eq!(p1.initial_send_window(), 1000);

        // Now try with a directory and configured parameters.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network().unwrap();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 100);
        assert!(p2.extend_by_ed25519_id());

        // Now try with a bogus circwindow value.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network().unwrap();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100_000);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 1000); // Not 100_000
        assert!(p2.extend_by_ed25519_id());
    }

    fn make_circmgr<R: Runtime>(runtime: R) -> Arc<CircMgrInner<FakeBuilder<R>, R>> {
        let config = crate::config::test_config::TestConfig::default();
        let statemgr = TestingStateMgr::new();
        let guardmgr =
            GuardMgr::new(runtime.clone(), statemgr.clone(), &config).expect("Create GuardMgr");
        let builder = FakeBuilder::new(
            &runtime,
            statemgr.clone(),
            &tor_guardmgr::TestConfig::default(),
        );
        let circmgr = Arc::new(CircMgrInner::new_generic(
            &config, &runtime, &guardmgr, builder,
        ));
        let netdir = Arc::new(TestNetDirProvider::new());
        CircMgrInner::launch_background_tasks(&circmgr, &runtime, &netdir, statemgr)
            .expect("launch CircMgrInner background tasks");
        circmgr
    }

    #[test]
    #[cfg(feature = "hs-common")]
    fn test_launch_hs_unmanaged() {
        tor_rtmock::MockRuntime::test_with_various(|runtime| async move {
            let circmgr = make_circmgr(runtime.clone());
            let netdir = tor_netdir::testnet::construct_netdir()
                .unwrap_if_sufficient()
                .unwrap();

            let (ret_tx, ret_rx) = tor_async_utils::oneshot::channel();
            runtime.spawn_identified("launch_hs_unamanged", async move {
                ret_tx
                    .send(
                        circmgr
                            .launch_hs_unmanaged::<OwnedChanTarget>(
                                None,
                                &netdir,
                                HsCircStubKind::Short,
                            )
                            .await,
                    )
                    .unwrap();
            });
            runtime.advance_by(Duration::from_millis(60)).await;
            ret_rx.await.unwrap().unwrap();
        });
    }
}
