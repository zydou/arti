//! `tor-circmgr`: circuits through the Tor network on demand.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a circuit is an encrypted multi-hop tunnel over multiple
//! relays.  This crate's purpose, long-term, is to manage a set of
//! circuits for a client.  It should construct circuits in response
//! to a client's needs, and preemptively construct circuits so as to
//! anticipate those needs.  If a client request can be satisfied with
//! an existing circuit, it should return that circuit instead of
//! constructing a new one.
//!
//! # Limitations
//!
//! But for now, this `tor-circmgr` code is extremely preliminary; its
//! data structures are all pretty bad, and it's likely that the API
//! is wrong too.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackDir, NetDir};
use tor_proto::circuit::{CircParameters, ClientCirc, UniqId};
use tor_rtcompat::Runtime;

use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, error, info, warn};

pub mod build;
mod config;
mod err;
mod impls;
mod mgr;
pub mod path;
mod preemptive;
mod timeouts;
mod usage;

pub use err::Error;
pub use usage::{IsolationToken, StreamIsolation, StreamIsolationBuilder, TargetPort, TargetPorts};

pub use config::{
    CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
    PathConfigBuilder, PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
};

use crate::preemptive::PreemptiveCircuitPredictor;
use usage::TargetCircUsage;

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
    Fallbacks(&'a [FallbackDir]),
    /// A complete network directory
    Directory(&'a NetDir),
}

impl<'a> From<&'a [FallbackDir]> for DirInfo<'a> {
    fn from(v: &'a [FallbackDir]) -> DirInfo<'a> {
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
        use tor_netdir::params::NetParameters;
        /// Extract a CircParameters from the NetParameters from a
        /// consensus.  We use a common function for both cases here
        /// to be sure that we look at the defaults from NetParameters
        /// code.
        fn from_netparams(inp: &NetParameters) -> CircParameters {
            let mut p = CircParameters::default();
            if let Err(e) = p.set_initial_send_window(inp.circuit_window.get() as u16) {
                warn!("Invalid parameter in directory: {}", e);
            }
            p.set_extend_by_ed25519_id(inp.extend_by_ed25519_id.into());
            p
        }

        match self {
            DirInfo::Fallbacks(_) => from_netparams(&NetParameters::default()),
            DirInfo::Directory(d) => from_netparams(d.params()),
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
#[derive(Clone)]
pub struct CircMgr<R: Runtime> {
    /// The underlying circuit manager object that implements our behavior.
    mgr: Arc<mgr::AbstractCircMgr<build::CircuitBuilder<R>, R>>,
    /// A preemptive circuit predictor, for, uh, building circuits preemptively.
    predictor: Arc<Mutex<PreemptiveCircuitPredictor>>,
}

impl<R: Runtime> CircMgr<R> {
    /// Construct a new circuit manager.
    pub fn new<SM>(
        config: CircMgrConfig,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
    ) -> Result<Arc<Self>>
    where
        SM: tor_persist::StateMgr + Send + Sync + 'static,
    {
        let CircMgrConfig {
            path_rules,
            circuit_timing,
            preemptive_circuits,
        } = config;

        let preemptive = Arc::new(Mutex::new(PreemptiveCircuitPredictor::new(
            preemptive_circuits,
        )));

        let guardmgr = tor_guardmgr::GuardMgr::new(runtime.clone(), storage.clone())?;

        let storage_handle = storage.create_handle(PARETO_TIMEOUT_DATA_KEY);

        let builder = build::CircuitBuilder::new(
            runtime.clone(),
            chanmgr,
            path_rules,
            storage_handle,
            guardmgr,
        );
        let mgr = mgr::AbstractCircMgr::new(builder, runtime.clone(), circuit_timing);
        let circmgr = Arc::new(CircMgr {
            mgr: Arc::new(mgr),
            predictor: preemptive,
        });

        Ok(circmgr)
    }

    /// Try to change our configuration settings to `new_config`.
    ///
    /// The actual behavior here will depend on the value of `how`.
    pub fn reconfigure(
        &self,
        new_config: &CircMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        let old_path_rules = self.mgr.peek_builder().path_config();
        let predictor = self.predictor.lock().expect("poisoned lock");
        let preemptive_circuits = predictor.config();
        if preemptive_circuits.initial_predicted_ports
            != new_config.preemptive_circuits.initial_predicted_ports
        {
            // This change has no effect, since the list of ports was _initial_.
            how.cannot_change("preemptive_circuits.initial_predicted_ports")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        let discard_circuits = !new_config
            .path_rules
            .at_least_as_permissive_as(&old_path_rules);

        self.mgr
            .peek_builder()
            .set_path_config(new_config.path_rules.clone());
        self.mgr
            .set_circuit_timing(new_config.circuit_timing.clone());
        predictor.set_config(new_config.preemptive_circuits.clone());

        if discard_circuits {
            // TODO(nickm): Someday, we might want to take a more lenient approach, and only
            // retire those circuits that do not conform to the new path rules.
            info!("Path configuration has become more restrictive: retiring existing circuits.");
            self.retire_all_circuits();
        }
        Ok(())
    }

    /// Reload state from the state manager.
    ///
    /// We only call this method if we _don't_ have the lock on the state
    /// files.  If we have the lock, we only want to save.
    pub fn reload_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().reload_state()?;
        Ok(())
    }

    /// Switch from having an unowned persistent state to having an owned one.
    ///
    /// Requires that we hold the lock on the state files.
    pub fn upgrade_to_owned_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().upgrade_to_owned_state()?;
        Ok(())
    }

    /// Flush state to the state manager, if there is any unsaved state and
    /// we have the lock.
    pub fn store_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().save_state()?;
        Ok(())
    }

    /// Reconfigure this circuit manager using the latest set of
    /// network parameters.
    ///
    /// (NOTE: for now, this only affects circuit timeout estimation.)
    pub fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.mgr.update_network_parameters(p);
        self.mgr.peek_builder().update_network_parameters(p);
    }

    /// Return true if `netdir` has enough information to be used for this
    /// circuit manager.
    ///
    /// (This will check whether the netdir is missing any primary guard
    /// microdescriptors)
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        self.mgr
            .peek_builder()
            .guardmgr()
            .netdir_is_sufficient(netdir)
    }

    /// Reconfigure this circuit manager using the latest network directory.
    ///
    /// This should be called on _any_ change to the network, as opposed to
    /// [`CircMgr::update_network_parameters`], which should only be
    /// called when the parameters change.
    pub fn update_network(&self, netdir: &NetDir) {
        self.mgr.peek_builder().guardmgr().update_network(netdir);
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<ClientCirc> {
        self.expire_circuits();
        let usage = TargetCircUsage::Dir;
        self.mgr.get_or_launch(&usage, netdir).await
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
    ) -> Result<ClientCirc> {
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
        let ports = ports.iter().map(Clone::clone).collect();
        let usage = TargetCircUsage::Exit { ports, isolation };
        self.mgr.get_or_launch(&usage, netdir).await
    }

    /// Launch circuits preemptively, using the preemptive circuit predictor's predictions.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from the
    /// `arti-client` crate, based on timings from the network
    /// parameters. As with `launch_timeout_testing_circuit_if_appropriate`, this
    /// should ideally be refactored to be internal to this crate, and not be a
    /// public API here.
    pub async fn launch_circuits_preemptively(&self, netdir: DirInfo<'_>) {
        debug!("Checking preemptive circuit predictions.");
        let (circs, threshold) = {
            let preemptive = self.predictor.lock().expect("preemptive lock poisoned");
            let threshold = preemptive.config().disable_at_threshold;
            (preemptive.predict(), threshold)
        };

        if self.mgr.n_circs() >= threshold {
            return;
        }

        let futures = circs
            .iter()
            .map(|usage| self.mgr.get_or_launch(usage, netdir));
        let results = futures::future::join_all(futures).await;
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(_) => debug!("Circuit exists (or was created) for {:?}", circs[i]),
                Err(e) => warn!("Failed to build preemptive circuit {:?}: {}", circs[i], e),
            }
        }
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub fn retire_circ(&self, circ_id: &UniqId) {
        let _ = self.mgr.take_circ(circ_id);
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

    /// Expire every circuit that has been dirty for too long.
    ///
    /// Expired circuits are not closed while they still have users,
    /// but they are no longer given out for new requests.
    fn expire_circuits(&self) {
        // TODO: I would prefer not to call this at every request, but
        // it should be fine for now.  (At some point we may no longer
        // need this, or might not need to call it so often, now that
        // our circuit expiration runs on scheduld timers via
        // spawn_expiration_task.)
        let now = self.mgr.peek_runtime().now();
        self.mgr.expire_circs(now);
    }

    /// If we need to launch a testing circuit to judge our circuit
    /// build timeouts timeouts, do so.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from the
    /// `arti-client` crate, based on timings from the network
    /// parameters.  Please don't invoke it on your own; I hope we can
    /// have this API go away in the future.
    ///
    /// I would much prefer to have this _not_ be a public API, and
    /// instead have it be a daemon task.  The trouble is that it
    /// needs to get a NetDir as input, and that isn't possible with
    /// the current CircMgr design.  See
    /// [arti#161](https://gitlab.torproject.org/tpo/core/arti/-/issues/161).
    pub fn launch_timeout_testing_circuit_if_appropriate(&self, netdir: &NetDir) -> Result<()> {
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
            let _ = mgr.launch_by_usage(&usage, dirinfo)?;
        }

        Ok(())
    }
}

impl<R: Runtime> Drop for CircMgr<R> {
    fn drop(&mut self) {
        match self.store_persistent_state() {
            Ok(()) => info!("Flushed persistent state at exit."),
            Err(Error::State(tor_persist::Error::NoLock)) => {
                debug!("Lock not held; no state to flush.");
            }
            Err(e) => error!("Unable to flush state on circuit manager drop: {}", e),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Helper type used to help type inference.
    pub(crate) type OptDummyGuardMgr<'a> =
        Option<&'a tor_guardmgr::GuardMgr<tor_rtcompat::tokio::TokioNativeTlsRuntime>>;

    #[test]
    fn get_params() {
        use tor_netdir::{MdReceiver, PartialNetDir};
        use tor_netdoc::doc::netstatus::NetParams;
        // If it's just fallbackdir, we get the default parameters.
        let di: DirInfo<'_> = (&[][..]).into();

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
}
