#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

#![allow(dead_code)] // FIXME TODO pt-client remove after implementing reactor.

pub mod config;
pub mod err;
pub mod ipc;

use crate::config::ManagedTransportConfig;
use crate::err::PtError;
use crate::ipc::{PluggableTransport, PtClientMethod, PtParameters};
use crate::mpsc::Receiver;
use futures::channel::mpsc::{self, UnboundedSender};
use futures::channel::oneshot;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tempfile::TempDir;
use tor_linkspec::PtTransportName;
use tor_rtcompat::Runtime;
use tracing::warn;
#[cfg(feature = "tor-channel-factory")]
use {
    async_trait::async_trait,
    tor_chanmgr::{
        builder::ChanBuilder,
        factory::{AbstractPtError, ChannelFactory},
        transport::ExternalProxyPlugin,
    },
};

/// Shared mutable state between the `PtReactor` and `PtMgr`.
#[derive(Default, Debug)]
struct PtSharedState {
    /// Connection information for pluggable transports from currently running binaries.
    cmethods: HashMap<PtTransportName, PtClientMethod>,
    /// Current configured set of pluggable transport binaries.
    configured: HashMap<PtTransportName, ManagedTransportConfig>,
}

/// A message to the `PtReactor`.
enum PtReactorMessage {
    /// Notify the reactor that the currently configured set of PTs has changed.
    Reconfigured,
    /// Ask the reactor to spawn a pluggable transport binary.
    Spawn {
        /// Spawn a binary to provide this PT.
        pt: PtTransportName,
        /// Notify the result via this channel.
        result: oneshot::Sender<err::Result<PtClientMethod>>,
    },
}

/// Background reactor to handle managing pluggable transport binaries.
struct PtReactor<R> {
    /// Runtime.
    rt: R,
    /// Currently running pluggable transport binaries.
    running: Vec<PluggableTransport>,
    /// State for the corresponding PtMgr.
    state: Arc<RwLock<PtSharedState>>,
    /// PtMgr channel.
    /// (Unbounded so that we can reconfigure without blocking: we're unlikely to have the reactor
    /// get behind.)
    rx: Receiver<PtReactorMessage>,
}

impl<R: Runtime> PtReactor<R> {
    /// XXX
    async fn run_one_step(&mut self) -> err::Result<()> {
        todo!()
    }
}

/// A pluggable transport manager knows how to make different
/// kinds of connections to the Tor network, for censorship avoidance.
///
/// Currently, we only support two kinds of pluggable transports: Those
/// configured in a PtConfig object, and those added with PtMgr::register.
pub struct PtMgr<R> {
    /// An underlying `Runtime`, used to spawn background tasks.
    #[allow(dead_code)]
    runtime: R,
    /// State for this PtMgr.
    state: Arc<RwLock<PtSharedState>>,
    /// PtReactor channel.
    tx: UnboundedSender<PtReactorMessage>,
    /// Temporary directory to store PT state in.
    //
    // FIXME(eta): This should be configurable.
    //
    // TODO pt-client: There should be one of these per PT, if possible.
    state_dir: TempDir,
}

impl<R: Runtime> PtMgr<R> {
    /// Transform the config into a more useful representation indexed by transport name.
    fn transform_config(
        binaries: Vec<ManagedTransportConfig>,
    ) -> HashMap<PtTransportName, ManagedTransportConfig> {
        let mut ret = HashMap::new();
        // FIXME(eta): You can currently specify overlapping protocols in your binaries, and it'll
        //             just use the last binary specified.
        //             I attempted to fix this, but decided I didn't want to stare into the list
        //             builder macro void after trying it for 15 minutes.
        for thing in binaries {
            for tn in thing.protocols.iter() {
                ret.insert(tn.clone(), thing.clone());
            }
        }
        ret
    }

    /// Create a new PtMgr.
    // TODO pt-client: maybe don't have the Vec directly exposed?
    pub fn new(transports: Vec<ManagedTransportConfig>, rt: R) -> Result<Self, PtError> {
        let state = PtSharedState {
            cmethods: Default::default(),
            configured: Self::transform_config(transports),
        };
        let state = Arc::new(RwLock::new(state));
        let (tx, _) = mpsc::unbounded();

        Ok(Self {
            runtime: rt,
            state,
            tx,
            state_dir: TempDir::new().map_err(|e| PtError::TempdirCreateFailed(Arc::new(e)))?,
        })
    }

    /// Reload the configuration
    pub fn reconfigure(
        &mut self,
        transports: Vec<ManagedTransportConfig>,
    ) -> Result<(), tor_config::ReconfigureError> {
        {
            let mut inner = self.state.write().expect("ptmgr poisoned");
            inner.configured = Self::transform_config(transports);
        }
        // We don't have any way of propagating this sanely; the caller will find out the reactor
        // has died later on anyway.
        let _ = self.tx.unbounded_send(PtReactorMessage::Reconfigured);
        Ok(())
    }
}

/// Spawn a `PluggableTransport` using a `ManagedTransportConfig`.
async fn spawn_from_config<R: Runtime>(
    rt: R,
    state_dir: PathBuf,
    cfg: ManagedTransportConfig,
) -> Result<PluggableTransport, PtError> {
    // FIXME(eta): make the rest of these parameters configurable
    let pt_params = PtParameters::builder()
        .state_location(state_dir)
        .transports(cfg.protocols)
        .build()
        .expect("PtParameters constructed incorrectly");

    // FIXME(eta): I really think this expansion should happen at builder validation time...
    let path = cfg.path.path().map_err(|e| PtError::PathExpansionFailed {
        path: cfg.path,
        error: e,
    })?;
    let mut pt = PluggableTransport::new(path, cfg.arguments, pt_params);
    pt.launch(rt).await?;
    Ok(pt)
}

#[cfg(feature = "tor-channel-factory")]
#[async_trait]
impl<R: Runtime> tor_chanmgr::factory::AbstractPtMgr for PtMgr<R> {
    // There is going to be a lot happening "under the hood" here.
    //
    // When we are asked to get a ChannelFactory for a given
    // connection, we will need to:
    //    - launch the binary for that transport if it is not already running*.
    //    - If we launched the binary, talk to it and see which ports it
    //      is listening on.
    //    - Return a ChannelFactory that connects via one of those ports,
    //      using the appropriate version of SOCKS, passing K=V parameters
    //      encoded properly.
    //
    // * As in other managers, we'll need to avoid trying to launch the same
    //   transport twice if we get two concurrent requests.
    //
    // Later if the binary crashes, we should detect that.  We should relaunch
    // it on demand.
    //
    // On reconfigure, we should shut down any no-longer-used transports.
    //
    // Maybe, we should shut down transports that haven't been used
    // for a long time.
    async fn factory_for_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<Option<Arc<dyn ChannelFactory + Send + Sync>>, Arc<dyn AbstractPtError>> {
        // NOTE(eta): This is using a RwLock inside async code (but not across an await point).
        //            Arguably this is fine since it's just a small read, and nothing should ever
        //            hold this lock for very long.
        let (mut cmethod, configured) = {
            let inner = self.state.read().expect("ptmgr poisoned");
            let cmethod = inner.cmethods.get(transport).copied();
            let configured = cmethod.is_some() || inner.configured.get(transport).is_some();
            (cmethod, configured)
        };
        if cmethod.is_none() {
            if configured {
                // Tell the reactor to spawn the PT, and wait for it.
                // (The reactor will handle coalescing multiple requests.)
                let (tx, rx) = oneshot::channel();
                self.tx
                    .unbounded_send(PtReactorMessage::Spawn {
                        pt: transport.clone(),
                        result: tx,
                    })
                    .map_err(|_| {
                        Arc::new(PtError::Internal(tor_error::internal!(
                            "PT reactor closed unexpectedly"
                        ))) as Arc<dyn AbstractPtError>
                    })?;
                cmethod = Some(
                    // NOTE(eta): Could be improved with result flattening.
                    rx.await
                        .map_err(|_| {
                            Arc::new(PtError::Internal(tor_error::internal!(
                                "PT reactor closed unexpectedly"
                            ))) as Arc<dyn AbstractPtError>
                        })?
                        .map_err(|x| Arc::new(x) as Arc<dyn AbstractPtError>)?,
                );
            } else {
                return Ok(None);
            }
        }
        let cmethod = cmethod.expect("impossible");
        let proxy = ExternalProxyPlugin::new(self.runtime.clone(), cmethod.endpoint, cmethod.kind);
        let factory = ChanBuilder::new(self.runtime.clone(), proxy);
        // FIXME(eta): Should we cache constructed factories? If no: should this still be an Arc?
        // FIXME(eta): Should we track what transports are live somehow, so we can shut them down?
        Ok(Some(Arc::new(factory)))
    }
}
