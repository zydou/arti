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

pub mod config;
pub mod err;
pub mod ipc;

mod managed;

use crate::config::{TransportConfig, TransportOptions};
use crate::err::PtError;
use crate::managed::{PtReactor, PtReactorMessage};
use futures::channel::mpsc::{self, UnboundedSender};
use futures::task::SpawnExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tor_error::error_report;
use tor_linkspec::PtTransportName;
use tor_rtcompat::Runtime;
use tor_socksproto::SocksVersion;
use tracing::warn;
#[cfg(feature = "tor-channel-factory")]
use {
    async_trait::async_trait,
    tor_async_utils::oneshot,
    tor_chanmgr::{
        builder::ChanBuilder,
        factory::{AbstractPtError, ChannelFactory},
        transport::ExternalProxyPlugin,
    },
    tracing::{info, trace},
};

/// Shared mutable state between the `PtReactor` and `PtMgr`.
#[derive(Default, Debug)]
struct PtSharedState {
    /// Connection information for pluggable transports from currently running binaries.
    ///
    /// Unmanaged pluggable transports are not included in this map.
    managed_cmethods: HashMap<PtTransportName, PtClientMethod>,
    /// Current configured set of pluggable transports.
    configured: HashMap<PtTransportName, TransportOptions>,
}

/// A pluggable transport manager knows how to make different
/// kinds of connections to the Tor network, for censorship avoidance.
pub struct PtMgr<R> {
    /// An underlying `Runtime`, used to spawn background tasks.
    #[allow(dead_code)]
    runtime: R,
    /// State for this PtMgr.
    state: Arc<RwLock<PtSharedState>>,
    /// PtReactor channel.
    tx: UnboundedSender<PtReactorMessage>,
}

impl<R: Runtime> PtMgr<R> {
    /// Transform the config into a more useful representation indexed by transport name.
    fn transform_config(
        binaries: Vec<TransportConfig>,
    ) -> Result<HashMap<PtTransportName, TransportOptions>, tor_error::Bug> {
        let mut ret = HashMap::new();
        // FIXME(eta): You can currently specify overlapping protocols, and it'll
        //             just use the last transport specified.
        //             I attempted to fix this, but decided I didn't want to stare into the list
        //             builder macro void after trying it for 15 minutes.
        for thing in binaries {
            for tn in thing.protocols.iter() {
                ret.insert(tn.clone(), thing.clone().try_into()?);
            }
        }
        Ok(ret)
    }

    /// Create a new PtMgr.
    // TODO: maybe don't have the Vec directly exposed?
    pub fn new(
        transports: Vec<TransportConfig>,
        state_dir: PathBuf,
        rt: R,
    ) -> Result<Self, PtError> {
        let state = PtSharedState {
            managed_cmethods: Default::default(),
            configured: Self::transform_config(transports)?,
        };
        let state = Arc::new(RwLock::new(state));
        let (tx, rx) = mpsc::unbounded();

        let mut reactor = PtReactor::new(rt.clone(), state.clone(), rx, state_dir);
        rt.spawn(async move {
            loop {
                match reactor.run_one_step().await {
                    Ok(true) => return,
                    Ok(false) => {}
                    Err(e) => {
                        error_report!(e, "PtReactor failed");
                        return;
                    }
                }
            }
        })
        .map_err(|e| PtError::Spawn { cause: Arc::new(e) })?;

        Ok(Self {
            runtime: rt,
            state,
            tx,
        })
    }

    /// Reload the configuration
    pub fn reconfigure(
        &self,
        how: tor_config::Reconfigure,
        transports: Vec<TransportConfig>,
    ) -> Result<(), tor_config::ReconfigureError> {
        let configured = Self::transform_config(transports)?;
        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }
        {
            let mut inner = self.state.write().expect("ptmgr poisoned");
            inner.configured = configured;
        }
        // We don't have any way of propagating this sanely; the caller will find out the reactor
        // has died later on anyway.
        let _ = self.tx.unbounded_send(PtReactorMessage::Reconfigured);
        Ok(())
    }

    /// Given a transport name, return a method that we can use to contact that transport.
    ///
    /// May have to launch a managed transport as needed.
    ///
    /// Returns Ok(None) if no such transport exists.
    #[cfg(feature = "tor-channel-factory")]
    async fn get_cmethod_for_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<Option<PtClientMethod>, PtError> {
        // NOTE(eta): This is using a RwLock inside async code (but not across an await point).
        //            Arguably this is fine since it's just a small read, and nothing should ever
        //            hold this lock for very long.
        let (cmethod, configured) = {
            let inner = self.state.read().expect("ptmgr poisoned");
            let cfg = inner.configured.get(transport);
            if let Some(TransportOptions::Unmanaged(cfg)) = cfg {
                // We have a unmanaged transport; that was easy.
                (Some(cfg.cmethod()), true)
            } else {
                let cmethod = inner.managed_cmethods.get(transport).cloned();
                let configured = cmethod.is_some() || cfg.is_some();
                (cmethod, configured)
            }
        };

        match (cmethod, configured) {
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
            (None, true) => {
                // A configured-but-not-running cmethod.
                Ok(Some(self.spawn_transport(transport).await?))
            }
            (None, false) => {
                trace!(
                    "Got a request for transport {}, which is not configured.",
                    transport
                );
                Ok(None)
            }
            (Some(cmethod), _) => {
                trace!(
                    "Found configured transport {} accessible via {:?}",
                    transport,
                    cmethod
                );
                Ok(Some(cmethod))
            }
        }
    }

    /// Communicate with the PT reactor to launch a managed transport.
    #[cfg(feature = "tor-channel-factory")]
    async fn spawn_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<PtClientMethod, PtError> {
        // Tell the reactor to spawn the PT, and wait for it.
        // (The reactor will handle coalescing multiple requests.)
        info!("Got a request for transport {transport}, which is not currently running. Launching it.");

        let (tx, rx) = oneshot::channel();
        self.tx
            .unbounded_send(PtReactorMessage::Spawn {
                pt: transport.clone(),
                result: tx,
            })
            .map_err(|_| {
                PtError::Internal(tor_error::internal!("PT reactor closed unexpectedly"))
            })?;

        let method = match rx.await {
            Err(_) => {
                return Err(PtError::Internal(tor_error::internal!(
                    "PT reactor closed unexpectedly"
                )));
            }
            Ok(Err(e)) => {
                warn!("PT for {transport} failed to launch: {e}");
                return Err(e);
            }
            Ok(Ok(method)) => method,
        };

        info!("Successfully launched PT for {transport} at {method:?}.");
        Ok(method)
    }
}

/// A SOCKS endpoint to connect through a pluggable transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtClientMethod {
    /// The SOCKS protocol version to use.
    pub(crate) kind: SocksVersion,
    /// The socket address to connect to.
    pub(crate) endpoint: SocketAddr,
}

impl PtClientMethod {
    /// Get the SOCKS protocol version to use.
    pub fn kind(&self) -> SocksVersion {
        self.kind
    }

    /// Get the socket address to connect to.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

#[cfg(feature = "tor-channel-factory")]
#[async_trait]
impl<R: Runtime> tor_chanmgr::factory::AbstractPtMgr for PtMgr<R> {
    async fn factory_for_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<Option<Arc<dyn ChannelFactory + Send + Sync>>, Arc<dyn AbstractPtError>> {
        let cmethod = match self.get_cmethod_for_transport(transport).await {
            Err(e) => return Err(Arc::new(e)),
            Ok(None) => return Ok(None),
            Ok(Some(m)) => m,
        };

        let proxy = ExternalProxyPlugin::new(self.runtime.clone(), cmethod.endpoint, cmethod.kind);
        let factory = ChanBuilder::new(self.runtime.clone(), proxy);
        // FIXME(eta): Should we cache constructed factories? If no: should this still be an Arc?
        // FIXME(eta): Should we track what transports are live somehow, so we can shut them down?
        Ok(Some(Arc::new(factory)))
    }
}
