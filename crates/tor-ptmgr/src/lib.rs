#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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

use crate::config::TransportConfig;
use crate::err::PtError;
use crate::ipc::{
    sealed::PluggableTransportPrivate, PluggableClientTransport, PluggableTransport,
    PtClientMethod, PtClientParameters, PtCommonParameters,
};
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::stream::FuturesUnordered;
use futures::task::SpawnExt;
use futures::{select, FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tor_async_utils::oneshot;
use tor_error::{error_report, internal};
use tor_linkspec::PtTransportName;
use tor_rtcompat::Runtime;
use tracing::{debug, info, trace, warn};
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
    ///
    /// Unmanaged pluggable transports are not included in this map.
    managed_cmethods: HashMap<PtTransportName, PtClientMethod>,
    /// Current configured set of pluggable transports.
    configured: HashMap<PtTransportName, TransportConfig>,
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

/// The result of a spawn attempt: the list of transports the spawned binary covers, and the result.
type SpawnResult = (Vec<PtTransportName>, err::Result<PluggableClientTransport>);

/// Background reactor to handle managing pluggable transport binaries.
struct PtReactor<R> {
    /// Runtime.
    rt: R,
    /// Currently running pluggable transport binaries.
    running: Vec<PluggableClientTransport>,
    /// A map of asked-for transports.
    ///
    /// If a transport name has an entry, we will append any additional requests for that entry.
    /// If no entry is present, we will start a request.
    requests: HashMap<PtTransportName, Vec<oneshot::Sender<err::Result<PtClientMethod>>>>,
    /// FuturesUnordered that spawned tasks get pushed on to.
    ///
    /// WARNING: This MUST always contain one "will never resolve" future!
    spawning: FuturesUnordered<Pin<Box<dyn Future<Output = SpawnResult> + Send>>>,
    /// State for the corresponding PtMgr.
    state: Arc<RwLock<PtSharedState>>,
    /// PtMgr channel.
    /// (Unbounded so that we can reconfigure without blocking: we're unlikely to have the reactor
    /// get behind.)
    rx: UnboundedReceiver<PtReactorMessage>,
    /// State directory.
    state_dir: PathBuf,
}

impl<R: Runtime> PtReactor<R> {
    /// Make a new reactor.
    fn new(
        rt: R,
        state: Arc<RwLock<PtSharedState>>,
        rx: UnboundedReceiver<PtReactorMessage>,
        state_dir: PathBuf,
    ) -> Self {
        let spawning = FuturesUnordered::new();
        spawning.push(Box::pin(futures::future::pending::<SpawnResult>())
            as Pin<Box<dyn Future<Output = _> + Send>>);
        Self {
            rt,
            running: vec![],
            requests: Default::default(),
            spawning,
            state,
            rx,
            state_dir,
        }
    }

    /// Called when a spawn request completes.
    #[allow(clippy::needless_pass_by_value)]
    fn handle_spawned(
        &mut self,
        covers: Vec<PtTransportName>,
        result: err::Result<PluggableClientTransport>,
    ) {
        match result {
            Err(e) => {
                warn!("Spawning PT for {:?} failed: {}", covers, e);
                // Go and tell all the transports about the bad news.
                let senders = covers
                    .iter()
                    .flat_map(|x| self.requests.remove(x))
                    .flatten();
                for sender in senders {
                    // We don't really care if the sender went away.
                    let _ = sender.send(Err(e.clone()));
                }
            }
            Ok(pt) => {
                let mut state = self.state.write().expect("ptmgr state poisoned");
                for (transport, method) in pt.transport_methods() {
                    state
                        .managed_cmethods
                        .insert(transport.clone(), method.clone());
                    for sender in self.requests.remove(transport).into_iter().flatten() {
                        let _ = sender.send(Ok(method.clone()));
                    }
                }

                let requested: HashSet<_> = covers.iter().collect();
                let found: HashSet<_> = pt.transport_methods().iter().map(|(t, _)| t).collect();
                if requested != found {
                    warn!("Bug: PT {} succeeded, but did not give the same transports we asked for. ({:?} vs {:?})",
                          pt.identifier(), found, requested);
                }
                self.running.push(pt);
            }
        }
    }

    /// Called to remove a pluggable transport from the shared state.
    fn remove_pt(&self, pt: PluggableClientTransport) {
        let mut state = self.state.write().expect("ptmgr state poisoned");
        for transport in pt.transport_methods().keys() {
            state.managed_cmethods.remove(transport);
        }
        // to satisfy clippy, and make it clear that this is a desired side-effect: doing this
        // shuts down the PT (asynchronously).
        drop(pt);
    }

    /// Run one step of the reactor. Returns true if the reactor should terminate.
    async fn run_one_step(&mut self) -> err::Result<bool> {
        use futures::future::Either;

        // FIXME(eta): This allocates a lot, which is technically unnecessary but requires careful
        //             engineering to get right. It's not really in the hot path, at least.
        let mut all_next_messages = self
            .running
            .iter_mut()
            // We could avoid the Box, but that'd require using unsafe to replicate what tokio::pin!
            // does under the hood.
            .map(|pt| Box::pin(pt.next_message()))
            .collect::<Vec<_>>();

        // We can't construct a select_all if all_next_messages is empty.
        let mut next_message = if all_next_messages.is_empty() {
            Either::Left(futures::future::pending())
        } else {
            Either::Right(futures::future::select_all(all_next_messages.iter_mut()).fuse())
        };

        select! {
            (result, idx, _) = next_message => {
                drop(all_next_messages); // no idea why NLL doesn't just infer this but sure

                match result {
                    Ok(m) => {
                        // FIXME(eta): We should forward the Status messages onto API consumers.
                        debug!("PT {} message: {:?}", self.running[idx].identifier(), m);
                    },
                    Err(e) => {
                        warn!("PT {} quit: {:?}", self.running[idx].identifier(), e);
                        let pt = self.running.remove(idx);
                        self.remove_pt(pt);
                    }
                }
            },
            spawn_result = self.spawning.next() => {
                drop(all_next_messages);
                // See the Warning in this field's documentation.
                let (covers, result) = spawn_result.expect("self.spawning should never dry up");
                self.handle_spawned(covers, result);
            }
            internal = self.rx.next() => {
                drop(all_next_messages);

                match internal {
                    Some(PtReactorMessage::Reconfigured) => {},
                    Some(PtReactorMessage::Spawn { pt, result }) => {
                        // Make sure we don't already have a running request.
                        if let Some(requests) = self.requests.get_mut(&pt) {
                            requests.push(result);
                            return Ok(false);
                        }
                        // Make sure we don't already have a binary for this PT.
                        for rpt in self.running.iter() {
                            if let Some(cmethod) = rpt.transport_methods().get(&pt) {
                                let _ = result.send(Ok(cmethod.clone()));
                                return Ok(false);
                            }
                        }
                        // We don't, so time to spawn one.
                        let config = {
                            let state = self.state.read().expect("ptmgr state poisoned");
                            state.configured.get(&pt).cloned()
                        };
                        let config = match config {
                            Some(v) if v.is_managed() => v,
                            Some(_) => {
                                let _ = result.send(Err(internal!("Tried to spawn an unmanaged transport").into()));
                                return Ok(false);
                            }
                            None => {
                                let _ = result.send(Err(PtError::UnconfiguredTransportDueToConcurrentReconfiguration));
                                return Ok(false);
                            }
                        };
                        // Keep track of the request, and also fill holes in other protocols so
                        // we don't try and run another spawn request for those.
                        self.requests.entry(pt).or_default().push(result);
                        for proto in config.protocols.iter() {
                            self.requests.entry(proto.clone()).or_default();
                        }

                        // Add the spawn future to our pile of them.
                        let spawn_fut = Box::pin(
                            spawn_from_config(self.rt.clone(), self.state_dir.clone(), config.clone())
                                .map(|result| (config.protocols, result))
                        );
                        self.spawning.push(spawn_fut);
                    },
                    None => return Ok(true)
                }
            }
        }
        Ok(false)
    }
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
    ) -> HashMap<PtTransportName, TransportConfig> {
        let mut ret = HashMap::new();
        // FIXME(eta): You can currently specify overlapping protocols, and it'll
        //             just use the last transport specified.
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
    // TODO: maybe don't have the Vec directly exposed?
    pub fn new(
        transports: Vec<TransportConfig>,
        state_dir: PathBuf,
        rt: R,
    ) -> Result<Self, PtError> {
        let state = PtSharedState {
            managed_cmethods: Default::default(),
            configured: Self::transform_config(transports),
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
        let configured = Self::transform_config(transports);
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
            if let Some(cmethod) = cfg.and_then(TransportConfig::cmethod_for_unmanaged_pt) {
                // We have a managed transport; that was easy.
                (Some(cmethod), true)
            } else {
                let cmethod = inner.managed_cmethods.get(transport).cloned();
                let configured = cmethod.is_some() || cfg.is_some();
                (cmethod, configured)
            }
        };

        match (cmethod, configured) {
            (None, true) => {
                // A configured-but-not-running cmethod.
                //
                // Tell the reactor to spawn the PT, and wait for it.
                // (The reactor will handle coalescing multiple requests.)
                info!(
                    "Got a request for transport {}, which is not currently running. Launching it.",
                    transport
                );
                let (tx, rx) = oneshot::channel();
                self.tx
                    .unbounded_send(PtReactorMessage::Spawn {
                        pt: transport.clone(),
                        result: tx,
                    })
                    .map_err(|_| {
                        PtError::Internal(tor_error::internal!("PT reactor closed unexpectedly"))
                    })?;
                let method =
                        // NOTE(eta): Could be improved with result flattening.
                        rx.await
                            .map_err(|_| {
                               PtError::Internal(tor_error::internal!(
                                    "PT reactor closed unexpectedly"
                                ))
                            })?
                            .map_err(|x| {
                                warn!("PT for {} failed to launch: {}", transport, x);
                                x
                            })?;
                info!(
                    "Successfully launched PT for {} at {:?}.",
                    transport, &method
                );
                Ok(Some(method))
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
}

/// Spawn a managed `PluggableTransport` using a `TransportConfig`.
///
/// Requires that the transport is a managed transport.
async fn spawn_from_config<R: Runtime>(
    rt: R,
    state_dir: PathBuf,
    cfg: TransportConfig,
) -> Result<PluggableClientTransport, PtError> {
    // FIXME(eta): I really think this expansion should happen at builder validation time...

    let cfg_path = cfg
        .path
        .as_ref()
        .ok_or_else(|| internal!("spawn_from_config on an unmanaged transport."))?;

    let binary_path = cfg_path.path().map_err(|e| PtError::PathExpansionFailed {
        path: cfg_path.clone(),
        error: e,
    })?;

    let filename = pt_identifier_as_path(&binary_path)?;

    // HACK(eta): Currently the state directory is named after the PT binary name. Maybe we should
    //            invent a better way of doing this?
    let new_state_dir = state_dir.join(filename);
    std::fs::create_dir_all(&new_state_dir).map_err(|e| PtError::StatedirCreateFailed {
        path: new_state_dir.clone(),
        error: Arc::new(e),
    })?;

    // FIXME(eta): make the rest of these parameters configurable
    let pt_common_params = PtCommonParameters::builder()
        .state_location(new_state_dir)
        .build()
        .expect("PtCommonParameters constructed incorrectly");

    let pt_client_params = PtClientParameters::builder()
        .transports(cfg.protocols)
        .build()
        .expect("PtClientParameters constructed incorrectly");

    let mut pt = PluggableClientTransport::new(
        binary_path,
        cfg.arguments,
        pt_common_params,
        pt_client_params,
    );
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

/// Given a path to a binary for a pluggable transport, return an identifier for
/// that binary in a format that can be used as a path component.
fn pt_identifier_as_path(binary_path: impl AsRef<Path>) -> Result<PathBuf, PtError> {
    // Extract the final component.
    let mut filename =
        PathBuf::from(
            binary_path
                .as_ref()
                .file_name()
                .ok_or_else(|| PtError::NotAFile {
                    path: binary_path.as_ref().to_path_buf(),
                })?,
        );

    // Strip an "exe" off the end, if appropriate.
    if let Some(ext) = filename.extension() {
        if ext.eq_ignore_ascii_case(std::env::consts::EXE_EXTENSION) {
            filename.set_extension("");
        }
    }

    Ok(filename)
}

/// Given a path to a binary for a pluggable transport, return an identifier for
/// that binary in human-readable form.
fn pt_identifier(binary_path: impl AsRef<Path>) -> Result<String, PtError> {
    Ok(pt_identifier_as_path(binary_path)?
        .to_string_lossy()
        .to_string())
}
