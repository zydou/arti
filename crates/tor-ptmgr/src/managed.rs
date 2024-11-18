//! Infrastructure required to support managed PTs.

use crate::config::{ManagedTransportOptions, TransportOptions};
use crate::err;
use crate::err::PtError;
use crate::ipc::{
    sealed::PluggableTransportPrivate, PluggableClientTransport, PluggableTransport,
    PtClientParameters, PtCommonParameters,
};
use crate::{PtClientMethod, PtSharedState};
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use oneshot_fused_workaround as oneshot;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tor_config_path::CfgPathResolver;
use tor_error::internal;
use tor_linkspec::PtTransportName;
use tor_rtcompat::Runtime;
use tracing::{debug, warn};

/// A message to the `PtReactor`.
pub(crate) enum PtReactorMessage {
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
pub(crate) struct PtReactor<R> {
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
    /// Path resolver for configuration files.
    path_resolver: Arc<CfgPathResolver>,
}

impl<R: Runtime> PtReactor<R> {
    /// Make a new reactor.
    pub(crate) fn new(
        rt: R,
        state: Arc<RwLock<PtSharedState>>,
        rx: UnboundedReceiver<PtReactorMessage>,
        state_dir: PathBuf,
        path_resolver: Arc<CfgPathResolver>,
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
            path_resolver,
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
    pub(crate) async fn run_one_step(&mut self) -> err::Result<bool> {
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

                        let Some(config) = config else {
                            let _ = result.send(Err(PtError::UnconfiguredTransportDueToConcurrentReconfiguration));
                            return Ok(false);
                        };

                        let TransportOptions::Managed(config) = config else {
                            let _ = result.send(Err(internal!("Tried to spawn an unmanaged transport").into()));
                            return Ok(false);
                        };

                        // Keep track of the request, and also fill holes in other protocols so
                        // we don't try and run another spawn request for those.
                        self.requests.entry(pt).or_default().push(result);
                        for proto in config.protocols.iter() {
                            self.requests.entry(proto.clone()).or_default();
                        }

                        // Add the spawn future to our pile of them.
                        let spawn_fut = Box::pin(
                            spawn_from_config(
                                self.rt.clone(),
                                self.state_dir.clone(),
                                config.clone(),
                                Arc::clone(&self.path_resolver)
                            )
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

/// Spawn a managed `PluggableTransport` using a `ManagedTransportOptions`.
async fn spawn_from_config<R: Runtime>(
    rt: R,
    state_dir: PathBuf,
    cfg: ManagedTransportOptions,
    path_resolver: Arc<CfgPathResolver>,
) -> Result<PluggableClientTransport, PtError> {
    // FIXME(eta): I really think this expansion should happen at builder validation time...

    let cfg_path = cfg.path;

    let binary_path = cfg_path
        .path(&path_resolver)
        .map_err(|e| PtError::PathExpansionFailed {
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
pub(crate) fn pt_identifier(binary_path: impl AsRef<Path>) -> Result<String, PtError> {
    Ok(pt_identifier_as_path(binary_path)?
        .to_string_lossy()
        .to_string())
}
