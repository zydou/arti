//! A simple reverse-proxy implementation for onion services.

use std::sync::{Arc, Mutex};

use futures::{
    channel::oneshot, task::SpawnExt as _, AsyncRead, AsyncWrite, Future, FutureExt as _, Stream,
    StreamExt as _,
};
use tor_cell::relaycell::msg as relaymsg;
use tor_error::debug_report;
use tor_hsservice::{OnionServiceDataStream, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::Runtime;
use tracing::debug;

use crate::config::{Encapsulation, ProxyAction, ProxyConfig, TargetAddr};

/// A reverse proxy that handles connections from an `OnionService` by routing
/// them to local addresses.
#[derive(Debug)]
pub struct OnionServiceReverseProxy {
    /// Mutable state held by this reverse proxy.
    state: Mutex<State>,
}

/// Mutable part of an RProxy
#[derive(Debug)]
struct State {
    /// The current configuration for this reverse proxy.
    config: ProxyConfig,
    /// A sender that we'll drop when it's time to shut down this proxy.
    shutdown_tx: Option<oneshot::Sender<void::Void>>,
    /// A receiver that we'll use to monitor for shutdown signals.
    shutdown_rx: futures::future::Shared<oneshot::Receiver<void::Void>>,
}

impl OnionServiceReverseProxy {
    /// Create a new proxy with a given configuration.
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Arc::new(Self {
            state: Mutex::new(State {
                config,
                shutdown_tx: Some(shutdown_tx),
                shutdown_rx: shutdown_rx.shared(),
            }),
        })
    }

    /// Try to change the configuration of this proxy.
    pub fn reconfigure(&self, config: ProxyConfig) -> Result<(), tor_config::ReconfigureError> {
        let mut state = self.state.lock().expect("poisoned lock");
        state.config = config;
        // Note: we don't need to use a postage::watch here, since we just want
        // to lock this configuration whenever we get a request.  We could use a
        // Mutex<Arc<>> instead, but the performance shouldn't matter.
        Ok(())
    }

    /// Shut down all request-handlers running using with this proxy.
    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("poisoned lock");
        let _ = state.shutdown_tx.take();
    }

    /// Use this proxy to handle a stream of [`RendRequest`] requests.
    ///
    /// The future returned by this function blocks indefinitely, so you may
    /// want to spawn a separate task for it.
    pub async fn handle_requests<R, S>(&self, runtime: R, requests: S)
    where
        R: Runtime,
        S: Stream<Item = tor_hsservice::RendRequest> + Unpin,
    {
        let mut stream_requests = tor_hsservice::handle_rend_requests(requests);
        // TODO HSS: Actually look at shutdown_rx here!
        while let Some(stream_request) = stream_requests.next().await {
            let action = self.choose_action(stream_request.request());

            let _outcome = runtime.spawn(run_action(runtime.clone(), action, stream_request));
            // TODO HSS: if we fail to spawn, report an error and exit
        }
    }

    /// Choose the configured action that we should take in response to a
    /// [`StreamRequest`], based on our current configuration.
    fn choose_action(&self, stream_request: &IncomingStreamRequest) -> ProxyAction {
        let port: u16 = match stream_request {
            IncomingStreamRequest::Begin(begin) => {
                // TODO HSS: Should we look at the address and flags at all?
                begin.port()
            }
            other => {
                tracing::warn!(
                    "Rejecting onion service request for invalid command {:?}. Internal error.",
                    other
                );
                return ProxyAction::DestroyCircuit;
            }
        };

        self.state
            .lock()
            .expect("poisoned lock")
            .config
            .resolve_port_for_begin(port)
            .cloned()
            // The default action is "destroy the circuit."
            .unwrap_or(ProxyAction::DestroyCircuit)
    }
}

/// Take the configured action from `action` on the incoming request `request`.
pub(super) async fn run_action<R: Runtime>(
    runtime: R,
    action: ProxyAction,
    request: StreamRequest,
) {
    match action {
        ProxyAction::DestroyCircuit => {
            if let Err(e) = request.shutdown_circuit() {
                debug_report!(e, "Unable to destroy onion service circuit");
            }
        }
        ProxyAction::Forward(encap, target) => match (encap, target) {
            (Encapsulation::Simple, TargetAddr::Inet(a)) => {
                let rt_clone = runtime.clone();
                forward_connection(rt_clone, request, runtime.connect(&a)).await;
            }
            (Encapsulation::Simple, TargetAddr::Unix(_)) => {
                // TODO HSS: We need to implement unix connections.
            }
        },
        ProxyAction::RejectStream => {
            // TODO HSS: Does this match the behavior from C tor?
            let end = relaymsg::End::new_misc();

            if let Err(e) = request.reject(end).await {
                debug_report!(e, "Unable to reject onion service request from client");
            }
        }
        ProxyAction::IgnoreStream => drop(request),
    };
}

/// Try to open a connection to an appropriate local target using
/// `target_stream_future`.  If successful, try to report success on `request`
/// and trandmit data between the two stream indefinitely.  On failure, close
/// `request`.
async fn forward_connection<R, FUT, TS, E>(
    _runtime: R,
    request: StreamRequest,
    target_stream_future: FUT,
) where
    R: Runtime,
    FUT: Future<Output = Result<TS, E>>,
    TS: AsyncRead + AsyncWrite,
    E: std::fmt::Display,
{
    let _local_stream = match target_stream_future.await {
        Ok(s) => s,
        Err(e) => {
            // TODO HSS: We should log more, since this is likely a missing
            // local service.
            // TODO HSS: (This is a major usability problem!)
            debug!("Unable to connect to onion service target: {}", e);
            let end = relaymsg::End::new_misc();
            if let Err(e) = request.reject(end).await {
                debug_report!(e, "Unable to reject onion service request from client");
            }
            return;
        }
    };

    let _onion_service_stream: OnionServiceDataStream = {
        // TODO HSS: Does this match the behavior from C tor?
        let connected = relaymsg::Connected::new_empty();
        match request.accept(connected).await {
            Ok(s) => s,
            Err(e) => {
                debug_report!(e, "Unable to accept connection from onion service client");
                return;
            }
        }
    };

    // TODO HSS: Forward data indefinitely.
    // TODO HSS: Why is OnionServiceDataStream not the same type as DataStream?
}
