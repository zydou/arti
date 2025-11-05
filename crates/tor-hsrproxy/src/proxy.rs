//! A simple reverse-proxy implementation for onion services.

use std::sync::{Arc, Mutex};

use futures::io::BufReader;
use futures::{
    AsyncRead, AsyncWrite, Future, FutureExt as _, Stream, StreamExt as _, select_biased,
};
use itertools::iproduct;
use oneshot_fused_workaround as oneshot;
use safelog::sensitive as sv;
use std::collections::HashMap;
use std::io::Error as IoError;
use strum::IntoEnumIterator;
use tor_cell::relaycell::msg as relaymsg;
use tor_error::{ErrorKind, HasKind, debug_report};
use tor_hsservice::{HsNickname, RendRequest, StreamRequest};
use tor_log_ratelim::log_ratelim;
use tor_proto::client::stream::{DataStream, IncomingStreamRequest};
use tor_rtcompat::{Runtime, SpawnExt as _};

use crate::config::{
    Encapsulation, ProxyAction, ProxyActionDiscriminants, ProxyConfig, TargetAddr,
};

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

/// An error that prevents further progress while processing requests.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandleRequestsError {
    /// The runtime says it was unable to spawn a task.
    #[error("Unable to spawn a task")]
    Spawn(#[source] Arc<futures::task::SpawnError>),
}

impl HasKind for HandleRequestsError {
    fn kind(&self) -> ErrorKind {
        match self {
            HandleRequestsError::Spawn(e) => e.kind(),
        }
    }
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
    ///
    /// This change applies only to new connections through the proxy; existing
    /// connections are not affected.
    pub fn reconfigure(
        &self,
        config: ProxyConfig,
        how: tor_config::Reconfigure,
    ) -> Result<(), tor_config::ReconfigureError> {
        if how == tor_config::Reconfigure::CheckAllOrNothing {
            // Every possible reconfiguration is allowed.
            return Ok(());
        }
        let mut state = self.state.lock().expect("poisoned lock");
        state.config = config;
        // Note: we don't need to use a postage::watch here, since we just want
        // to lock this configuration whenever we get a request.  We could use a
        // Mutex<Arc<>> instead, but the performance shouldn't matter.
        //
        Ok(())
    }

    /// Shut down all request-handlers running using with this proxy.
    pub fn shutdown(&self) {
        let mut state = self.state.lock().expect("poisoned lock");
        let _ = state.shutdown_tx.take();
    }

    /// Use this proxy to handle a stream of [`RendRequest`]s.
    ///
    /// The future returned by this function blocks indefinitely, so you may
    /// want to spawn a separate task for it.
    ///
    /// The provided nickname is used for logging.
    pub async fn handle_requests<R, S>(
        &self,
        runtime: R,
        nickname: HsNickname,
        requests: S,
    ) -> Result<(), HandleRequestsError>
    where
        R: Runtime,
        S: Stream<Item = RendRequest> + Unpin,
    {
        let mut stream_requests = tor_hsservice::handle_rend_requests(requests).fuse();
        let mut shutdown_rx = self
            .state
            .lock()
            .expect("poisoned lock")
            .shutdown_rx
            .clone()
            .fuse();
        let nickname = Arc::new(nickname);

        /// Which of the three counters for each action
        #[cfg(feature = "metrics")]
        #[derive(Clone, Copy, Eq, PartialEq, Hash)]
        enum CounterSelector {
            /// Two counters, one for successes, one for failures
            Ret(Result<(), ()>),
            /// One counter for the total
            Total,
        }

        #[cfg(feature = "metrics")]
        let metrics_counters = {
            use CounterSelector as CS;

            let counters = iproduct!(
                ProxyActionDiscriminants::iter(),
                [
                    (CS::Total, "arti_hss_proxy_connections_total"),
                    (CS::Ret(Ok(())), "arti_hss_proxy_connections_ok_total"),
                    (CS::Ret(Err(())), "arti_hss_proxy_connections_failed_total"),
                ],
            )
            .map(|(action, (outcome, name))| {
                let k = (action, outcome);
                let nickname = nickname.to_string();
                let action: &str = action.into();
                let v = metrics::counter!(name, "nickname" => nickname, "action" => action);
                (k, v)
            })
            .collect::<HashMap<(ProxyActionDiscriminants, CounterSelector), _>>();

            Arc::new(counters)
        };

        loop {
            let stream_request = select_biased! {
                _ = shutdown_rx => return Ok(()),
                stream_request = stream_requests.next() => match stream_request {
                    None => return Ok(()),
                    Some(s) => s,
                }
            };

            runtime.spawn({
                let action = self.choose_action(stream_request.request());
                let runtime = runtime.clone();
                let nickname = nickname.clone();
                let req = stream_request.request().clone();

                #[cfg(feature = "metrics")]
                let metrics_counters = metrics_counters.clone();

                async move {
                    let outcome =
                        run_action(runtime, nickname.as_ref(), action.clone(), stream_request).await;

                    #[cfg(feature = "metrics")]
                    {
                        use CounterSelector as CS;

                        let action = ProxyActionDiscriminants::from(&action);
                        let outcome = outcome.as_ref().map(|_|()).map_err(|_|());
                        for outcome in [CS::Total, CS::Ret(outcome)] {
                            if let Some(counter) = metrics_counters.get(&(action, outcome)) {
                                counter.increment(1);
                            } else {
                                // statically be impossible, but let's not panic
                            }
                        }
                    }

                    log_ratelim!(
                        "Performing action on {}", nickname;
                        outcome;
                        Err(_) => WARN, "Unable to take action {:?} for request {:?}", sv(action), sv(req)
                    );
                }
            })
                .map_err(|e| HandleRequestsError::Spawn(Arc::new(e)))?;
        }
    }

    /// Choose the configured action that we should take in response to a
    /// [`StreamRequest`], based on our current configuration.
    fn choose_action(&self, stream_request: &IncomingStreamRequest) -> ProxyAction {
        let port: u16 = match stream_request {
            IncomingStreamRequest::Begin(begin) => {
                // The C tor implementation deliberately ignores the address and
                // flags on the BEGIN message, so we do too.
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
async fn run_action<R: Runtime>(
    runtime: R,
    nickname: &HsNickname,
    action: ProxyAction,
    request: StreamRequest,
) -> Result<(), RequestFailed> {
    match action {
        ProxyAction::DestroyCircuit => {
            request
                .shutdown_circuit()
                .map_err(RequestFailed::CantDestroy)?;
        }
        ProxyAction::Forward(encap, target) => match (encap, target) {
            (Encapsulation::Simple, ref addr @ TargetAddr::Inet(a)) => {
                let rt_clone = runtime.clone();
                forward_connection(rt_clone, request, runtime.connect(&a), nickname, addr).await?;
            } /* TODO (#1246)
                (Encapsulation::Simple, TargetAddr::Unix(_)) => {
                    // TODO: We need to implement unix connections.
                }
              */
        },
        ProxyAction::RejectStream => {
            // C tor sends DONE in this case, so we do too.
            let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE);

            request
                .reject(end)
                .await
                .map_err(RequestFailed::CantReject)?;
        }
        ProxyAction::IgnoreStream => drop(request),
    };
    Ok(())
}

/// An error from a single attempt to handle an onion service request.
#[derive(thiserror::Error, Debug, Clone)]
enum RequestFailed {
    /// Encountered an error trying to destroy a circuit.
    #[error("Unable to destroy onion service circuit")]
    CantDestroy(#[source] tor_error::Bug),

    /// Encountered an error trying to reject a single stream request.
    #[error("Unable to reject onion service request")]
    CantReject(#[source] tor_hsservice::ClientError),

    /// Encountered an error trying to tell the remote onion service client that
    /// we have accepted their connection.
    #[error("Unable to accept onion service connection")]
    AcceptRemote(#[source] tor_hsservice::ClientError),

    /// The runtime refused to spawn a task for us.
    #[error("Unable to spawn task")]
    Spawn(#[source] Arc<futures::task::SpawnError>),
}

impl HasKind for RequestFailed {
    fn kind(&self) -> ErrorKind {
        match self {
            RequestFailed::CantDestroy(e) => e.kind(),
            RequestFailed::CantReject(e) => e.kind(),
            RequestFailed::AcceptRemote(e) => e.kind(),
            RequestFailed::Spawn(e) => e.kind(),
        }
    }
}

/// Size of buffer to use for communication between Arti and the
/// target service.
//
// This particular value is chosen more or less arbitrarily.
// Larger values let us do fewer reads from the application,
// but consume more memory.
//
// (The default value for BufReader is 8k as of this writing.)
const STREAM_BUF_LEN: usize = 4096;

/// Try to open a connection to an appropriate local target using
/// `target_stream_future`.  If successful, try to report success on `request`
/// and transmit data between the two stream indefinitely.  On failure, close
/// `request`.
///
/// Only return an error if we were unable to behave as intended due to a
/// problem we did not already report.
async fn forward_connection<R, FUT, TS>(
    runtime: R,
    request: StreamRequest,
    target_stream_future: FUT,
    nickname: &HsNickname,
    addr: &TargetAddr,
) -> Result<(), RequestFailed>
where
    R: Runtime,
    FUT: Future<Output = Result<TS, IoError>>,
    TS: AsyncRead + AsyncWrite + Send + 'static,
{
    let local_stream = target_stream_future.await.map_err(Arc::new);

    // TODO: change this to "log_ratelim!(nickname=%nickname, ..." when log_ratelim can do that
    // (we should search for HSS log messages and make them all be in the same form)
    log_ratelim!(
        "Connecting to {} for onion service {}", sv(addr), nickname;
        local_stream
    );

    let local_stream = match local_stream {
        Ok(s) => s,
        Err(_) => {
            let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE);
            if let Err(e_rejecting) = request.reject(end).await {
                debug_report!(
                    &e_rejecting,
                    "Unable to reject onion service request from client"
                );
                return Err(RequestFailed::CantReject(e_rejecting));
            }
            // We reported the (rate-limited) error from local_stream in
            // DEBUG_REPORT above.
            return Ok(());
        }
    };

    let onion_service_stream: DataStream = {
        let connected = relaymsg::Connected::new_empty();
        request
            .accept(connected)
            .await
            .map_err(RequestFailed::AcceptRemote)?
    };

    let onion_service_stream = BufReader::with_capacity(STREAM_BUF_LEN, onion_service_stream);
    let local_stream = BufReader::with_capacity(STREAM_BUF_LEN, local_stream);

    runtime
        .spawn(
            futures_copy::copy_buf_bidirectional(
                onion_service_stream,
                local_stream,
                futures_copy::eof::Close,
                futures_copy::eof::Close,
            )
            .map(|_| ()),
        )
        .map_err(|e| RequestFailed::Spawn(Arc::new(e)))?;

    Ok(())
}
