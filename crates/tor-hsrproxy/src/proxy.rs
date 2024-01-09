//! A simple reverse-proxy implementation for onion services.

use std::sync::{Arc, Mutex};

use futures::{
    select_biased, task::SpawnExt as _, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future,
    FutureExt as _, Stream, StreamExt as _,
};
use safelog::sensitive as sv;
use std::io::{Error as IoError, Result as IoResult};
use tor_async_utils::oneshot;
use tor_cell::relaycell::msg as relaymsg;
use tor_error::{debug_report, ErrorKind, HasKind};
use tor_hsservice::{HsNickname, RendRequest, StreamRequest};
use tor_log_ratelim::log_ratelim;
use tor_proto::stream::{DataStream, IncomingStreamRequest};
use tor_rtcompat::Runtime;

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

        loop {
            let stream_request = select_biased! {
                _ = shutdown_rx => return Ok(()),
                stream_request = stream_requests.next() => match stream_request {
                    None => return Ok(()),
                    Some(s) => s,
                }
            };

            let action = self.choose_action(stream_request.request());
            let a_clone = action.clone();
            let rt_clone = runtime.clone();
            let nn_clone = Arc::clone(&nickname);
            let req = stream_request.request().clone();

            runtime
                .spawn(async move {
                    let outcome =
                        run_action(rt_clone, nn_clone.as_ref(), action, stream_request).await;

                    log_ratelim!(
                        "Performing action on {}", nn_clone;
                        outcome;
                        Err(_) => WARN, "Unable to take action {:?} for request {:?}", sv(a_clone), sv(req)
                    );
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
            }
            (Encapsulation::Simple, TargetAddr::Unix(_)) => {
                // TODO: We need to implement unix connections.
            }
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

    let (svc_r, svc_w) = onion_service_stream.split();
    let (local_r, local_w) = local_stream.split();

    runtime
        .spawn(copy_interactive(local_r, svc_w).map(|_| ()))
        .map_err(|e| RequestFailed::Spawn(Arc::new(e)))?;
    runtime
        .spawn(copy_interactive(svc_r, local_w).map(|_| ()))
        .map_err(|e| RequestFailed::Spawn(Arc::new(e)))?;

    Ok(())
}

/// Copy all the data from `reader` into `writer` until we encounter an EOF or
/// an error.
///
/// Unlike as futures::io::copy(), this function is meant for use with
/// interactive readers and writers, where the reader might pause for
/// a while, but where we want to send data on the writer as soon as
/// it is available.
///
/// This function assumes that the writer might need to be flushed for
/// any buffered data to be sent.  It tries to minimize the number of
/// flushes, however, by only flushing the writer when the reader has no data.
///
/// NOTE: This is duplicate code from `arti::socks`.  But instead of
/// deduplicating it, we should change the behavior in `DataStream` that makes
/// it necessary. See arti#786 for a fuller discussion.
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let mut read_future = reader.read(&mut buf[..]);
        match poll!(&mut read_future) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match read_future.await {
            Err(e) => break Err(e),
            Ok(0) => break Ok(()),
            Ok(n) => writer.write_all(&buf[..n]).await?,
        }
    };

    // Make sure that we flush any lingering data if we can.
    //
    // If there is a difference between closing and dropping, then we
    // only want to do a "proper" close if the reader closed cleanly.
    let flush_result = if loop_result.is_ok() {
        writer.close().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}
