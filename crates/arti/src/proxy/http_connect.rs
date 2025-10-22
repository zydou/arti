//! Implement an HTTP1 CONNECT proxy using `hyper`.
//!
//! Note that Tor defines several extensions to HTTP CONNECT;
//! See [the spec](spec.torproject.org/http-connect.html)
//! for more information.

use super::{ListenerIsolation, ProxyContext, copy_interactive};
use anyhow::{Context as _, anyhow};
use arti_client::{StreamPrefs, TorAddr};
use futures::task::SpawnExt as _;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, FutureExt as _, io::BufReader};
use http::{Method, StatusCode, response::Builder as ResponseBuilder};
use hyper::{Response, server::conn::http1::Builder as ServerBuilder, service::service_fn};
use hyper_futures::AsyncReadWriteCompat;
use safelog::{Sensitive as Sv, sensitive as sv};
use tor_error::{ErrorKind, ErrorReport as _, HasKind as _, into_internal, warn_report};
use tor_rtcompat::Runtime;
use tracing::instrument;

/// Request type that we receive from Hyper.
type Request = hyper::Request<hyper::body::Incoming>;

/// We use "String" as our body type, since we only return a body on error,
/// in which case it already starts life as a formatted string.
///
/// (We could use () or `Empty` for our (200 OK) replies,
/// but empty strings are cheap enough that it isn't worth it.)
type Body = String;

/// Given a just-received TCP connection `S` on a HTTP proxy port, handle the
/// HTTP handshake and relay the connection over the Tor network.
///
/// Uses `isolation_info` to decide which circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the HTTP request.
#[instrument(skip_all, level = "trace")]
pub(super) async fn handle_http_conn<R, S>(
    context: super::ProxyContext<R>,
    stream: BufReader<S>,
    isolation_info: ListenerIsolation,
) -> crate::Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // NOTES:
    // * We _could_ use a timeout, but we trust that the client is not trying to DOS us.
    ServerBuilder::new()
        .half_close(false)
        .keep_alive(true)
        .max_headers(256)
        .max_buf_size(16 * 1024)
        .title_case_headers(true)
        .auto_date_header(false) // We omit the date header out of general principle.
        .serve_connection(
            AsyncReadWriteCompat::new(stream),
            service_fn(|request| handle_http_request::<R, S>(request, &context, isolation_info)),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

/// Handle a single HTTP request.
///
/// This function is invoked by hyper.
async fn handle_http_request<R, S>(
    request: Request,
    context: &ProxyContext<R>,
    listener_isolation: ListenerIsolation,
) -> Result<Response<Body>, anyhow::Error>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    match *request.method() {
        Method::OPTIONS => handle_options_request(request).await,
        Method::CONNECT => {
            handle_connect_request::<R, S>(request, context, listener_isolation).await
        }
        _ => Ok(ResponseBuilder::new()
            .status(StatusCode::NOT_IMPLEMENTED)
            .err(
                request.method(),
                format!("{} is not supported", request.method()),
            )?),
    }
}

/// Return an appropriate reply to the given OPTIONS request.
async fn handle_options_request(request: Request) -> Result<Response<Body>, anyhow::Error> {
    let target = request.uri().to_string();
    match target.as_str() {
        "*" => {}
        s if TorAddr::from(s).is_ok() => {}
        _ => {
            return Ok(ResponseBuilder::new()
                .status(StatusCode::BAD_REQUEST)
                .err(&Method::OPTIONS, "Target was not a valid address")?);
        }
    }
    // XXXX Handle body if there is one!?
    Ok(ResponseBuilder::new()
        .header("Allow", "OPTIONS, CONNECT")
        .status(StatusCode::OK)
        .ok(&Method::OPTIONS)?)
}

/// Return an appropriate reply to the given CONNECT request.
async fn handle_connect_request<R, S>(
    request: Request,
    context: &ProxyContext<R>,
    listener_isolation: ListenerIsolation,
) -> anyhow::Result<Response<Body>>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    match handle_connect_request_impl::<R, S>(request, context, listener_isolation).await {
        Ok(response) => Ok(response),
        Err(e) => Ok(e.try_into_response()?),
    }
}

/// Helper for handle_connect_request:
/// return an error type that can be converted into an HTTP message.
///
/// (This is a separate function to make error handling simpler.)
async fn handle_connect_request_impl<R, S>(
    request: Request,
    context: &ProxyContext<R>,
    listener_isolation: ListenerIsolation,
) -> Result<Response<Body>, HttpConnectError>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let target = request.uri().to_string();
    let tor_addr =
        TorAddr::from(&target).map_err(|e| HttpConnectError::InvalidStreamTarget(sv(target), e))?;
    let stream_prefs = StreamPrefs::default();

    // XXXX Implement isolation.
    let _ = listener_isolation;
    // XXXX Implement RPC.
    // XXXX Implement stream family preference.
    let client = context.tor_client.clone();

    // If we reach this point, the request looks okay, so we'll try to connect.
    let tor_stream = client
        .connect_with_prefs(&tor_addr, &stream_prefs)
        .await
        .map_err(|e| HttpConnectError::ConnectFailed(sv(tor_addr), e))?;

    // We have connected.  We need to launch a separate task to actually be the proxy, though,
    // since IIUC hyper::upgrade::on won't return an answer
    // until after the response is given to the client.
    let runtime = context.tor_client.runtime().clone();
    context
        .tor_client
        .runtime()
        .spawn(async move {
            match transfer::<R, S>(runtime, request, tor_stream).await {
                Ok(()) => {}
                Err(e) => {
                    warn_report!(e, "Error while launching transfer");
                }
            }
        })
        .map_err(into_internal!("Unable to spawn transfer task"))?;

    ResponseBuilder::new()
        .status(StatusCode::OK)
        .ok(&Method::CONNECT)
}

/// Extension trait on ResponseBuilder
trait RespBldExt {
    /// Return a response for a successful builder.
    fn ok(self, method: &Method) -> anyhow::Result<Response<Body>, HttpConnectError>;

    /// Return a response for an error message.
    fn err(
        self,
        method: &Method,
        message: impl Into<String>,
    ) -> Result<Response<Body>, HttpConnectError>;
}

impl RespBldExt for ResponseBuilder {
    fn ok(self, method: &Method) -> Result<Response<Body>, HttpConnectError> {
        let bld = add_common_headers(self, method);
        Ok(bld
            .body("".into())
            .map_err(into_internal!("Formatting HTTP response"))?)
    }

    fn err(
        self,
        method: &Method,
        message: impl Into<String>,
    ) -> Result<Response<Body>, HttpConnectError> {
        let bld = add_common_headers(self, method);
        Ok(bld
            .body(message.into())
            .map_err(into_internal!("Formatting HTTP response"))?)
    }
}

/// Add all common headers to the builder `bld`, and return a new builder.
fn add_common_headers(mut bld: ResponseBuilder, method: &Method) -> ResponseBuilder {
    bld = bld.header("X-Tor-Capabilities", "");
    if let (Some(software), Some(version)) = (
        option_env!("CARGO_PKG_NAME"),
        option_env!("CARGO_PKG_VERSION"),
    ) {
        if method == Method::CONNECT {
            bld = bld.header(
                "Via",
                format!("x-tor/1.0 tor-network ({software} {version})"),
            );
        } else {
            bld = bld.header("Server", format!("x-tor/1.0 ({software} {version})"));
        }
    }
    bld
}

/// An error that occurs during an HTTP CONNECT attempt, which can (usually)
/// be reported to the client.
#[derive(Clone, Debug, thiserror::Error)]
enum HttpConnectError {
    /// Tried to connect to an invalid stream target.
    #[error("Invalid target address {0:?}")]
    InvalidStreamTarget(Sv<String>, #[source] arti_client::TorAddrError),

    /// arti_client was unable to connect ot a stream target.
    #[error("Unable to connect to {0}")]
    ConnectFailed(Sv<TorAddr>, #[source] arti_client::Error),

    /// We encountered an internal error.
    #[error("Internal error while handling request")]
    Internal(#[from] tor_error::Bug),
}

impl HttpConnectError {
    /// Return an appropriate HTTP status code for this error.
    fn status_code(&self) -> StatusCode {
        use HttpConnectError as HCE;
        use StatusCode as SC; // Not a Joyce reference
        match self {
            HCE::InvalidStreamTarget(_, _) => SC::BAD_REQUEST,
            HCE::ConnectFailed(_, e) => kind_to_status(e.kind()),
            HCE::Internal(e) => kind_to_status(e.kind()),
        }
    }

    /// If possible, return a response that we should give to this error.
    fn try_into_response(self) -> Result<Response<Body>, HttpConnectError> {
        let status_code = self.status_code();
        // XXXX encode more information, per the spec.
        ResponseBuilder::new()
            .status(status_code)
            .err(&Method::CONNECT, self.report().to_string())
    }
}

/// Convert an ErrorKind into a StatusCode.
fn kind_to_status(_kind: ErrorKind) -> StatusCode {
    StatusCode::BAD_REQUEST //XXXX Actually implement this.
}

/// Recover the original stream from a [`hyper::upgrade::Upgraded`].
fn deconstruct_upgrade<S>(upgraded: hyper::upgrade::Upgraded) -> Result<S, anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let parts: hyper::upgrade::Parts<AsyncReadWriteCompat<BufReader<S>>> = upgraded
        .downcast()
        .map_err(|_| anyhow!("downcast failed!"))?;
    let hyper::upgrade::Parts { io, read_buf, .. } = parts;
    if !read_buf.is_empty() {
        // TODO Figure out whether this can happen, due to possible race conditions if the client
        // gets the OK before we check this?.
        return Err(anyhow!(
            "Extraneous data on hyper buffer after upgrade to proxy mode"
        ));
    }
    let io: BufReader<S> = io.into_inner();
    if !io.buffer().is_empty() {
        // TODO Figure out whether this can happen due to possible race conditions if the client gets the OK
        // before we check this?
        return Err(anyhow!(
            "Extraneous data on BufReader after upgrade to proxy mode"
        ));
    }
    Ok(io.into_inner())
}

/// Recover the application stream from `request`, and launch tasks to transfer data between the application and
/// the `tor_stream`.
async fn transfer<R, S>(
    runtime: R,
    request: Request,
    tor_stream: arti_client::DataStream,
) -> anyhow::Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let upgraded = hyper::upgrade::on(request)
        .await
        .context("Unable to upgrade connection")?;
    let app_stream: S = deconstruct_upgrade(upgraded)?;

    let (app_r, app_w) = app_stream.split();
    let (tor_r, tor_w) = tor_stream.split();

    // Finally, spawn two background tasks to relay traffic between
    // the application stream and the tor stream.
    runtime
        .spawn(copy_interactive(app_r, tor_w).map(|_| ()))
        .context("Spawning task")?;
    runtime
        .spawn(copy_interactive(tor_r, app_w).map(|_| ()))
        .context("Spawning task")?;

    Ok(())
}
