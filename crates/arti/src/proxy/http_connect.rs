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
use safelog::{Sensitive as Sv, sensitive as sv};
use tor_error::{ErrorKind, ErrorReport as _, HasKind, into_internal, warn_report};
use tor_rtcompat::Runtime;
use tracing::{instrument, warn};

use hyper_futures_io::FuturesIoCompat;

#[cfg(feature = "rpc")]
use {crate::rpc::conntarget::ConnTarget, tor_rpcbase as rpc};

cfg_if::cfg_if! {
    if #[cfg(feature="rpc")] {
        /// Error type returned from a failed connect_with_prefs.
        type ClientError = Box<dyn arti_client::rpc::ClientConnectionError>;
    } else {
        /// Error type returned from a failed connect_with_prefs.
        type ClientError = arti_client::Error;
    }
}

/// Request type that we receive from Hyper.
type Request = hyper::Request<hyper::body::Incoming>;

/// We use "String" as our body type, since we only return a body on error,
/// in which case it already starts life as a formatted string.
///
/// (We could use () or `Empty` for our (200 OK) replies,
/// but empty strings are cheap enough that it isn't worth it.)
type Body = String;

/// A value used to isolate streams received via HTTP CONNECT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Isolation {
    /// The value of the Proxy-Authorization header.
    proxy_auth: Option<ProxyAuthorization>,
    /// The legacy X-Tor-Isolation token.
    x_tor_isolation: Option<String>,
    /// The up-to-date Tor-Isolation token.
    tor_isolation: Option<String>,
}

/// Constants and code for the HTTP headers we use.
mod hdr {
    pub(super) use http::header::{CONTENT_TYPE, PROXY_AUTHORIZATION, SERVER, VIA};

    /// Client-to-proxy: Which IP family should we use?
    pub(super) const TOR_FAMILY_PREFERENCE: &str = "Tor-Family-Preference";

    /// Client-To-Proxy: The ID of an RPC object to receive our request.
    pub(super) const TOR_RPC_TARGET: &str = "Tor-RPC-Target";

    /// Client-To-Proxy: An isolation token to use with our stream.
    /// (Legacy name.)
    pub(super) const X_TOR_STREAM_ISOLATION: &str = "X-Tor-Stream-Isolation";

    /// Client-To-Proxy: An isolation token to use with our stream.
    pub(super) const TOR_STREAM_ISOLATION: &str = "Tor-Stream-Isolation";

    /// Proxy-to-client: A list of the capabilities that this proxy provides.
    pub(super) const TOR_CAPABILITIES: &str = "Tor-Capabilities";

    /// Proxy-to-client: A machine-readable list of failure reasons.
    pub(super) const TOR_REQUEST_FAILED: &str = "Tor-Request-Failed";

    /// Return the unique string-valued value of the header `name`;
    /// or None if the header doesn't exist,
    /// or an error if the header is duplicated or not UTF-8.
    pub(super) fn uniq_utf8(
        map: &http::HeaderMap,
        name: impl http::header::AsHeaderName,
    ) -> Result<Option<&str>, super::HttpConnectError> {
        let mut iter = map.get_all(name).iter();
        let val = match iter.next() {
            Some(v) => v,
            None => return Ok(None),
        };
        match iter.next() {
            Some(_) => Err(super::HttpConnectError::DuplicateHeader),
            None => val
                .to_str()
                .map(Some)
                .map_err(|_| super::HttpConnectError::HeaderNotUtf8),
        }
    }
}

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
            FuturesIoCompat(stream),
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
    use hyper::body::Body as _;

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
    if request.headers().contains_key(hdr::CONTENT_TYPE) {
        // RFC 9110 says that if a client wants to include a body with its OPTIONS request (!),
        // it must include a Content-Type header.  Therefore, we reject such requests.
        return Ok(ResponseBuilder::new()
            .status(StatusCode::BAD_REQUEST)
            .err(&Method::OPTIONS, "Unexpected Content-Type on OPTIONS")?);

        // TODO: It would be cool to detect nonempty bodies in other ways, though in practice
        // it should never come up.
    }
    if !request.body().is_end_stream() {
        return Ok(ResponseBuilder::new()
            .status(StatusCode::BAD_REQUEST)
            .err(&Method::OPTIONS, "Unexpected body on OPTIONS request")?);
    }

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

    let mut stream_prefs = StreamPrefs::default();
    set_family_preference(&mut stream_prefs, &tor_addr, request.headers())?;

    set_isolation(&mut stream_prefs, request.headers(), listener_isolation)?;

    let client = find_conn_target(
        context,
        hdr::uniq_utf8(request.headers(), hdr::TOR_RPC_TARGET)?,
    )?;

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

/// Set the IP family preference in `prefs`.
fn set_family_preference(
    prefs: &mut StreamPrefs,
    addr: &TorAddr,
    headers: &http::HeaderMap,
) -> Result<(), HttpConnectError> {
    if let Some(val) = hdr::uniq_utf8(headers, hdr::TOR_FAMILY_PREFERENCE)? {
        match val.trim() {
            "ipv4-preferred" => prefs.ipv4_preferred(),
            "ipv6-preferred" => prefs.ipv6_preferred(),
            "ipv4-only" => prefs.ipv4_only(),
            "ipv6-only" => prefs.ipv6_only(),
            _ => return Err(HttpConnectError::InvalidFamilyPreference),
        };
    } else if let Some(ip) = addr.as_ip_address() {
        // TODO: Perhaps we should check unconditionally whether the IP address is consistent with header,
        // if one was given?  On the other hand, if the application tells us to make an IPV6-only
        // connection to an IPv4 address, it probably deserves what it gets.
        if ip.is_ipv4() {
            prefs.ipv4_only();
        } else {
            prefs.ipv6_only();
        }
    }

    Ok(())
}

/// Configure the stream isolation from the provided headers.
fn set_isolation(
    prefs: &mut StreamPrefs,
    headers: &http::HeaderMap,
    listener_isolation: ListenerIsolation,
) -> Result<(), HttpConnectError> {
    let proxy_auth =
        hdr::uniq_utf8(headers, hdr::PROXY_AUTHORIZATION)?.map(ProxyAuthorization::from_header);
    let x_tor_isolation = hdr::uniq_utf8(headers, hdr::X_TOR_STREAM_ISOLATION)?.map(str::to_owned);
    let tor_isolation = hdr::uniq_utf8(headers, hdr::TOR_STREAM_ISOLATION)?.map(str::to_owned);

    let isolation = super::ProvidedIsolation::Http(Isolation {
        proxy_auth,
        x_tor_isolation,
        tor_isolation,
    });

    let isolation = super::StreamIsolationKey(listener_isolation, isolation);
    prefs.set_isolation(isolation);

    Ok(())
}

/// An isolation value based on the Proxy-Authorization header.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum ProxyAuthorization {
    /// The entire contents of the Proxy-Authorization header.
    Legacy(String),
    /// The decoded value of the basic authorization, with the user set to "tor-iso".
    Modern(Vec<u8>),
}

impl ProxyAuthorization {
    /// Return a ProxyAuthorization based on the value of the Proxy-Authorization header.
    ///
    /// Give a warning if the header is in the legacy (obsolete) format.
    fn from_header(value: &str) -> Self {
        if let Some(result) = Self::modern_from_header(value) {
            result
        } else {
            warn!(
                "{} header in obsolete format. If you want isolation, use {}, \
                 or {} with Basic authentication and username 'tor-iso'",
                hdr::PROXY_AUTHORIZATION,
                hdr::X_TOR_STREAM_ISOLATION,
                hdr::PROXY_AUTHORIZATION
            );
            Self::Legacy(value.to_owned())
        }
    }

    /// Helper: Try to return a Modern authorization value, if this is one.
    fn modern_from_header(value: &str) -> Option<Self> {
        use base64ct::Encoding as _;
        let value = value.trim_ascii();
        let (kind, value) = value.split_once(' ')?;
        if kind != "Basic" {
            return None;
        }
        let value = value.trim_ascii();
        // TODO: Is this the right format, or should we allow missing padding?
        let decoded = base64ct::Base64::decode_vec(value).ok()?;
        if decoded.starts_with(b"tor-iso:") {
            Some(ProxyAuthorization::Modern(decoded))
        } else {
            None
        }
    }
}

/// Look up the connection target given the value of an Tor-RPC-Target header.
#[cfg(feature = "rpc")]
fn find_conn_target<R: Runtime>(
    context: &ProxyContext<R>,
    rpc_target: Option<&str>,
) -> Result<ConnTarget<R>, HttpConnectError> {
    let Some(target_id) = rpc_target else {
        return Ok(ConnTarget::Client(Box::new(context.tor_client.clone())));
    };

    let Some(rpc_mgr) = &context.rpc_mgr else {
        return Err(HttpConnectError::NoRpcSupport);
    };

    let (context, object) = rpc_mgr
        .lookup_object(&rpc::ObjectId::from(target_id))
        .map_err(|_| HttpConnectError::RpcObjectNotFound)?;

    Ok(ConnTarget::Rpc { object, context })
}

/// Look up the connection target given the value of an Tor-RPC-Target header
//
// (This is the implementation when we have no RPC support.)
#[cfg(not(feature = "rpc"))]
fn find_conn_target<R: Runtime>(
    context: &ProxyContext<R>,
    rpc_target: Option<&str>,
) -> Result<arti_client::TorClient<R>, HttpConnectError> {
    if rpc_target.is_some() {
        Err(HttpConnectError::NoRpcSupport)
    } else {
        Ok(context.tor_client.clone())
    }
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
        let bld = add_common_headers(self, method).header(hdr::CONTENT_TYPE, "text/plain");
        Ok(bld
            .body(message.into())
            .map_err(into_internal!("Formatting HTTP response"))?)
    }
}

/// Add all common headers to the builder `bld`, and return a new builder.
fn add_common_headers(mut bld: ResponseBuilder, method: &Method) -> ResponseBuilder {
    bld = bld.header(hdr::TOR_CAPABILITIES, "");
    if let (Some(software), Some(version)) = (
        option_env!("CARGO_PKG_NAME"),
        option_env!("CARGO_PKG_VERSION"),
    ) {
        if method == Method::CONNECT {
            bld = bld.header(
                hdr::VIA,
                format!("tor/1.0 tor-network ({software} {version})"),
            );
        } else {
            bld = bld.header(hdr::SERVER, format!("tor/1.0 ({software} {version})"));
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

    /// We found a duplicate HTTP header that we do not allow.
    ///
    /// (We only enforce this for the headers that we look at ourselves.)
    #[error("Duplicate HTTP header found.")]
    DuplicateHeader,

    /// We tried to found an HTTP header whose value wasn't encode as UTF-8.
    ///
    /// (We only enforce this for the headers that we look at ourselves.)
    #[error("HTTP header value was not in UTF-8")]
    HeaderNotUtf8,

    /// The Tor-Family-Preference header wasn't as expected.
    #[error("Unrecognized value for {}", hdr::TOR_FAMILY_PREFERENCE)]
    InvalidFamilyPreference,

    /// The user asked to use an RPC object, but we don't support RPC.
    #[error(
        "Found {} header, but we are running without RPC support",
        hdr::TOR_RPC_TARGET
    )]
    NoRpcSupport,

    /// The user asked to use an RPC object, but we didn't find the one they wanted.
    #[error("RPC target object not found")]
    RpcObjectNotFound,

    /// arti_client was unable to connect to a stream target.
    #[error("Unable to connect to {0}")]
    ConnectFailed(Sv<TorAddr>, #[source] ClientError),

    /// We encountered an internal error.
    #[error("Internal error while handling request")]
    Internal(#[from] tor_error::Bug),
}

impl HasKind for HttpConnectError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use HttpConnectError as HCE;
        match self {
            HCE::InvalidStreamTarget(_, _)
            | HCE::DuplicateHeader
            | HCE::HeaderNotUtf8
            | HCE::InvalidFamilyPreference
            | HCE::RpcObjectNotFound => EK::LocalProtocolViolation,
            HCE::NoRpcSupport => EK::FeatureDisabled,
            HCE::ConnectFailed(_, e) => e.kind(),
            HCE::Internal(e) => e.kind(),
        }
    }
}

impl HttpConnectError {
    /// Return an appropriate HTTP status code for this error.
    fn status_code(&self) -> StatusCode {
        use HttpConnectError as HCE; // Not a Joyce reference
        use StatusCode as SC;
        match self {
            HCE::InvalidStreamTarget(_, _)
            | HCE::DuplicateHeader
            | HCE::HeaderNotUtf8
            | HCE::InvalidFamilyPreference
            | HCE::RpcObjectNotFound
            | HCE::NoRpcSupport => SC::BAD_REQUEST,
            HCE::ConnectFailed(_, e) => kind_to_status(e.kind()),
            HCE::Internal(e) => kind_to_status(e.kind()),
        }
    }

    /// If possible, return a response that we should give to this error.
    fn try_into_response(self) -> Result<Response<Body>, HttpConnectError> {
        let error_kind = self.kind();
        let status_code = self.status_code();
        // TODO: It would be neat to also include specific END reasons here.  But to get them we'd
        // need to depend on the "details" feature of arti-client, which I'm not sure we want to do.
        //
        // If we _do_ get a way to extract END reasons, we can also use them manually alongside
        // kind_to_status.
        ResponseBuilder::new()
            .status(status_code)
            .header(hdr::TOR_REQUEST_FAILED, format!("arti/{error_kind:?}"))
            .err(&Method::CONNECT, self.report().to_string())
    }
}

/// Convert an ErrorKind into a StatusCode.
//
// TODO: Perhaps move this to tor-error, so it can be an exhaustive match.
fn kind_to_status(kind: ErrorKind) -> StatusCode {
    use http::StatusCode as SC;
    use tor_error::ErrorKind as EK;
    match kind {
        EK::ArtiShuttingDown
        | EK::BadApiUsage
        | EK::BootstrapRequired
        | EK::CacheAccessFailed
        | EK::CacheCorrupted
        | EK::ClockSkew
        | EK::DirectoryExpired
        | EK::ExternalToolFailed
        | EK::FsPermissions
        | EK::Internal
        | EK::InvalidConfig
        | EK::InvalidConfigTransition
        | EK::KeystoreAccessFailed
        | EK::KeystoreCorrupted
        | EK::NoHomeDirectory
        | EK::Other
        | EK::PersistentStateAccessFailed
        | EK::PersistentStateCorrupted
        | EK::SoftwareDeprecated
        | EK::TorDirectoryUnusable
        | EK::TransientFailure
        | EK::ReactorShuttingDown
        | EK::RelayIdMismatch
        | EK::RelayTooBusy
        | EK::TorAccessFailed
        | EK::TorDirectoryError => SC::INTERNAL_SERVER_ERROR,

        EK::FeatureDisabled | EK::NotImplemented => SC::NOT_IMPLEMENTED,

        EK::CircuitCollapse
        | EK::CircuitRefused
        | EK::ExitPolicyRejected
        | EK::LocalNetworkError
        | EK::LocalProtocolViolation
        | EK::LocalResourceAlreadyInUse
        | EK::LocalResourceExhausted
        | EK::NoExit
        | EK::NoPath => SC::SERVICE_UNAVAILABLE,

        EK::TorProtocolViolation | EK::RemoteProtocolViolation | EK::RemoteNetworkFailed => {
            SC::BAD_GATEWAY
        }

        EK::ExitTimeout | EK::TorNetworkTimeout | EK::RemoteNetworkTimeout => SC::GATEWAY_TIMEOUT,

        EK::ForbiddenStreamTarget => SC::FORBIDDEN,

        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceAddressInvalid | EK::InvalidStreamTarget => SC::BAD_REQUEST,
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceWrongClientAuth => SC::FORBIDDEN,
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceConnectionFailed
        | EK::OnionServiceMissingClientAuth
        | EK::OnionServiceNotFound
        | EK::OnionServiceNotRunning
        | EK::OnionServiceProtocolViolation => SC::SERVICE_UNAVAILABLE,

        EK::RemoteConnectionRefused
        | EK::RemoteHostNotFound
        | EK::RemoteHostResolutionFailed
        | EK::RemoteStreamClosed
        | EK::RemoteStreamError
        | EK::RemoteStreamReset => SC::SERVICE_UNAVAILABLE,

        _ => SC::INTERNAL_SERVER_ERROR,
    }
}

/// Recover the original stream from a [`hyper::upgrade::Upgraded`].
fn deconstruct_upgrade<S>(upgraded: hyper::upgrade::Upgraded) -> Result<S, anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let parts: hyper::upgrade::Parts<FuturesIoCompat<BufReader<S>>> = upgraded
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
    let io: BufReader<S> = io.0;
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

/// Helper module: Make `futures` types usable by `hyper`.
//
// TODO: We may want to expose this as a separate crate, or move it into tor-async-utils,
// if we turn out to need it elsewhere.
mod hyper_futures_io {
    use pin_project::pin_project;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use hyper::rt::ReadBufCursor;

    /// A wrapper around an AsyncBufRead + AsyncWrite to implement traits required by hyper.
    #[derive(Debug)]
    #[pin_project]
    pub(super) struct FuturesIoCompat<T>(#[pin] pub(super) T);

    impl<T> hyper::rt::Read for FuturesIoCompat<T>
    where
        // We require AsyncBufRead here it is a good match for ReadBufCursor::put_slice.
        T: futures::io::AsyncBufRead,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            mut buf: ReadBufCursor<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let mut this = self.project();

            let available: &[u8] = ready!(this.0.as_mut().poll_fill_buf(cx))?;
            let n_available = available.len();

            if !available.is_empty() {
                buf.put_slice(available);
                this.0.consume(n_available);
            }

            // This means either "data arrived" or "EOF" depending on whether we added new bytes.
            Poll::Ready(Ok(()))
        }
    }

    impl<T> hyper::rt::Write for FuturesIoCompat<T>
    where
        T: futures::io::AsyncWrite,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.project().0.poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.project().0.poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.project().0.poll_close(cx)
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

    // Make sure that HeaderMap is case-insensitive as the documentation implies.
    #[test]
    fn headermap_casei() {
        use http::header::{HeaderMap, HeaderValue};
        let mut hm = HeaderMap::new();
        hm.append(
            "my-head-is-a-house-for",
            HeaderValue::from_str("a-secret").unwrap(),
        );
        assert_eq!(
            hm.get("My-Head-Is-A-House-For").unwrap().as_bytes(),
            b"a-secret"
        );
        assert_eq!(
            hm.get("MY-HEAD-IS-A-HOUSE-FOR").unwrap().as_bytes(),
            b"a-secret"
        );
    }
}
