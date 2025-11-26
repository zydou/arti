//! Implement an HTTP1 CONNECT proxy using `hyper`.
//!
//! Note that Tor defines several extensions to HTTP CONNECT;
//! See [the spec](spec.torproject.org/http-connect.html)
//! for more information.

use super::{ListenerIsolation, ProxyContext};
use anyhow::{Context as _, anyhow};
use arti_client::{StreamPrefs, TorAddr};
use futures::{AsyncRead, AsyncWrite, io::BufReader};
use http::{Method, StatusCode, response::Builder as ResponseBuilder};
use hyper::{Response, server::conn::http1::Builder as ServerBuilder, service::service_fn};
use safelog::{Sensitive as Sv, sensitive as sv};
use tor_error::{ErrorKind, ErrorReport as _, HasKind, into_internal, warn_report};
use tor_rtcompat::Runtime;
use tor_rtcompat::SpawnExt as _;
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

impl Isolation {
    /// Return true if no isolation field in this object is set.
    pub(super) fn is_empty(&self) -> bool {
        let Isolation {
            proxy_auth,
            x_tor_isolation,
            tor_isolation,
        } = self;
        proxy_auth.as_ref().is_none_or(ProxyAuthorization::is_empty)
            && x_tor_isolation.as_ref().is_none_or(String::is_empty)
            && tor_isolation.as_ref().is_none_or(String::is_empty)
    }
}

/// Constants and code for the HTTP headers we use.
mod hdr {
    pub(super) use http::header::{CONTENT_TYPE, HOST, PROXY_AUTHORIZATION, SERVER, VIA};

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

    /// A list of all the headers that we support from client-to-proxy.
    ///
    /// Does not include headers that we check for HTTP conformance,
    /// but not for any other purpose.
    pub(super) const ALL_REQUEST_HEADERS: &[&str] = &[
        TOR_FAMILY_PREFERENCE,
        TOR_RPC_TARGET,
        X_TOR_STREAM_ISOLATION,
        TOR_STREAM_ISOLATION,
        // Can't use 'PROXY_AUTHORIZATION', since it isn't a str, and its as_str() isn't const.
        "Proxy-Authorization",
    ];

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
    // Avoid cross-site attacks based on DNS forgery by validating that the Host
    // header is in fact localhost.  In these cases, we don't want to reply at all,
    // _even with an error message_, since our headers could be used to tell a hostile
    // webpage information about the local arti process.
    //
    // We don't do this for CONNECT requests, since those are forbidden by
    // XHR and JS fetch(), and since Host _will_ be non-localhost for those.
    if request.method() != Method::CONNECT {
        match hdr::uniq_utf8(request.headers(), hdr::HOST) {
            Err(e) => return Err(e).context("Host header invalid. Rejecting request."),
            Ok(Some(host)) if !host_is_localhost(host) => {
                return Err(anyhow!(
                    "Host header {host:?} was not localhost. Rejecting request."
                ));
            }
            Ok(_) => {}
        }
    }

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
    context
        .tor_client
        .runtime()
        .spawn(async move {
            match transfer::<S>(request, tor_stream).await {
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

    /// Return true if this ProxyAuthorization has no authorization information.
    fn is_empty(&self) -> bool {
        match self {
            ProxyAuthorization::Legacy(s) => s.is_empty(),
            ProxyAuthorization::Modern(v) => v.is_empty(),
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

/// Return a string representing our capabilities.
fn capabilities() -> &'static str {
    use std::sync::LazyLock;
    static CAPS: LazyLock<String> = LazyLock::new(|| {
        let mut caps = hdr::ALL_REQUEST_HEADERS.to_vec();
        caps.sort();
        caps.join(" ")
    });

    CAPS.as_str()
}

/// Add all common headers to the builder `bld`, and return a new builder.
fn add_common_headers(mut bld: ResponseBuilder, method: &Method) -> ResponseBuilder {
    bld = bld.header(hdr::TOR_CAPABILITIES, capabilities());
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
        if let Some(end_reason) = self.remote_end_reason() {
            return end_reason_to_http_status(end_reason);
        }
        match self {
            HCE::InvalidStreamTarget(_, _)
            | HCE::DuplicateHeader
            | HCE::HeaderNotUtf8
            | HCE::InvalidFamilyPreference
            | HCE::RpcObjectNotFound
            | HCE::NoRpcSupport => SC::BAD_REQUEST,
            HCE::ConnectFailed(_, e) => e.kind().http_status_code(),
            HCE::Internal(e) => e.kind().http_status_code(),
        }
    }

    /// If possible, return a response that we should give to this error.
    fn try_into_response(self) -> Result<Response<Body>, HttpConnectError> {
        let error_kind = self.kind();
        let end_reason = self.remote_end_reason();
        let status_code = self.status_code();
        let mut request_failed = format!("arti/{error_kind:?}");
        if let Some(end_reason) = end_reason {
            request_failed.push_str(&format!(" end/{end_reason}"));
        }

        ResponseBuilder::new()
            .status(status_code)
            .header(hdr::TOR_REQUEST_FAILED, request_failed)
            .err(&Method::CONNECT, self.report().to_string())
    }

    /// Return the end reason for this error, if this error does in fact represent an END message
    /// from the remote side of a stream.
    //
    // TODO: This function is a bit fragile; it forces us to use APIs from tor-proto and
    // tor-cell that are not re-exported from arti-client.  It also relies on the fact that
    // there is a single error type way down in `tor-proto` representing a received END message.
    fn remote_end_reason(&self) -> Option<tor_cell::relaycell::msg::EndReason> {
        use tor_proto::Error as ProtoErr;
        let mut error: &(dyn std::error::Error + 'static) = self;
        loop {
            if let Some(ProtoErr::EndReceived(reason)) = error.downcast_ref::<ProtoErr>() {
                return Some(*reason);
            }
            if let Some(source) = error.source() {
                error = source;
            } else {
                return None;
            }
        }
    }
}

/// Return the appropriate HTTP status code for a remote END reason.
///
/// Return `None` if the END reason is unrecognized and we should use the `ErrorKind`
///
/// (We  _could_ use the ErrorKind unconditionally,
/// but the mapping from END reason to ErrorKind is [given in the spec][spec],
/// so we try to obey it.)
///
/// [spec]: https://spec.torproject.org/http-connect.html#error-codes
fn end_reason_to_http_status(end_reason: tor_cell::relaycell::msg::EndReason) -> StatusCode {
    use StatusCode as S;
    use tor_cell::relaycell::msg::EndReason as R;
    match end_reason {
        //
        R::CONNECTREFUSED => S::FORBIDDEN, // 403
        // 500: Internal server error.
        R::MISC | R::NOTDIRECTORY => S::INTERNAL_SERVER_ERROR,

        // 502: Bad Gateway.
        R::DESTROY | R::DONE | R::HIBERNATING | R::INTERNAL | R::RESOURCELIMIT | R::TORPROTOCOL => {
            S::BAD_GATEWAY
        }
        // 503: Service unavailable
        R::CONNRESET | R::EXITPOLICY | R::NOROUTE | R::RESOLVEFAILED => S::SERVICE_UNAVAILABLE,

        // 504: Gateway timeout.
        R::TIMEOUT => S::GATEWAY_TIMEOUT,

        // This is possible if the other side sent an unrecognized error code.
        _ => S::INTERNAL_SERVER_ERROR, // 500
    }
}

/// Recover the original stream from a [`hyper::upgrade::Upgraded`].
fn deconstruct_upgrade<S>(upgraded: hyper::upgrade::Upgraded) -> Result<BufReader<S>, anyhow::Error>
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
    Ok(io)
}

/// Recover the application stream from `request`, and launch tasks to transfer data between the application and
/// the `tor_stream`.
async fn transfer<S>(request: Request, tor_stream: arti_client::DataStream) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let upgraded = hyper::upgrade::on(request)
        .await
        .context("Unable to upgrade connection")?;
    let app_stream: BufReader<S> = deconstruct_upgrade(upgraded)?;
    let tor_stream = BufReader::with_capacity(super::APP_STREAM_BUF_LEN, tor_stream);

    // Finally. relay traffic between
    // the application stream and the tor stream, forever.
    let _ = futures_copy::copy_buf_bidirectional(
        app_stream,
        tor_stream,
        futures_copy::eof::Close,
        futures_copy::eof::Close,
    )
    .await?;

    Ok(())
}

/// Return true if `host` is a possible value for a Host header addressing localhost.
fn host_is_localhost(host: &str) -> bool {
    if let Ok(addr) = host.parse::<std::net::SocketAddr>() {
        addr.ip().is_loopback()
    } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip.is_loopback()
    } else if let Some((addr, port)) = host.split_once(':') {
        port.parse::<std::num::NonZeroU16>().is_ok() && addr.eq_ignore_ascii_case("localhost")
    } else {
        host.eq_ignore_ascii_case("localhost")
    }
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use arti_client::{BootstrapBehavior, TorClient, config::TorClientConfigBuilder};
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    use tor_rtmock::{MockRuntime, io::stream_pair};

    use super::*;

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

    #[test]
    fn host_header_localhost() {
        assert_eq!(host_is_localhost("localhost"), true);
        assert_eq!(host_is_localhost("localhost:9999"), true);
        assert_eq!(host_is_localhost("localHOSt:9999"), true);
        assert_eq!(host_is_localhost("127.0.0.1:9999"), true);
        assert_eq!(host_is_localhost("[::1]:9999"), true);
        assert_eq!(host_is_localhost("127.1.2.3:1234"), true);
        assert_eq!(host_is_localhost("127.0.0.1"), true);
        assert_eq!(host_is_localhost("::1"), true);

        assert_eq!(host_is_localhost("[::1]"), false); // not in the right format!
        assert_eq!(host_is_localhost("www.torproject.org"), false);
        assert_eq!(host_is_localhost("www.torproject.org:1234"), false);
        assert_eq!(host_is_localhost("localhost:0"), false);
        assert_eq!(host_is_localhost("localhost:999999"), false);
        assert_eq!(host_is_localhost("plocalhost:1234"), false);
        assert_eq!(host_is_localhost("[::0]:1234"), false);
        assert_eq!(host_is_localhost("192.0.2.55:1234"), false);
        assert_eq!(host_is_localhost("3fff::1"), false);
        assert_eq!(host_is_localhost("[3fff::1]:1234"), false);
    }

    fn interactive_test_setup(
        rt: &MockRuntime,
    ) -> anyhow::Result<(
        tor_rtmock::io::LocalStream,
        impl Future<Output = anyhow::Result<()>>,
        tempfile::TempDir,
    )> {
        let (s1, s2) = stream_pair();
        let s1: BufReader<_> = BufReader::new(s1);

        let iso: ListenerIsolation = (7, "127.0.0.1".parse().unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(
            dir.as_ref().join("state"),
            dir.as_ref().join("cache"),
        )
        .build()
        .unwrap();
        let tor_client = TorClient::with_runtime(rt.clone())
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()?;
        let context: ProxyContext<_> = ProxyContext {
            tor_client,
            #[cfg(feature = "rpc")]
            rpc_mgr: None,
        };
        let handle = rt.spawn_join("HTTP Handler", handle_http_conn(context, s1, iso));
        Ok((s2, handle, dir))
    }

    #[test]
    fn successful_options_test() -> anyhow::Result<()> {
        // Try an OPTIONS request and make sure we get a plausible-looking answer.
        //
        // (This test is mostly here to make sure that invalid_host_test() isn't failing because
        // of anything besides the Host header.)
        MockRuntime::try_test_with_various(async |rt| -> anyhow::Result<()> {
            let (mut s, join, _dir) = interactive_test_setup(&rt)?;

            s.write_all(b"OPTIONS * HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            let _n_read = s.read_to_end(&mut buf).await?;
            let () = join.await?;

            let reply = std::str::from_utf8(&buf)?;
            assert!(dbg!(reply).starts_with("HTTP/1.0 200 OK\r\n"));

            Ok(())
        })
    }

    #[test]
    fn invalid_host_test() -> anyhow::Result<()> {
        // Try a hostname that looks like a CSRF attempt and make sure that we discard it without
        // any reply.
        MockRuntime::try_test_with_various(async |rt| -> anyhow::Result<()> {
            let (mut s, join, _dir) = interactive_test_setup(&rt)?;

            s.write_all(b"OPTIONS * HTTP/1.0\r\nHost: csrf.example.com\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            let n_read = s.read_to_end(&mut buf).await?;
            let http_outcome = join.await;

            assert_eq!(n_read, 0);
            assert!(buf.is_empty());
            assert!(http_outcome.is_err());

            let error_msg = http_outcome.unwrap_err().source().unwrap().to_string();
            assert_eq!(
                error_msg,
                r#"Host header "csrf.example.com" was not localhost. Rejecting request."#
            );

            Ok(())
        })
    }
}
