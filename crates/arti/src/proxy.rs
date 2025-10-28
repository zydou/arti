//! Implement a simple proxy that relays connections over Tor.
//!
//! A proxy is launched with [`run_proxy()`], which listens for new
//! connections, handles an appropriate handshake,
//! and then relays traffic as appropriate.

semipublic_mod! {
    #[cfg(feature="http-connect")]
    mod http_connect;
    mod socks;
}

use futures::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Error as IoError,
};
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::io::Result as IoResult;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

#[allow(unused)]
use arti_client::HasKind;
use arti_client::TorClient;
#[cfg(feature = "rpc")]
use arti_rpcserver::RpcMgr;
use tor_config::Listen;
use tor_error::warn_report;
use tor_rtcompat::{NetStreamListener, Runtime};
use tor_socksproto::SocksAuth;

use anyhow::{Context, Result, anyhow};

use crate::rpc::RpcProxySupport;

/// Placeholder type when RPC is disabled at compile time.
#[cfg(not(feature = "rpc"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum RpcMgr {}

/// A Key used to isolate connections.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection, the source IpAddr of the client, and the
/// authentication string provided by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamIsolationKey(ListenerIsolation, ProvidedIsolation);

/// Isolation information provided through the proxy connection
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProvidedIsolation {
    /// The socks isolation itself.
    LegacySocks(SocksAuth),
    /// A bytestring provided as isolation with the extended Socks5 username/password protocol.
    ExtendedSocks {
        /// Which format was negotiated?
        ///
        /// (At present, different format codes can't share a circuit.)
        format_code: u8,
        /// What's the isolation string?
        isolation: Box<[u8]>,
    },
    #[cfg(feature = "http-connect")]
    /// An HTTP token, taken from headers.
    Http(http_connect::Isolation),
}

impl arti_client::isolation::IsolationHelper for StreamIsolationKey {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self == other {
            Some(self.clone())
        } else {
            None
        }
    }
}

/// Size of read buffer to apply to application data streams.
//
// This particular value is chosen more or less arbitrarily.
// Larger values let us do fewer reads from the application,
// but consume more memory.
//
// (The default value for BufReader is 8k as of this writing.)
const APP_STREAM_BUF_LEN: usize = 4096;

const _: () = {
    assert!(APP_STREAM_BUF_LEN >= tor_socksproto::SOCKS_BUF_LEN);
};

/// NOTE: The following documentation belongs in a spec.
/// But for now, it's our best attempt to document the design and protocol
/// implemented here
/// for integrating proxies with our RPC system. --nickm
///
/// Roughly speaking:
///
/// ## Key concepts
///
/// A data stream is "RPC-visible" if, when it is created via a proxy connection,
/// the RPC system is told about it.
///
/// Every RPC-visible stream is associated with a given RPC object when it is created.
/// (Since the RPC object is being specified in the proxy protocol,
/// it must be one with an externally visible Object ID.
/// Such Object IDs are cryptographically unguessable and unforgeable,
/// and are qualified with a unique identifier for their associated RPC session.)
/// Call this RPC Object the "target" object for now.
/// This target RPC object must implement
/// the [`ConnectWithPrefs`](arti_client::rpc::ConnectWithPrefs) special method.
///
/// Right now, there are two general kinds of objects that implement this method:
/// client-like objects, and one-shot clients.
///
/// A client-like object is either a `TorClient` or an RPC `Session`.
/// It knows about and it is capable of opening multiple data streams.
/// Using it as the target object for a proxy connection tells Arti
/// that the resulting data stream (if any)
/// should be built by it, and associated with its RPC session.
///
/// An application gets a TorClient by asking the session for one,
/// or for asking a TorClient to give you a new variant clone of itself.
///
/// A one-shot client is an `arti_rpcserver::stream::OneshotClient`.
/// It is created from a client-like object, but can only be used for a single data stream.
/// When created, it it not yet connected or trying to connect to anywhere:
/// the act of using it as the target Object for a proxy connection causes
/// it to begin connecting.
///
/// An application gets a `OneShotClient` by calling `arti:new_oneshot_client`
/// on any client-like object.
///
/// ## The Proxy protocol
///
/// See the specification for
/// [SOCKS extended authentication](https://spec.torproject.org/socks-extensions.html#extended-auth)
/// for full details on integrating RPC with SOCKS.
/// For HTTP integration, see
/// [the relevant section of prop365](https://spec.torproject.org/proposals/365-http-connect-ext.html#x-tor-rpc-target-arti-rpc-support).
///
/// ### Further restrictions on Object IDs and isolation
///
/// In some cases,
/// the RPC Object ID may denote an object
/// that already includes information about its intended stream isolation.
/// In such cases, the stream isolation MUST be blank.
/// Implementations MUST reject non-blank stream isolation in such cases.
///
/// In some cases, the RPC object ID may denote an object
/// that already includes information
/// about its intended destination address and port.
/// In such cases, the destination address MUST be `0.0.0.0` or `::`
/// (encoded either as an IPv4 address, an IPv6 address, or a hostname)
/// and the destination port MUST be 0.
/// Implementations MUST reject other addresses in such cases.
///
/// ### Another proposed change
///
/// We could add a new method to clients, with a name like
/// "open_stream" or "connect_stream".
/// This method would include all target and isolation information in its parameters.
/// It would actually create a DataStream immediately, tell it to begin connecting,
/// and return an externally visible object ID.
/// The RPC protocol could be used to watch the DataStream object,
/// to see when it was connected.
///
/// The resulting DataStream object could also be used as the target of a proxy connection.
/// We would require in such a case that no isolation be provided in the proxy handshake,
/// and that the target address was (e.g.) INADDR_ANY.
///
/// ## Intended use cases (examples)
///
/// (These examples assume that the application
/// already knows the proxy port it should use.
/// I'm leaving out the isolation strings as orthogonal.)
///
/// These are **NOT** the only possible use cases;
/// they're just the two that help understand this system best (I hope).
///
/// ### Case 1: Using a client-like object directly.
///
/// Here the application has authenticated to RPC
/// and gotten the session ID `SESSION-1`.
/// (In reality, this would be a longer ID, and full of crypto).
///
/// The application wants to open a new stream to www.example.com.
/// They don't particularly care about isolation,
/// but they do want their stream to use their RPC session.
/// They don't want an Object ID for the stream.
///
/// To do this, they make a SOCKS connection to arti,
/// with target address www.example.com.
/// They set the username to `<torS0X>0SESSION-1`,
/// and the password to the empty string.
///
/// (Alternatively, it could use HTTP CONNECT, setting
/// Tor-Rpc-Target to SESSION-1.)
///
/// Arti looks up the Session object via the `SESSION-1` object ID
/// and tells it (via the ConnectWithPrefs special method)
/// to connect to www.example.com.
/// The session creates a new DataStream using its internal TorClient,
/// but does not register the stream with an RPC Object ID.
/// Arti proxies the application's connection through this DataStream.
///
///
/// ### Case 2: Creating an identifiable stream.
///
/// Here the application wants to be able to refer to its DataStream
/// after the stream is created.
/// As before, we assume that it's on an RPC session
/// where the Session ID is `SESSION-1`.
///
/// The application sends an RPC request of the form:
/// `{"id": 123, "obj": "SESSION-1", "method": "arti:new_oneshot_client", "params": {}}`
///
/// It receives a reply like:
/// `{"id": 123, "result": {"id": "STREAM-1"} }`
///
/// (In reality, `STREAM-1` would also be longer and full of crypto.)
///
/// Now the application has an object called `STREAM-1` that is not yet a connected
/// stream, but which may become one.
///
/// This time, it wants to set its isolation string to "xyzzy".
///
/// The application opens a socks connection as before.
/// For the username it sends `<torS0X>0STREAM-1`,
/// and for the password it sends `xyzzy`.
///
/// (Alternatively, it could use HTTP CONNECT, setting Tor-Isolation to xyzzy,
/// and Tor-Rpc-Target to STREAM-1.)
///
/// Now Arti looks up the `RpcDataStream` object via `STREAM-1`,
/// and tells it (via the ConnectWithPrefs special method)
/// to connect to www.example.com.
/// This causes the `RpcDataStream` internally to create a new `DataStream`,
/// and to store that `DataStream` in itself.
/// The `RpcDataStream` with Object ID `STREAM-1`
/// is now an alias for the newly created `DataStream`.
/// Arti proxies the application's connection through that `DataStream`.
///
#[cfg(feature = "rpc")]
#[allow(dead_code)]
mod socks_and_rpc {}

/// Information used to implement a proxy listener.
struct ProxyContext<R: Runtime> {
    /// A TorClient to use (by default) to anonymize requests.
    tor_client: TorClient<R>,
    /// If present, an RpcMgr to use when for attaching requests to RPC
    /// sessions.
    #[cfg(feature = "rpc")]
    rpc_mgr: Option<Arc<arti_rpcserver::RpcMgr>>,
}

/// Type alias for the isolation information associated with a given proxy
/// connection _before_ any negotiation occurs.
///
/// Currently this is an index for which listener accepted the connection, plus
/// the address of the client that connected to the proxy port.
type ListenerIsolation = (usize, IpAddr);

/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing proxy reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing proxy stream")
}

/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing proxy reply")?;
    writer
        .close()
        .await
        .context("Error while closing proxy stream")
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
#[instrument(skip_all, level = "trace")]
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; APP_STREAM_BUF_LEN];

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

/// Return true if a given IoError, when received from accept, is a fatal
/// error.
fn accept_err_is_fatal(err: &IoError) -> bool {
    #![allow(clippy::match_like_matches_macro)]

    /// Re-declaration of WSAEMFILE with the right type to match
    /// `raw_os_error()`.
    #[cfg(windows)]
    const WSAEMFILE: i32 = winapi::shared::winerror::WSAEMFILE as i32;

    // Currently, EMFILE and ENFILE aren't distinguished by ErrorKind;
    // we need to use OS-specific errors. :P
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EMFILE) | Some(libc::ENFILE) => false,
        #[cfg(windows)]
        Some(WSAEMFILE) => false,
        _ => true,
    }
}

/// Launch a proxy to listen on a given localhost port, and run
/// indefinitely.
///
/// Requires a `runtime` to use for launching tasks and handling
/// timeouts, and a `tor_client` to use in connecting over the Tor
/// network.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[allow(clippy::cognitive_complexity)] // TODO: Refactor
#[instrument(skip_all, level = "trace")]
pub(crate) async fn run_proxy<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    listen: Listen,
    rpc_data: Option<RpcProxySupport>,
) -> Result<()> {
    #[cfg(feature = "rpc")]
    let (rpc_mgr, mut rpc_state_sender) = match rpc_data {
        Some(RpcProxySupport {
            rpc_mgr,
            rpc_state_sender,
        }) => (Some(rpc_mgr), Some(rpc_state_sender)),
        None => (None, None),
    };
    #[cfg(not(feature = "rpc"))]
    let rpc_mgr = None;

    if !listen.is_localhost_only() {
        warn!(
            "Configured to listen for proxy connections on non-local addresses. \
            This is usually insecure! We recommend listening on localhost only."
        );
    }

    let mut listeners = Vec::new();
    let mut listening_on_addrs = Vec::new();

    // Try to bind to the listener ports.
    match listen.ip_addrs() {
        Ok(addrgroups) => {
            for addrgroup in addrgroups {
                for addr in addrgroup {
                    match runtime.listen(&addr).await {
                        Ok(listener) => {
                            info!("Listening on {:?}.", addr);
                            listeners.push(listener);
                            listening_on_addrs.push(addr);
                        }
                        #[cfg(unix)]
                        Err(ref e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => {
                            warn_report!(e, "Address family not supported {}", addr);
                        }
                        Err(ref e) => {
                            return Err(anyhow!("Can't listen on {}: {e}", addr));
                        }
                    }
                }
            }
        }
        Err(e) => warn_report!(e, "Invalid listen spec"),
    }

    // We weren't able to bind any ports: There's nothing to do.
    if listeners.is_empty() {
        error!("Couldn't open any listeners.");
        return Err(anyhow!("Couldn't open listeners"));
    }

    cfg_if::cfg_if! {
        if #[cfg(feature="rpc")] {
            if let Some(rpc_state_sender) = &mut rpc_state_sender {
                rpc_state_sender.set_socks_listeners(&listening_on_addrs[..]);
            }
        } else {
            let _ = listening_on_addrs;
        }
    }

    run_proxy_with_listeners(tor_client, listeners, rpc_mgr).await
}

/// Launch a proxy from a given set of already bound listeners.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[instrument(skip_all, level = "trace")]
pub(crate) async fn run_proxy_with_listeners<R: Runtime>(
    tor_client: TorClient<R>,
    listeners: Vec<<R as tor_rtcompat::NetStreamProvider>::Listener>,
    rpc_mgr: Option<Arc<RpcMgr>>,
) -> Result<()> {
    // Create a stream of (incoming socket, listener_id) pairs, selected
    // across all the listeners.
    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(NetStreamListener::incoming)
            .enumerate()
            .map(|(listener_id, incoming_conns)| {
                incoming_conns.map(move |socket| (socket, listener_id))
            }),
    );

    // Loop over all incoming connections.  For each one, call
    // handle_proxy_conn() in a new task.
    while let Some((stream, sock_id)) = incoming.next().await {
        let (stream, addr) = match stream {
            Ok((s, a)) => (s, a),
            Err(err) => {
                if accept_err_is_fatal(&err) {
                    return Err(err).context("Failed to receive incoming stream on proxy port");
                } else {
                    warn_report!(err, "Incoming stream failed");
                    continue;
                }
            }
        };
        let proxy_context = ProxyContext {
            tor_client: tor_client.clone(),
            #[cfg(feature = "rpc")]
            rpc_mgr: rpc_mgr.clone(),
        };
        let runtime_copy = tor_client.runtime().clone();
        tor_client.runtime().spawn(async move {
            let res =
                handle_proxy_conn(runtime_copy, proxy_context, stream, (sock_id, addr.ip())).await;
            if let Err(e) = res {
                // TODO: warn_report doesn't work on anyhow::Error.
                warn!("connection exited with error: {}", tor_error::Report(e));
            }
        })?;
    }

    Ok(())
}

/// A (possibly) supported proxy protocol.
enum ProxyProtocols {
    /// Some HTTP/1 command or other.
    ///
    /// (We only support CONNECT and OPTIONS, but we reject other commands in [`http_connect`].)
    Http1,
    /// SOCKS4 or SOCKS5.
    Socks,
}

/// Look at the first byte of a proxy connection, and guess what protocol
/// what protocol it is trying to speak.
fn classify_protocol_from_first_byte(byte: u8) -> Option<ProxyProtocols> {
    match byte {
        b'a'..=b'z' | b'A'..=b'Z' => Some(ProxyProtocols::Http1),
        4 | 5 => Some(ProxyProtocols::Socks),
        _ => None,
    }
}

/// Handle a single connection `stream` from an application.
///
/// Depending on what protocol the application is speaking
/// (and what protocols we support!), negotiate an appropriate set of options,
/// and relay traffic to and from the application.
async fn handle_proxy_conn<R, S>(
    runtime: R,
    context: ProxyContext<R>,
    stream: S,
    isolation_info: ListenerIsolation,
) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let mut stream = BufReader::with_capacity(APP_STREAM_BUF_LEN, stream);
    use futures::AsyncBufReadExt as _;

    let buf: &[u8] = stream.fill_buf().await?;
    if buf.is_empty() {
        // connection closed
        return Ok(());
    }
    match classify_protocol_from_first_byte(buf[0]) {
        Some(ProxyProtocols::Http1) => {
            cfg_if::cfg_if! {
                if #[cfg(feature="http-connect")] {
                    http_connect::handle_http_conn(context, stream, isolation_info).await
                } else {
                    write_all_and_close(&mut stream, socks::WRONG_PROTOCOL_PAYLOAD).await?;
                    Ok(())
                }
            }
        }
        Some(ProxyProtocols::Socks) => {
            socks::handle_socks_conn(runtime, context, stream, isolation_info).await
        }
        None => {
            // We have no idea what protocol the client expects,
            // so we have no idea how to tell it so.
            warn!(
                "Unrecognized protocol on proxy listener (first byte {:x})",
                buf[0]
            );
            Ok(())
        }
    }
}
