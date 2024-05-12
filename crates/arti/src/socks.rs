//! Implement a simple SOCKS proxy that relays connections over Tor.
//!
//! A proxy is launched with [`run_socks_proxy()`], which listens for new
//! connections and then runs

use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Error as IoError};
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use safelog::sensitive;
use std::io::Result as IoResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature = "rpc")]
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[allow(unused)]
use arti_client::HasKind;
use arti_client::{ErrorKind, IntoTorAddr as _, StreamPrefs, TorClient};
use tor_config::Listen;
use tor_error::warn_report;
#[cfg(feature = "rpc")]
use tor_rpcbase::{self as rpc, ObjectArcExt as _};
use tor_rtcompat::{Runtime, TcpListener};
use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest};

use anyhow::{anyhow, Context, Result};

/// Payload to return when an HTTP connection arrive on a Socks port
const WRONG_PROTOCOL_PAYLOAD: &[u8] = br#"HTTP/1.0 501 Tor is not an HTTP Proxy
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>
</head>
<body>
<h1>This is a SOCKs proxy, not an HTTP proxy.</h1>
<p>
It appears you have configured your web browser to use this Tor port as
an HTTP proxy.
</p><p>
This is not correct: This port is configured as a SOCKS proxy, not
an HTTP proxy. If you need an HTTP proxy tunnel, wait for Arti to
add support for it in place of, or in addition to, socks_port.
Please configure your client accordingly.
</p>
<p>
See <a href="https://gitlab.torproject.org/tpo/core/arti/#todo-need-to-change-when-arti-get-a-user-documentation">https://gitlab.torproject.org/tpo/core/arti</a> for more information.
</p>
</body>
</html>"#;

/// Find out which kind of address family we can/should use for a
/// given `SocksRequest`.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
fn stream_preference(req: &SocksRequest, addr: &str) -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    if addr.parse::<Ipv4Addr>().is_ok() {
        // If they asked for an IPv4 address correctly, nothing else will do.
        prefs.ipv4_only();
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        // If they asked for an IPv6 address correctly, nothing else will do.
        prefs.ipv6_only();
    } else if req.version() == tor_socksproto::SocksVersion::V4 {
        // SOCKS4 and SOCKS4a only support IPv4
        prefs.ipv4_only();
    } else {
        // Otherwise, default to saying IPv4 is preferred.
        prefs.ipv4_preferred();
    }
    prefs
}

/// A Key used to isolate connections.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection, the source IpAddr of the client, and the
/// authentication string provided by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksIsolationKey(ConnIsolation, ProvidedIsolation);
/// Isolation information provided through the socks connection
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProvidedIsolation {
    /// The socks isolation itself.
    Auth(SocksAuth),
    /// A string provided as isolation with an RPC connection
    #[cfg(feature = "rpc")]
    RpcString(Option<String>),
}

impl arti_client::isolation::IsolationHelper for SocksIsolationKey {
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

/// The meaning of a SOCKS authentication field, according to our conventions.
struct AuthInterpretation {
    /// Assign this stream to a client determined by given RPC session, and
    /// register its existence with that session.
    #[cfg(feature = "rpc")]
    assign_to_session: Option<rpc::ObjectId>,

    /// Isolate this stream from other streams that do not have the same
    /// value.
    isolation: ProvidedIsolation,
}

/// Given the authentication object from a socks connection, determine what it's telling
/// us to do.
///
/// (In no case is it actually SOCKS authentication: it can either be a message
/// to the stream isolation system or the RPC system.)
fn interpret_socks_auth(auth: &SocksAuth) -> Result<AuthInterpretation> {
    // TODO RPC: This whole function and the way that it parses SOCKS
    // authentication is a placeholder (because we need to put _something_ here
    // for now).  We could probably come up with a much better design, and
    // should.
    //
    // TODO RPC: In our final design we should probably figure out way to
    // migrate away from the current "anything goes" approach to stream
    // isolation without breaking all the existing apps that think they can use
    // an arbitrary byte-string as their isolation token.

    /// A constant which, when it appears as a username, indicates that the
    /// stream is to be assigned to an Arti RPC session.
    const RPC_SESSION_CONST: &[u8] = b"<arti-rpc-session>";

    #[allow(unused_variables)] // TODO RPC remove
    match auth {
        SocksAuth::Username(user, pass) if user == RPC_SESSION_CONST => {
            cfg_if::cfg_if! {
                if #[cfg(feature="rpc")] {
                    let pass =
                        std::str::from_utf8(pass).context("rpc-session info must be utf-8")?;
                    let (session, isolation) = match pass.split_once(':') {
                        Some((s,i)) => (s.to_owned().into(), Some(i.to_owned())),
                        None => (pass.to_owned().into(), None),
                    };
                    Ok(AuthInterpretation {
                        assign_to_session: Some(session),
                        isolation: ProvidedIsolation::RpcString(isolation)
                    })
                } else {
                    Err(anyhow!("Not built with support for RPC"))
                }
            }
        }
        other_auth => Ok(AuthInterpretation {
            #[cfg(feature = "rpc")]
            assign_to_session: None,
            isolation: ProvidedIsolation::Auth(other_auth.clone()),
        }),
    }
}

/// Information used to implement a SOCKS connection.
struct SocksConnContext<R: Runtime> {
    /// A TorClient to use (by default) to anonymize requests.
    tor_client: TorClient<R>,
    /// If present, an RpcMgr to use when for attaching requests to RPC
    /// sessions.
    #[cfg(feature = "rpc")]
    rpc_mgr: Option<Arc<arti_rpcserver::RpcMgr>>,
}

/// Type alias for the isolation information associated with a given SOCKS
/// connection _before_ SOCKS is negotiated.
///
/// Currently this is an index for which listener accepted the connection, plus
/// the address of the client that connected to the Socks port.
type ConnIsolation = (usize, IpAddr);

/// Define a macro to return the type that we use to represent Arti sessions.
///
/// TODO RPC: This is ugly! We can't use a type alias (e.g. `type Foo<R> = ...`) for parameterization reasons.
/// Under no circumstances should this awful thing propagate outside this module.
/// XXXX do not merge unless this is resolved.
#[cfg(feature = "rpc")]
macro_rules! session_type {
    () => { Arc<dyn arti_client::rpc::ClientConnectionTarget> };
}
/// Define a macro to return the type we use to represent Arti sessions.
#[cfg(not(feature = "rpc"))]
macro_rules! session_type {
    () => { TorClient<R>};
}

impl<R: Runtime> SocksConnContext<R> {
    /// Interpret a SOCKS request and our input information to determine which
    /// TorClient object and StreamPrefs we should use.
    ///
    /// TODO RPC: This API is horrible and needs revision; once it gets it, we
    /// should document it much better. XXXX Do not merge unless this is resolved.
    fn get_prefs_and_session(
        &self,
        request: &SocksRequest,
        target_addr: &str,
        conn_isolation: ConnIsolation,
    ) -> Result<(StreamPrefs, session_type!())> {
        // Determine whether we want to ask for IPv4/IPv6 addresses.
        let mut prefs = stream_preference(request, target_addr);

        // Interpret socks authentication to see whether we want to connect to an RPC connector.
        let interp = interpret_socks_auth(request.auth())?;
        prefs.set_isolation(SocksIsolationKey(conn_isolation, interp.isolation));

        #[cfg(feature = "rpc")]
        if let Some(session) = interp.assign_to_session {
            {
                // XXXX remove this indentation
                if let Some(mgr) = &self.rpc_mgr {
                    let session = mgr
                        .lookup_object(&session)
                        .context("no such session found")?;
                    let target: Arc<dyn arti_client::rpc::ClientConnectionTarget> = session
                        .cast_to_arc_trait()
                        .map_err(|_| anyhow!("Target did not implement ClientConnectionTarget"))?;

                    return Ok((prefs, target));
                } else {
                    return Err(anyhow!("no rpc manager found!?"));
                }
            }
        }

        let client = self.tor_client.clone();
        #[cfg(feature = "rpc")]
        let client = Arc::new(client);

        Ok((prefs, client))
    }
}

/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_info` to decide which circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
async fn handle_socks_conn<R, S>(
    runtime: R,
    context: SocksConnContext<R>,
    socks_stream: S,
    isolation_info: ConnIsolation,
) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Part 1: Perform the SOCKS handshake, to learn where we are
    // being asked to connect, and what we're being asked to do once
    // we connect there.
    //
    // The SOCKS handshake can require multiple round trips (SOCKS5
    // always does) so we we need to run this part of the process in a
    // loop.
    let mut handshake = tor_socksproto::SocksProxyHandshake::new();

    let (mut socks_r, mut socks_w) = socks_stream.split();
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        if n_read == inbuf.len() {
            // We would like to read more of this SOCKS request, but there is no
            // more space in the buffer.  If we try to keep reading into an
            // empty buffer, we'll just read nothing, try to parse it, and learn
            // that we still wish we had more to read.
            //
            // In theory we might want to resize the buffer.  Right now, though,
            // we just reject handshakes that don't fit into 1k.
            return Err(anyhow!("Socks handshake did not fit in 1KiB buffer"));
        }
        // Read some more stuff.
        n_read += socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // try to advance the handshake to the next state.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => continue, // Message truncated.
            Ok(Err(e)) => {
                if let tor_socksproto::Error::BadProtocol(version) = e {
                    // check for HTTP methods: CONNECT, DELETE, GET, HEAD, OPTION, PUT, POST, PATCH and
                    // TRACE.
                    // To do so, check the first byte of the connection, which happen to be placed
                    // where SOCKs version field is.
                    if [b'C', b'D', b'G', b'H', b'O', b'P', b'T'].contains(&version) {
                        write_all_and_close(&mut socks_w, WRONG_PROTOCOL_PAYLOAD).await?;
                    }
                }
                // if there is an handshake error, don't reply with a Socks error, remote does not
                // seems to speak Socks.
                return Err(e.into());
            }
            Ok(Ok(action)) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            inbuf.copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            write_all_and_flush(&mut socks_w, &action.reply).await?;
        }
        if action.finished {
            break handshake.into_request();
        }
    };
    let request = match request {
        Some(r) => r,
        None => {
            warn!("SOCKS handshake succeeded, but couldn't convert into a request.");
            return Ok(());
        }
    };

    // Unpack the socks request and find out where we're connecting to.
    let addr = request.addr().to_string();
    let port = request.port();
    debug!(
        "Got a socks request: {} {}:{}",
        request.command(),
        sensitive(&addr),
        port
    );

    let (prefs, tor_client) = context.get_prefs_and_session(&request, &addr, isolation_info)?;

    match request.command() {
        SocksCmd::CONNECT => {
            // The SOCKS request wants us to connect to a given address.
            // So, launch a connection over Tor.
            let tor_addr = (addr.clone(), port).into_tor_addr()?;
            let tor_stream = tor_client.connect_with_prefs(&tor_addr, &prefs).await;
            let tor_stream = match tor_stream {
                Ok(s) => s,
                Err(e) => return reply_error(&mut socks_w, &request, e.kind()).await,
            };
            // Okay, great! We have a connection over the Tor network.
            debug!("Got a stream for {}:{}", sensitive(&addr), port);

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request
                .reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .context("Encoding socks reply")?;
            write_all_and_flush(&mut socks_w, &reply[..]).await?;

            let (tor_r, tor_w) = tor_stream.split();

            // Finally, spawn two background tasks to relay traffic between
            // the socks stream and the tor stream.
            runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
            runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
        }
        SocksCmd::RESOLVE => {
            // We've been asked to perform a regular hostname lookup.
            // (This is a tor-specific SOCKS extension.)

            let addr = if let Ok(addr) = addr.parse() {
                // if this is a valid ip address, just parse it and reply.
                Ok(addr)
            } else {
                tor_client
                    .resolve_with_prefs(&addr, &prefs)
                    .await
                    .map_err(|e| e.kind())
                    .and_then(|addrs| addrs.first().copied().ok_or(ErrorKind::Other))
            };
            match addr {
                Ok(addr) => {
                    let reply = request
                        .reply(
                            tor_socksproto::SocksStatus::SUCCEEDED,
                            Some(&SocksAddr::Ip(addr)),
                        )
                        .context("Encoding socks reply")?;
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                }
                Err(e) => return reply_error(&mut socks_w, &request, e).await,
            }
        }
        SocksCmd::RESOLVE_PTR => {
            // We've been asked to perform a reverse hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addr: IpAddr = match addr.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    let reply = request
                        .reply(tor_socksproto::SocksStatus::ADDRTYPE_NOT_SUPPORTED, None)
                        .context("Encoding socks reply")?;
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            let hosts = match tor_client.resolve_ptr_with_prefs(addr, &prefs).await {
                Ok(hosts) => hosts,
                Err(e) => return reply_error(&mut socks_w, &request, e.kind()).await,
            };
            if let Some(host) = hosts.into_iter().next() {
                // this conversion should never fail, legal DNS names len must be <= 253 but Socks
                // names can be up to 255 chars.
                let hostname = SocksAddr::Hostname(host.try_into()?);
                let reply = request
                    .reply(tor_socksproto::SocksStatus::SUCCEEDED, Some(&hostname))
                    .context("Encoding socks reply")?;
                write_all_and_close(&mut socks_w, &reply[..]).await?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request
                .reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None)
                .context("Encoding socks reply")?;
            write_all_and_close(&mut socks_w, &reply[..]).await?;
        }
    };

    // TODO: we should close the TCP stream if either task fails. Do we?
    // See #211 and #190.

    Ok(())
}

/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing SOCKS stream")
}

/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .close()
        .await
        .context("Error while closing SOCKS stream")
}

/// Reply a Socks error based on an arti-client Error and close the stream.
/// Returns the error provided in parameter
async fn reply_error<W>(
    writer: &mut W,
    request: &SocksRequest,
    error: arti_client::ErrorKind,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    use {tor_socksproto::SocksStatus as S, ErrorKind as EK};

    // TODO: Currently we _always_ try to return extended SOCKS return values
    // for onion service failures from proposal 304 when they are appropriate.
    // But according to prop 304, this is something we should only do when it's
    // requested, for compatibility with SOCKS implementations that can't handle
    // unexpected REP codes.
    //
    // I suggest we make these extended error codes "always-on" for now, and
    // later add a feature to disable them if it's needed. -nickm

    // TODO: Perhaps we should map the extended SOCKS return values for onion
    // service failures unconditionally, even if we haven't compiled in onion
    // service client support.  We can make that change after the relevant
    // ErrorKinds are no longer `experimental-api` in `tor-error`.

    // We need to send an error. See what kind it is.
    let status = match error {
        EK::RemoteNetworkFailed => S::TTL_EXPIRED,

        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceNotFound => S::HS_DESC_NOT_FOUND,
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceAddressInvalid => S::HS_BAD_ADDRESS,
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceMissingClientAuth => S::HS_MISSING_CLIENT_AUTH,
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceWrongClientAuth => S::HS_WRONG_CLIENT_AUTH,

        // NOTE: This is not a perfect correspondence from these ErrorKinds to
        // the errors we're returning here. In the longer run, we'll want to
        // encourage other ways to indicate failure to clients.  Those ways might
        // include encouraging HTTP CONNECT, or the RPC system, both of which
        // would give us more robust ways to report different kinds of failure.
        #[cfg(feature = "onion-service-client")]
        EK::OnionServiceNotRunning
        | EK::OnionServiceConnectionFailed
        | EK::OnionServiceProtocolViolation => S::HS_INTRO_FAILED,

        _ => S::GENERAL_FAILURE,
    };
    let reply = request
        .reply(status, None)
        .context("Encoding socks reply")?;
    // if writing back the error fail, still return the original error
    let _ = write_all_and_close(writer, &reply[..]).await;

    Err(anyhow!(error))
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

/// Launch a SOCKS proxy to listen on a given localhost port, and run
/// indefinitely.
///
/// Requires a `runtime` to use for launching tasks and handling
/// timeouts, and a `tor_client` to use in connecting over the Tor
/// network.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn run_socks_proxy<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    listen: Listen,
    // TODO RPC: This is not a good way to make an API conditional. We MUST
    // refactor this before the RPC feature becomes non-experimental.
    #[cfg(feature = "rpc")] rpc_mgr: Option<Arc<arti_rpcserver::RpcMgr>>,
) -> Result<()> {
    let mut listeners = Vec::new();

    // Try to bind to the SOCKS ports.
    match listen.ip_addrs() {
        Ok(addrgroups) => {
            for addrgroup in addrgroups {
                for addr in addrgroup {
                    match runtime.listen(&addr).await {
                        Ok(listener) => {
                            info!("Listening on {:?}.", addr);
                            listeners.push(listener);
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
        error!("Couldn't open any SOCKS listeners.");
        return Err(anyhow!("Couldn't open SOCKS listeners"));
    }

    // Create a stream of (incoming socket, listener_id) pairs, selected
    // across all the listeners.
    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(TcpListener::incoming)
            .enumerate()
            .map(|(listener_id, incoming_conns)| {
                incoming_conns.map(move |socket| (socket, listener_id))
            }),
    );

    // Loop over all incoming connections.  For each one, call
    // handle_socks_conn() in a new task.
    while let Some((stream, sock_id)) = incoming.next().await {
        let (stream, addr) = match stream {
            Ok((s, a)) => (s, a),
            Err(err) => {
                if accept_err_is_fatal(&err) {
                    return Err(err).context("Failed to receive incoming stream on SOCKS port");
                } else {
                    warn_report!(err, "Incoming stream failed");
                    continue;
                }
            }
        };
        let socks_context = SocksConnContext {
            tor_client: tor_client.clone(),
            #[cfg(feature = "rpc")]
            rpc_mgr: rpc_mgr.clone(),
        };
        let runtime_copy = runtime.clone();
        runtime.spawn(async move {
            let res =
                handle_socks_conn(runtime_copy, socks_context, stream, (sock_id, addr.ip())).await;
            if let Err(e) = res {
                // TODO: warn_report doesn't work on anyhow::Error.
                warn!("connection exited with error: {}", tor_error::Report(e));
            }
        })?;
    }

    Ok(())
}
