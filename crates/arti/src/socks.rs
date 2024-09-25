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
use tor_rpcbase::{self as rpc};
use tor_rtcompat::{NetStreamListener, Runtime};
use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest, SOCKS_BUF_LEN};

use anyhow::{anyhow, Context, Result};

#[cfg(feature = "rpc")]
use crate::rpc::RpcStateSender;

/// Payload to return when an HTTP connection arrive on a Socks port
const WRONG_PROTOCOL_PAYLOAD: &[u8] = br#"HTTP/1.0 501 Tor is not an HTTP Proxy
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>
</head>
<body>
<h1>This is a SOCKS proxy, not an HTTP proxy.</h1>
<p>
It appears you have configured your web browser to use this Tor port as
an HTTP proxy.
</p>
<p>
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
    Legacy(SocksAuth),
    /// A bytestring provided as isolation with the extended Socks5 username/password protocol.
    Extended {
        /// Which format was negotiated?
        ///
        /// (At present, different format codes can't share a circuit.)
        format_code: u8,
        /// What's the isolation string?
        isolation: Box<[u8]>,
    },
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
    /// Associate this stream with a DataStream created by using a particular RPC object
    /// as a Tor client.
    #[cfg(feature = "rpc")]
    rpc_object: Option<rpc::ObjectId>,

    /// Isolate this stream from other streams that do not have the same
    /// value.
    isolation: ProvidedIsolation,
}

/// NOTE: The following documentation belongs in a spec.
/// But for now, it's our best attempt to document the design and protocol
/// implemented here
/// for integrating SOCKS with our RPC system. --nickm
///
/// Roughly speaking:
///
/// ## Key concepts
///
/// A data stream is "RPC-visible" if, when it is created via SOCKS,
/// the RPC system is told about it.
///
/// Every RPC-visible stream is associated with a given RPC object when it is created.
/// (Since the RPC object is being specified in the SOCKS protocol,
/// it must be one with an externally visible Object ID.
/// Such Object IDs are cryptographically unguessable and unforgeable,
/// and are qualified with a unique identifier for their associated RPC session.)
/// Call this RPC Object the "target" object for now.
/// This target RPC object must implement
/// the [`ConnectWithPrefs`](arti_client::rpc::ConnectWithPrefs) special method.
///
/// Right now, there are two general kinds of objects that implement this method:
/// client-like objects, and stream-like objects.
///
/// A client-like object is either a `TorClient` or an RPC `Session`.
/// It knows about and it is capable of opening multiple data streams.
/// Using it as the target object for a SOCKS connection tells Arti
/// that the resulting data stream (if any)
/// should be built by it, and associated with its RPC session.
///
/// An application gets a TorClient by asking the session for one,
/// or for asking a TorClient to give you a new variant clone of itself.
///
/// A stream-like object is an `arti_rpcserver::stream::RpcDataStream`.
/// It is created from a client-like object, but represents a single data stream.
/// When created, it it not yet connected or trying to connect to anywhere:
/// the act of using it as the target Object for a SOCKS connection causes
/// it to begin connecting.
/// (You can also think of this as a single-use client,
/// which once used, becomes interchangeable with the DataStream it created.)
/// (TODO: We may wish to change this vocabulary.
/// We may wish to call this a "stream handle", for instance?)
///
/// An application gets an RpcDataStream by calling `arti:new_stream_handle
/// on any client-like object.  Currently, this always creates an RpcDataStream
/// that makes optimistic connections; See #1583.
///
/// ## The SOCKS protocol
///
/// See [proposal 351](https://spec.torproject.org/proposals/351-socks-auth-extensions.html) for now.
/// Once it is merged, see the
/// [SOCKS extensions spec](https://spec.torproject.org/socks-extensions.html).
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
/// The resulting DataStream object could also be used as the target of a SOCKS connection.
/// We would require in such a case that no isolation be provided in the SOCKS handshake,
/// and that the target address was (e.g.) INADDR_ANY.
///
/// ## Intended use cases (examples)
///
/// (These examples assume that the application
/// already knows the SOCKS port it should use.
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
/// Arti looks up the Session object via the `SESSION-1` object ID
/// and tells it (via the ConnectWithPrefs special method)
/// to connect to www.example.com.
/// The session creates a new DataStream using its internal TorClient,
/// but does not register the stream with an RPC Object ID.
/// Arti proxies the application's SOCKS connection through this DataStream.
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
/// `{"id": 123, "obj": "SESSION-1", "method": "arti:new_stream_handle", "params": {}}`
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
/// Now Arti looks up the `RpcDataStream` object via `STREAM-1`,
/// and tells it (via the ConnectWithPrefs special method)
/// to connect to www.example.com.
/// This causes the `RpcDataStream` internally to create a new `DataStream`,
/// and to store that `DataStream` in itself.
/// The `RpcDataStream` with Object ID `STREAM-1`
/// is now an alias for the newly created `DataStream`.
/// Arti proxies the application's SOCKS connection through that `DataStream`.
///
#[cfg(feature = "rpc")]
#[allow(dead_code)]
mod socks_and_rpc {}

/// Given the authentication object from a socks connection, determine what it's telling
/// us to do.
///
/// (In no case is it actually SOCKS authentication: it can either be a message
/// to the stream isolation system or the RPC system.)
fn interpret_socks_auth(auth: &SocksAuth) -> Result<AuthInterpretation> {
    /// Interpretation of a SOCKS5 username according to Prop351.
    enum Uname<'a> {
        /// This is a legacy username; it's just part of the
        /// isolation information.
        //
        // Note: We're not actually throwing away the username here;
        // instead we're going to use the whole SocksAuth
        // in a `ProvidedAuthentication::Legacy``.
        // TODO RPC: Find a more idiomatic way to express this data flow.
        Legacy,
        /// This is using the prop351 socks extension: contains the extension
        /// format code and the remaining information from the username.
        Extended(u8, &'a [u8]),
    }
    /// Helper: Try to interpret a SOCKS5 username field as indicating the start of a set of
    /// extended socks authentication information.
    ///
    /// Implements Prop351.
    ///
    /// If it does indicate that extensions are in use,
    /// return a `Uname::Extended` containing
    /// the extension format type and the remaining information from the username.
    ///
    /// If it indicates that no extensions are in use,
    /// return `Uname::Legacy`.
    ///
    /// If it is badly formatted, return an error.
    fn interpret_socks5_username(username: &[u8]) -> Result<Uname<'_>> {
        /// 8-byte "magic" sequence from Prop351.
        /// When it appears at the start of a username,
        /// indicates that the username/password are to be interpreted as
        /// as encoding SOCKS5 extended parameters,
        /// but the format might not be one we recognize.
        const SOCKS_EXT_CONST_ANY: &[u8] = b"<torS0X>";
        let Some(remainder) = username.strip_prefix(SOCKS_EXT_CONST_ANY) else {
            return Ok(Uname::Legacy);
        };
        if remainder.is_empty() {
            return Err(anyhow!("Exteneded SOCKS information without format code."));
        }
        // TODO MSRV 1.80: use split_at_checked instead.
        // This won't panic since we checked for an empty string above.
        let (format_code, remainder) = remainder.split_at(1);
        Ok(Uname::Extended(format_code[0], remainder))
    }

    let isolation = match auth {
        SocksAuth::Username(user, pass) => match interpret_socks5_username(user)? {
            Uname::Legacy => ProvidedIsolation::Legacy(auth.clone()),
            Uname::Extended(b'1', b"") => {
                return Err(anyhow!("Received empty RPC object ID"));
            }
            Uname::Extended(format_code @ b'1', remainder) => {
                #[cfg(not(feature = "rpc"))]
                return Err(anyhow!(
                    "Received RPC object ID, but not built with support for RPC"
                ));
                #[cfg(feature = "rpc")]
                return Ok(AuthInterpretation {
                    rpc_object: Some(rpc::ObjectId::from(
                        std::str::from_utf8(remainder).context("Rpc object ID was not utf-8")?,
                    )),
                    isolation: ProvidedIsolation::Extended {
                        format_code,
                        isolation: pass.clone().into(),
                    },
                });
            }
            Uname::Extended(format_code @ b'0', b"") => ProvidedIsolation::Extended {
                format_code,
                isolation: pass.clone().into(),
            },
            Uname::Extended(b'0', _) => {
                return Err(anyhow!("Extraneous information in SOCKS username field."))
            }
            _ => return Err(anyhow!("Unrecognized SOCKS format code")),
        },
        _ => ProvidedIsolation::Legacy(auth.clone()),
    };

    Ok(AuthInterpretation {
        #[cfg(feature = "rpc")]
        rpc_object: None,
        isolation,
    })
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

cfg_if::cfg_if! {
    if #[cfg(feature="rpc")] {
        use crate::rpc::conntarget::ConnTarget;
    } else {
        /// A type returned by get_prefs_and_session,
        /// and used to launch data streams or resolve attempts.
        ///
        /// TODO RPC: This is quite ugly; we should do something better.
        /// At least, we should never expose this outside the socks module.
        type ConnTarget<R> = TorClient<R>;
    }
}

impl<R: Runtime> SocksConnContext<R> {
    /// Interpret a SOCKS request and our input information to determine which
    /// TorClient / ClientConnectionTarget object and StreamPrefs we should use.
    ///
    /// TODO RPC: The return type here is a bit ugly.
    fn get_prefs_and_session(
        &self,
        request: &SocksRequest,
        target_addr: &str,
        conn_isolation: ConnIsolation,
    ) -> Result<(StreamPrefs, ConnTarget<R>)> {
        // Determine whether we want to ask for IPv4/IPv6 addresses.
        let mut prefs = stream_preference(request, target_addr);

        // Interpret socks authentication to see whether we want to connect to an RPC connector.
        let interp = interpret_socks_auth(request.auth())?;
        prefs.set_isolation(SocksIsolationKey(conn_isolation, interp.isolation));

        #[cfg(feature = "rpc")]
        if let Some(session) = interp.rpc_object {
            if let Some(mgr) = &self.rpc_mgr {
                let (context, object) = mgr
                    .lookup_object(&session)
                    .context("no such session found")?;
                let target = ConnTarget::Rpc { context, object };
                return Ok((prefs, target));
            } else {
                return Err(anyhow!("no rpc manager found!?"));
            }
        }

        let client = self.tor_client.clone();
        #[cfg(feature = "rpc")]
        let client = ConnTarget::Client(client);

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
        let n = socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;
        if n == 0 {
            debug!("Socks connection closed");
            return Ok(());
        }
        n_read += n;

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

    let mut buf = [0_u8; SOCKS_BUF_LEN];

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
    #[cfg(feature = "rpc")] rpc_data: Option<(
        Arc<arti_rpcserver::RpcMgr>, //
        RpcStateSender,
    )>,
) -> Result<()> {
    #[cfg(feature = "rpc")]
    let (rpc_mgr, mut rpc_state_sender) = match rpc_data {
        Some((m, s)) => (Some(m), Some(s)),
        None => (None, None),
    };

    let mut listeners = Vec::new();
    let mut listening_on_addrs = Vec::new();

    // Try to bind to the SOCKS ports.
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
        error!("Couldn't open any SOCKS listeners.");
        return Err(anyhow!("Couldn't open SOCKS listeners"));
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
