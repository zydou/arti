//! SOCKS-specific proxy support.

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use safelog::sensitive;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, instrument, warn};

#[allow(unused)]
use arti_client::HasKind;
use arti_client::{ErrorKind, IntoTorAddr as _, StreamPrefs};
#[cfg(feature = "rpc")]
use tor_rpcbase::{self as rpc};
use tor_rtcompat::Runtime;
use tor_socksproto::{Handshake as _, SocksAddr, SocksAuth, SocksCmd, SocksRequest};

use anyhow::{Context, Result, anyhow};

use super::{
    ListenerIsolation, ProvidedIsolation, ProxyContext, StreamIsolationKey, write_all_and_close,
    write_all_and_flush,
};
cfg_if::cfg_if! {
    if #[cfg(feature="rpc")] {
        use crate::rpc::conntarget::ConnTarget;
    } else {
        use arti_client::TorClient;

        /// A type returned by get_prefs_and_session,
        /// and used to launch data streams or resolve attempts.
        ///
        /// TODO RPC: This is quite ugly; we should do something better.
        /// At least, we should never expose this outside the socks module.
        type ConnTarget<R> = TorClient<R>;
    }
}

/// Payload to return when an HTTP connection arrive on a Socks port
/// without HTTP support.
#[cfg(not(feature = "http-connect"))]
pub(super) const WRONG_PROTOCOL_PAYLOAD: &[u8] = br#"HTTP/1.0 501 Not running as an HTTP Proxy
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
an HTTP proxy. If you need an HTTP proxy tunnel,
build Arti with the <code>http-connect</code> feature enabled.
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

/// Given the authentication object from a socks connection, determine what it's telling
/// us to do.
///
/// (In no case is it actually SOCKS authentication: it can either be a message
/// to the stream isolation system or the RPC system.)
fn interpret_socks_auth(auth: &SocksAuth) -> Result<AuthInterpretation> {
    /// Interpretation of a SOCKS5 username according to
    /// the [SOCKS extended authentication](https://spec.torproject.org/socks-extensions.html#extended-auth)
    /// specification.
    enum Uname<'a> {
        /// This is a legacy username; it's just part of the
        /// isolation information.
        //
        // Note: We're not actually throwing away the username here;
        // instead we're going to use the whole SocksAuth
        // in a `ProvidedAuthentication::Legacy``.
        // TODO RPC: Find a more idiomatic way to express this data flow.
        Legacy,
        /// This is using the socks extension: contains the extension
        /// format code and the remaining information from the username.
        Extended(u8, &'a [u8]),
    }
    /// Helper: Try to interpret a SOCKS5 username field as indicating the start of a set of
    /// extended socks authentication information.
    ///
    /// Implements [SOCKS extended authentication](https://spec.torproject.org/socks-extensions.html#extended-auth).
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
        /// 8-byte "magic" sequence from
        /// [SOCKS extended authentication](https://spec.torproject.org/socks-extensions.html#extended-auth).
        /// When it appears at the start of a username,
        /// indicates that the username/password are to be interpreted as
        /// as encoding SOCKS5 extended parameters,
        /// but the format might not be one we recognize.
        const SOCKS_EXT_CONST_ANY: &[u8] = b"<torS0X>";
        let Some(remainder) = username.strip_prefix(SOCKS_EXT_CONST_ANY) else {
            return Ok(Uname::Legacy);
        };
        let (format_code, remainder) = remainder
            .split_at_checked(1)
            .ok_or_else(|| anyhow!("Extended SOCKS information without format code."))?;
        Ok(Uname::Extended(format_code[0], remainder))
    }

    let isolation = match auth {
        SocksAuth::Username(user, pass) => match interpret_socks5_username(user)? {
            Uname::Legacy => ProvidedIsolation::LegacySocks(auth.clone()),
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
                    isolation: ProvidedIsolation::ExtendedSocks {
                        format_code,
                        isolation: pass.clone().into(),
                    },
                });
            }
            Uname::Extended(format_code @ b'0', b"") => ProvidedIsolation::ExtendedSocks {
                format_code,
                isolation: pass.clone().into(),
            },
            Uname::Extended(b'0', _) => {
                return Err(anyhow!("Extraneous information in SOCKS username field."));
            }
            _ => return Err(anyhow!("Unrecognized SOCKS format code")),
        },
        _ => ProvidedIsolation::LegacySocks(auth.clone()),
    };

    Ok(AuthInterpretation {
        #[cfg(feature = "rpc")]
        rpc_object: None,
        isolation,
    })
}

impl<R: Runtime> super::ProxyContext<R> {
    /// Interpret a SOCKS request and our input information to determine which
    /// TorClient / ClientConnectionTarget object and StreamPrefs we should use.
    ///
    /// TODO RPC: The return type here is a bit ugly.
    fn get_prefs_and_session(
        &self,
        request: &SocksRequest,
        target_addr: &str,
        conn_isolation: ListenerIsolation,
    ) -> Result<(StreamPrefs, ConnTarget<R>)> {
        // Determine whether we want to ask for IPv4/IPv6 addresses.
        let mut prefs = stream_preference(request, target_addr);

        // Interpret socks authentication to see whether we want to connect to an RPC connector.
        let interp = interpret_socks_auth(request.auth())?;
        prefs.set_isolation(StreamIsolationKey(conn_isolation, interp.isolation));

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
        let client = ConnTarget::Client(Box::new(client));

        Ok((prefs, client))
    }
}

/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_info` to decide which circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
#[instrument(skip_all, level = "trace")]
pub(super) async fn handle_socks_conn<R, S>(
    context: ProxyContext<R>,
    mut socks_stream: BufReader<S>,
    isolation_info: ListenerIsolation,
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

    let mut inbuf = tor_socksproto::Buffer::new();
    let request = loop {
        use tor_socksproto::NextStep as NS;

        // Try to perform the next step in the handshake.
        // (If there is an handshake error, don't reply with a Socks error, remote does not
        // seems to speak Socks.)
        let step = handshake.step(&mut inbuf)?;

        match step {
            NS::Recv(mut recv) => {
                let n = socks_stream
                    .read(recv.buf())
                    .await
                    .context("Error while reading SOCKS handshake")?;
                recv.note_received(n)?;
            }
            NS::Send(data) => write_all_and_flush(&mut socks_stream, &data).await?,
            NS::Finished(fin) => break fin.into_output_forbid_pipelining()?,
        }
    };

    // Make sure there is no buffered data!
    if !socks_stream.buffer().is_empty() {
        let error = tor_socksproto::Error::ForbiddenPipelining;
        return reply_error(&mut socks_stream, &request, error.kind()).await;
    }

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
                Err(e) => return reply_error(&mut socks_stream, &request, e.kind()).await,
            };
            // Okay, great! We have a connection over the Tor network.
            debug!("Got a stream for {}:{}", sensitive(&addr), port);

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request
                .reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .context("Encoding socks reply")?;
            write_all_and_flush(&mut socks_stream, &reply[..]).await?;

            let tor_stream = BufReader::with_capacity(super::APP_STREAM_BUF_LEN, tor_stream);

            // Finally, relay traffic between
            // the socks stream and the tor stream.
            futures_copy::copy_buf_bidirectional(
                socks_stream,
                tor_stream,
                futures_copy::eof::Close,
                futures_copy::eof::Close,
            )
            .await?;
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
                    write_all_and_close(&mut socks_stream, &reply[..]).await?;
                }
                Err(e) => return reply_error(&mut socks_stream, &request, e).await,
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
                    write_all_and_close(&mut socks_stream, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            let hosts = match tor_client.resolve_ptr_with_prefs(addr, &prefs).await {
                Ok(hosts) => hosts,
                Err(e) => return reply_error(&mut socks_stream, &request, e.kind()).await,
            };
            if let Some(host) = hosts.into_iter().next() {
                // this conversion should never fail, legal DNS names len must be <= 253 but Socks
                // names can be up to 255 chars.
                let hostname = SocksAddr::Hostname(host.try_into()?);
                let reply = request
                    .reply(tor_socksproto::SocksStatus::SUCCEEDED, Some(&hostname))
                    .context("Encoding socks reply")?;
                write_all_and_close(&mut socks_stream, &reply[..]).await?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request
                .reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None)
                .context("Encoding socks reply")?;
            write_all_and_close(&mut socks_stream, &reply[..]).await?;
        }
    };

    // TODO: we should close the TCP stream if either task fails. Do we?
    // See #211 and #190.

    Ok(())
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
    use {ErrorKind as EK, tor_socksproto::SocksStatus as S};

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
    //
    // TODO: Perhaps move this to tor-error, so it can be an exhaustive match.
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
