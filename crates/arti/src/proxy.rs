//! Implement a simple SOCKS proxy that relays connections over Tor.
//!
//! A proxy is launched with [`run_socks_proxy()`], which listens for new
//! connections and then runs

use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Error as IoError};
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Result as IoResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{self, Arc};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use arti_client::{ErrorKind, HasKind, IsolationToken, StreamPrefs, TorClient};
use tor_rtcompat::{Runtime, TcpListener};
use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest};

use anyhow::{anyhow, Context, Result};

/// Find out which kind of address family we can/should use for a
/// given `SocksRequest`.
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
type IsolationKey = (usize, IpAddr, SocksAuth);

/// Shared and garbage-collected Map used to isolate connections.
struct IsolationMap {
    /// Inner map guarded by a Mutex
    inner: sync::Mutex<IsolationMapInner>,
}

/// Inner map, generally guarded by a Mutex
struct IsolationMapInner {
    /// Map storing isolation token and last time they where used
    map: HashMap<IsolationKey, (IsolationToken, Instant)>,
    /// Instant after which the garbage collector will be run again
    next_gc: Instant,
}

/// How frequently should we discard entries from the isolation map, and
/// how old should we let them get?
const ISOMAP_GC_INTERVAL: Duration = Duration::from_secs(60 * 30);

impl IsolationMap {
    /// Create a new, empty, IsolationMap
    fn new() -> Self {
        IsolationMap {
            inner: sync::Mutex::new(IsolationMapInner {
                map: HashMap::new(),
                next_gc: Instant::now() + ISOMAP_GC_INTERVAL,
            }),
        }
    }

    /// Get the IsolationToken corresponding to the given key-tuple, creating a new IsolationToken
    /// if none exists for this key.
    ///
    /// Every 30 minutes, on next call to this functions, entry older than 30 minutes are removed
    fn get_or_create(&self, key: IsolationKey, now: Instant) -> IsolationToken {
        let mut inner = self.inner.lock().expect("Poisoned lock on isolation map.");
        if inner.next_gc < now {
            inner.next_gc = now + ISOMAP_GC_INTERVAL;

            let old_limit = now - ISOMAP_GC_INTERVAL;
            inner.map.retain(|_, val| val.1 > old_limit);
        }
        let entry = inner
            .map
            .entry(key)
            .or_insert_with(|| (IsolationToken::new(), now));
        entry.1 = now;
        entry.0
    }
}

/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_map` to decide which circuits circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
async fn handle_socks_conn<R, S>(
    runtime: R,
    tor_client: TorClient<R>,
    socks_stream: S,
    isolation_map: Arc<IsolationMap>,
    isolation_info: (usize, IpAddr),
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
    let mut handshake = tor_socksproto::SocksHandshake::new();

    let (mut socks_r, mut socks_w) = socks_stream.split();
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        // Read some more stuff.
        n_read += socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // try to advance the handshake to the next state.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => continue, // Message truncated.
            Ok(Err(e)) => return Err(e.into()),
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
    info!(
        "Got a socks request: {} {}:{}",
        request.command(),
        addr,
        port
    );

    // Use the source address, SOCKS authentication, and listener ID
    // to determine the stream's isolation properties.  (Our current
    // rule is that two streams may only share a circuit if they have
    // the same values for all of these properties.)
    let auth = request.auth().clone();
    let (source_address, ip) = isolation_info;
    let isolation_token = isolation_map.get_or_create((source_address, ip, auth), Instant::now());

    // Determine whether we want to ask for IPv4/IPv6 addresses.
    let mut prefs = stream_preference(&request, &addr);
    prefs.set_isolation_group(isolation_token);

    match request.command() {
        SocksCmd::CONNECT => {
            // The SOCKS request wants us to connect to a given address.
            // So, launch a connection over Tor.
            let tor_stream = tor_client
                .connect_with_prefs((addr.clone(), port), &prefs)
                .await;
            let tor_stream = match tor_stream {
                Ok(s) => s,
                // In the case of a stream timeout, send the right SOCKS reply.
                Err(e) => {
                    // The connect attempt has failed.  We need to
                    // send an error.  See what kind it is.
                    //
                    let reply = match e.kind() {
                        ErrorKind::ExitTimeout => {
                            request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None)
                        }
                        _ => request.reply(tor_socksproto::SocksStatus::GENERAL_FAILURE, None),
                    };
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            // Okay, great! We have a connection over the Tor network.
            info!("Got a stream for {}:{}", addr, port);
            // TODO: Should send a SOCKS reply if something fails. See #258.

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
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
            let addrs = tor_client.resolve_with_prefs(&addr, &prefs).await?;
            if let Some(addr) = addrs.first() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Ip(*addr)),
                );
                write_all_and_flush(&mut socks_w, &reply[..]).await?;
            }
        }
        SocksCmd::RESOLVE_PTR => {
            // We've been asked to perform a reverse hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addr: IpAddr = match addr.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    let reply =
                        request.reply(tor_socksproto::SocksStatus::ADDRTYPE_NOT_SUPPORTED, None);
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            let hosts = tor_client.resolve_ptr_with_prefs(addr, &prefs).await?;
            if let Some(host) = hosts.into_iter().next() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Hostname(host.try_into()?)),
                );
                write_all_and_flush(&mut socks_w, &reply[..]).await?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request.reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None);
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
pub(crate) async fn run_socks_proxy<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    socks_port: u16,
) -> Result<()> {
    let mut listeners = Vec::new();

    // We actually listen on two ports: one for ipv4 and one for ipv6.
    let localhosts: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];

    // Try to bind to the SOCKS ports.
    for localhost in &localhosts {
        let addr: SocketAddr = (*localhost, socks_port).into();
        match runtime.listen(&addr).await {
            Ok(listener) => {
                info!("Listening on {:?}.", addr);
                listeners.push(listener);
            }
            Err(e) => warn!("Can't listen on {:?}: {}", addr, e),
        }
    }
    // We weren't able to bind any ports: There's nothing to do.
    if listeners.is_empty() {
        error!("Couldn't open any listeners.");
        return Err(anyhow!("Couldn't open listeners"));
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

    // Make a new IsolationMap; We'll use this to register which incoming
    // connections can and cannot share a circuit.
    let isolation_map = Arc::new(IsolationMap::new());

    // Loop over all incoming connections.  For each one, call
    // handle_socks_conn() in a new task.
    while let Some((stream, sock_id)) = incoming.next().await {
        let (stream, addr) = match stream {
            Ok((s, a)) => (s, a),
            Err(err) => {
                if accept_err_is_fatal(&err) {
                    return Err(err).context("Failed to receive incoming stream on SOCKS port");
                } else {
                    warn!("Incoming stream failed: {}", err);
                    continue;
                }
            }
        };
        let client_ref = tor_client.clone();
        let runtime_copy = runtime.clone();
        let isolation_map_ref = Arc::clone(&isolation_map);
        runtime.spawn(async move {
            let res = handle_socks_conn(
                runtime_copy,
                client_ref,
                stream,
                isolation_map_ref,
                (sock_id, addr.ip()),
            )
            .await;
            if let Err(e) = res {
                warn!("connection exited with error: {}", e);
            }
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_isomap() {
        let m = IsolationMap::new();

        let k1 = (6, "10.0.0.1".parse().unwrap(), SocksAuth::NoAuth);
        let k2 = (
            6,
            "10.0.0.1".parse().unwrap(),
            SocksAuth::Socks4(vec![1, 2, 3]),
        );

        let t1 = Instant::now() + ISOMAP_GC_INTERVAL / 2;

        let tok1 = m.get_or_create(k1.clone(), t1);
        let tok2 = m.get_or_create(k2, t1);
        assert_ne!(tok1, tok2);
        assert_eq!(tok1, m.get_or_create(k1.clone(), t1));

        // Now make sure the GC happens, but the items aren't deleted since
        // they aren't quite old enough
        let t2 = t1 + (ISOMAP_GC_INTERVAL * 3) / 4;
        assert_eq!(tok1, m.get_or_create(k1.clone(), t2));

        // Now make sure that the GC happens, and the items _are_ deleted
        // as to old.
        let t3 = t2 + ISOMAP_GC_INTERVAL * 2;
        let tok3 = m.get_or_create(k1, t3);
        assert_ne!(tok3, tok2);
        assert_ne!(tok3, tok1);
    }
}
