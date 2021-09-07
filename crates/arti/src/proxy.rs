//! Implement a simple SOCKS proxy that relays connections over Tor.
//!
//! A proxy is launched with [`run_socks_proxy()`], which listens for new
//! connections and then runs

use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::lock::Mutex;
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Result as IoResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use tor_client::{ConnectPrefs, IsolationToken, TorClient};
use tor_rtcompat::{Runtime, TcpListener, TimeoutError};
use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest};

use anyhow::{Context, Result};

/// Find out which kind of address family we can/should use for a
/// given `SocksRequest`.
fn stream_preference(req: &SocksRequest, addr: &str) -> ConnectPrefs {
    let mut prefs = ConnectPrefs::new();
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
    inner: Mutex<IsolationMapInner>,
}

/// Inner map, generally guarded by a Mutex
struct IsolationMapInner {
    /// Map storing isolation token and last time they where used
    map: HashMap<IsolationKey, (IsolationToken, Instant)>,
    /// Instant after which the garbage collector will be run again
    next_gc: Instant,
}

impl IsolationMap {
    /// Create a new, empty, IsolationMap
    fn new() -> Self {
        IsolationMap {
            inner: Mutex::new(IsolationMapInner {
                map: HashMap::new(),
                next_gc: Instant::now() + Duration::new(60 * 30, 0),
            }),
        }
    }

    /// Get the IsolationToken corresponding to the given key-tuple, creating a new IsolationToken
    /// if none exists for this key.
    ///
    /// Every 30 minutes, on next call to this functions, entry older than 30 minutes are removed
    async fn get_or_create(&self, key: IsolationKey) -> IsolationToken {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if inner.next_gc < now {
            inner.next_gc = now + Duration::new(60 * 30, 0);

            let old_limit = now - Duration::new(60 * 30, 0);
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
/// may use.  Requires that `isolation_info` is a pair listeng the listener
/// id and the source address for the socks request.
async fn handle_socks_conn<R, S>(
    runtime: R,
    tor_client: Arc<TorClient<R>>,
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
            Err(tor_socksproto::Error::Truncated) => continue,
            Err(e) => return Err(e.into()),
            Ok(action) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            (&mut inbuf).copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            socks_w
                .write(&action.reply[..])
                .await
                .context("Error while writing reply to SOCKS handshake")?;
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
    let isolation_token = isolation_map
        .get_or_create((source_address, ip, auth))
        .await;

    // Determine whether we want to ask for IPv4/IPv6 addresses.
    let mut prefs = stream_preference(&request, &addr);
    prefs.set_isolation_group(isolation_token);

    match request.command() {
        SocksCmd::CONNECT => {
            // The SOCKS request wants us to connect to a given address.
            // So, launch a connection over Tor.
            let tor_stream = tor_client.connect(&addr, port, Some(prefs)).await;
            let tor_stream = match tor_stream {
                Ok(s) => s,
                // In the case of a stream timeout, send the right SOCKS reply.
                Err(e) => {
                    // The connect attempt has failed.  We need to
                    // send an error.  See what kind it is.
                    //
                    // TODO: Using downcast_ref() here is ugly. maybe we shouldn't
                    // be using anyhow at this point?
                    match e.downcast_ref::<TimeoutError>() {
                        Some(_) => {
                            let reply =
                                request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None);
                            socks_w
                                .write(&reply[..])
                                .await
                                .context("Couldn't write SOCKS reply")?;
                            return Err(e);
                        }
                        _ => return Err(e),
                    }
                }
            };
            // Okay, great! We have a connection over the Tor network.
            info!("Got a stream for {}:{}", addr, port);
            // TODO: XXXX-A1 Should send a SOCKS reply if something fails.

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
            socks_w
                .write(&reply[..])
                .await
                .context("Couldn't write SOCKS reply")?;

            let (tor_r, tor_w) = tor_stream.split();

            // Finally, spawn two background tasks to relay traffic between
            // the socks stream and the tor stream.
            runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
            runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
        }
        SocksCmd::RESOLVE => {
            // We've been asked to perform a regular hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addrs = tor_client.resolve(&addr, Some(prefs)).await?;
            if let Some(addr) = addrs.first() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Ip(*addr)),
                );
                socks_w
                    .write(&reply[..])
                    .await
                    .context("Couldn't write SOCKS reply")?;
            }
        }
        SocksCmd::RESOLVE_PTR => {
            // We've been asked to perform a reverse hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let hosts = tor_client.resolve_ptr(&addr, Some(prefs)).await?;
            if let Some(host) = hosts.into_iter().next() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Hostname(host.try_into()?)),
                );
                socks_w
                    .write(&reply[..])
                    .await
                    .context("Couldn't write SOCKS reply")?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
        }
    };

    // TODO: XXXX-A1 we should close the TCP stream if either task fails. Do we?
    // TODO: XXXX-A1 should report the errors.

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

/// Launch a SOCKS proxy to listen on a given localhost port, and run
/// indefinitely.
///
/// Requires a `runtime` to use for launching tasks and handling
/// timeouts, and a `tor_client` to use in connecting over the Tor
/// network.
pub(crate) async fn run_socks_proxy<R: Runtime>(
    runtime: R,
    tor_client: Arc<TorClient<R>>,
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
        return Ok(()); // XXXX should return an error.
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
        let (stream, addr) = stream.context("Failed to receive incoming stream on SOCKS port")?;
        let client_ref = Arc::clone(&tor_client);
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
