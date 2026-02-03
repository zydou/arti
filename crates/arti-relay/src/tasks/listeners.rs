//! Connection listening tasks of the relay.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use safelog::Sensitive;
use tor_chanmgr::ChanMgr;
use tor_log_ratelim::log_ratelim;
use tor_rtcompat::{NetStreamListener, NetStreamProvider, Runtime, SpawnExt as _};
use tracing::debug;

/// Listens for Tor (OR) connections on a list of listeners,
/// building a channel for each incoming connection.
pub(crate) async fn or_listener<R: Runtime>(
    runtime: R,
    chan_mgr: Arc<ChanMgr<R>>,
    listeners: impl IntoIterator<Item = <R as NetStreamProvider<SocketAddr>>::Listener>,
    advertised_addresses: crate::config::Advertise,
) -> anyhow::Result<void::Void> {
    // a list of listening streams
    let incoming: Vec<_> = listeners
        .into_iter()
        .map(|listener| {
            let local_addr = listener.local_addr()?;
            let incoming = listener
                .incoming()
                .map(move |next| next.map(|(stream, addr)| (stream, addr, local_addr)));
            Ok(incoming)
        })
        .collect::<Result<_, anyhow::Error>>()?;

    // a single stream for all listeners
    let mut incoming = futures::stream::select_all(incoming);

    while let Some(next) = incoming.next().await {
        // This likely indicates a system configuration issue (for example max num of open files too
        // low), but we don't want to warn too often since it's likely future incoming connections
        // will fail as well.

        // The `log_ratelim` macro requires the error to be `Clone` (although this is likely
        // unnecessary here), so we throw it in an `Arc`.
        let next = next.map_err(Arc::new);

        log_ratelim!(
            "accepting incoming OR connection";
            next;
            Err(_) => WARN, "Dropping connection";
        );

        let Ok((stream, remote_addr, local_addr)) = next else {
            // We should have logged the error above.
            continue;
        };

        // This may be sensitive (for example if this is a client connecting to a guard).
        let remote_addr = Sensitive::new(remote_addr);

        debug!("New incoming OR connection from {remote_addr} on local address {local_addr}");

        // Spawn a task to handle the incoming connection (for example the channel handshake).
        let chan_mgr = Arc::clone(&chan_mgr);
        let my_addrs = advertised_addresses.all_ips();
        runtime
            .spawn(async move {
                match chan_mgr
                    .handle_incoming(remote_addr, my_addrs, stream)
                    .await
                {
                    Ok(_chan) => {
                        // TODO: do we need to do anything else here?
                    }
                    Err(e) => debug!("Unable to handle incoming OR connection: {e}"),
                }
            })
            .context("Failed to spawn incoming channel handler")?;
    }

    Err(anyhow::anyhow!("Incoming stream closed"))
}
