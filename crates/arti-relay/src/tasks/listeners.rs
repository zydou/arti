//! Connection listening tasks of the relay.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use safelog::Sensitive;
use tor_chanmgr::ChanMgr;
use tor_rtcompat::{NetStreamListener, NetStreamProvider, Runtime, SpawnExt as _};
use tracing::debug;

/// Listens for Tor (OR) connections on a list of listeners,
/// building a channel for each incoming connection.
pub(crate) async fn or_listener<R: Runtime>(
    runtime: R,
    chan_mgr: Arc<ChanMgr<R>>,
    listeners: impl IntoIterator<Item = <R as NetStreamProvider<SocketAddr>>::Listener>,
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
        // TODO: Should we warn if the connection is from a local address? For example if the user
        // sets up a socat proxy to the OR port, I think it would still work but wouldn't work well
        // with the idea of canonical connections. But we wouldn't want this to warn when using
        // chutney for example. **Edit:** This is probably fine. It might lead to extra connections
        // between relays temporarily since one connection will be considered non-canonical, but if
        // there is one connection that both relays consider canonical, both relays should hopefully
        // use that channel and the other channel will be unused and eventually closed. But there
        // are edge cases here, for example if both relays are using a proxy and the two relays will
        // never have a single connection that both consider canonical.
        let (stream, remote_addr, local_addr) = match next {
            Ok(x) => x,
            Err(e) => {
                // TODO: We should probably warn as this likely indicates a system configuration
                // issue (for example max num of open files too low). But we don't want to warn too
                // often since it's likely future incoming connections will fail as well.
                debug!("Unable to accept incoming OR connection: {e}");
                continue;
            }
        };

        // This may be sensitive (for example if this is a client connecting to a guard).
        let remote_addr = Sensitive::new(remote_addr);

        debug!("New incoming OR connection from {remote_addr} on local address {local_addr}");

        // Spawn a task to handle the incoming connection (for example the channel handshake).
        let chan_mgr = Arc::clone(&chan_mgr);
        runtime
            .spawn(async move {
                match chan_mgr.handle_incoming(remote_addr, stream).await {
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
