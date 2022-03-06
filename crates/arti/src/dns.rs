//! Implement a simple DNS resolver that relay request over Tor.
//!
//! A resolver is launched with [`run_dns_resolver()`], which listens for new
//! connections and then runs

use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};

use arti_client::TorClient;
use tor_rtcompat::{Runtime, UdpSocket};

use anyhow::{anyhow, Result};

/// Given a datagram containing a DNS query, resolve the query over
/// the Tor network and send the response back.
async fn handle_dns_req<R, U>(
    _tor_client: TorClient<R>,
    packet: &[u8],
    addr: SocketAddr,
    socket: Arc<U>,
) -> Result<()>
where
    R: Runtime,
    U: UdpSocket,
{
    // TODO actually process the request
    socket.send(packet, &addr).await?;
    Ok(())
}

/// Launch a DNS resolver to lisetn on a given local port, and run
/// indefinitely.
pub(crate) async fn run_dns_resolver<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    dns_port: u16,
) -> Result<()> {
    let mut listeners = Vec::new();

    // We actually listen on two ports: one for ipv4 and one for ipv6.
    let localhosts: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];

    // Try to bind to the DNS ports.
    for localhost in &localhosts {
        let addr: SocketAddr = (*localhost, dns_port).into();
        match runtime.bind(&addr).await {
            Ok(listener) => {
                info!("Listening on {:?}.", addr);
                listeners.push(listener);
            }
            Err(e) => warn!("Can't listen on {:?}: {}", addr, e),
        }
    }
    // We weren't able to bind any ports: There's nothing to do.
    if listeners.is_empty() {
        error!("Couldn't open any DNS listeners.");
        return Err(anyhow!("Couldn't open SOCKS listeners"));
    }

    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(|socket| {
                futures::stream::unfold(Arc::new(socket), |socket| async {
                    let mut packet = [0; 1536];
                    let packet = socket
                        .recv(&mut packet)
                        .await
                        .map(|(size, remote)| (packet, size, remote, socket.clone()));
                    Some((packet, socket))
                })
            })
            .enumerate()
            .map(|(listener_id, incoming_packet)| {
                Box::pin(incoming_packet.map(move |packet| (packet, listener_id)))
            }),
    );

    while let Some((packet, _id)) = incoming.next().await {
        let (packet, size, addr, socket) = match packet {
            Ok(packet) => packet,
            Err(err) => {
                // TODO move socks::accept_err_is_fatal somewhere else and use it here?
                warn!("Incoming datagram failed: {}", err);
                continue;
            }
        };

        let client_ref = tor_client.clone();
        // TODO implement isolation
        runtime.spawn(async move {
            let res = handle_dns_req(client_ref, &packet[..size], addr, socket).await;
            if let Err(e) = res {
                warn!("connection exited with error: {}", e);
            }
        })?;
    }

    Ok(())
}
