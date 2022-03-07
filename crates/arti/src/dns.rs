//! Implement a simple DNS resolver that relay request over Tor.
//!
//! A resolver is launched with [`run_dns_resolver()`], which listens for new
//! connections and then runs

use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};
use trust_dns_proto::op::{
    header::MessageType, op_code::OpCode, response_code::ResponseCode, Message,
};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use arti_client::TorClient;
use tor_rtcompat::{Runtime, UdpSocket};

use anyhow::{anyhow, Result};

/// Maximum lenght for receiving a single datagram
const MAX_DATAGRAM_SIZE: usize = 1536;

/// Send an error DNS response with code NotImplemented
async fn not_implemented<U: UdpSocket>(id: u16, addr: &SocketAddr, socket: &U) -> Result<()> {
    let response = Message::error_msg(id, OpCode::Query, ResponseCode::NotImp);
    socket.send(&response.to_bytes()?, addr).await?;
    Ok(())
}

/// Given a datagram containing a DNS query, resolve the query over
/// the Tor network and send the response back.
async fn handle_dns_req<R, U>(
    tor_client: TorClient<R>,
    packet: &[u8],
    addr: SocketAddr,
    socket: Arc<U>,
) -> Result<()>
where
    R: Runtime,
    U: UdpSocket,
{
    let mut query = Message::from_bytes(packet)?;
    let id = query.id();

    let mut answers = Vec::new();

    for query in query.queries() {
        let mut a = Vec::new();
        let mut ptr = Vec::new();
        // TODO maybe support ANY?
        match query.query_class() {
            DNSClass::IN => {
                match query.query_type() {
                    typ @ RecordType::A | typ @ RecordType::AAAA => {
                        let mut name = query.name().clone();
                        // name would be "torproject.org." without this
                        name.set_fqdn(false);
                        let res = tor_client.resolve(&name.to_utf8()).await?;
                        for ip in res {
                            a.push((query.name().clone(), ip, typ));
                        }
                    }
                    RecordType::PTR => {
                        let addr = query.name().parse_arpa_name()?.addr();
                        let res = tor_client.resolve_ptr(addr).await?;
                        for domain in res {
                            let domain = Name::from_utf8(domain)?;
                            ptr.push((query.name().clone(), domain));
                        }
                    }
                    _ => {
                        return not_implemented(id, &addr, &*socket).await;
                    }
                }
            }
            _ => {
                return not_implemented(id, &addr, &*socket).await;
            }
        }
        for (name, ip, typ) in a {
            match (ip, typ) {
                (IpAddr::V4(v4), RecordType::A) => {
                    answers.push(Record::from_rdata(name, 3600, RData::A(v4)));
                }
                (IpAddr::V6(v6), RecordType::AAAA) => {
                    answers.push(Record::from_rdata(name, 3600, RData::AAAA(v6)));
                }
                _ => (),
            }
        }
        for (ptr, name) in ptr {
            answers.push(Record::from_rdata(ptr, 3600, RData::PTR(name)));
        }
    }

    let mut response = Message::new();
    response
        .set_id(id)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(true)
        .add_queries(query.take_queries())
        .add_answers(answers);
    // TODO maybe add some edns?

    socket.send(&response.to_bytes()?, &addr).await?;
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
        return Err(anyhow!("Couldn't open any DNS listeners"));
    }

    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(|socket| {
                futures::stream::unfold(Arc::new(socket), |socket| async {
                    let mut packet = [0; MAX_DATAGRAM_SIZE];
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
                // TODO move crate::socks::accept_err_is_fatal somewhere else and use it here?
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
