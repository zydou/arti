//! Implement a simple DNS resolver that relay request over Tor.
//!
//! A resolver is launched with [`run_dns_resolver()`], which listens for new
//! connections and then runs

use futures::lock::Mutex;
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use hickory_proto::op::{
    header::MessageType, op_code::OpCode, response_code::ResponseCode, Message, Query,
};
use hickory_proto::rr::{rdata, DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use arti_client::{Error, HasKind, StreamPrefs, TorClient};
use safelog::sensitive as sv;
use tor_config::Listen;
use tor_error::{error_report, warn_report};
use tor_rtcompat::{Runtime, UdpSocket};

use anyhow::{anyhow, Result};

/// Maximum length for receiving a single datagram
const MAX_DATAGRAM_SIZE: usize = 1536;

/// A Key used to isolate dns requests.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection and the source IpAddr of the client)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsIsolationKey(usize, IpAddr);

impl arti_client::isolation::IsolationHelper for DnsIsolationKey {
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

/// Identifier for a DNS request, composed of its source IP and transaction ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey(DnsIsolationKey, Vec<Query>);

/// Target for a DNS response
#[derive(Debug, Clone)]
struct DnsResponseTarget<U> {
    /// Transaction ID
    id: u16,
    /// Address of the client
    addr: SocketAddr,
    /// Socket to send the response through
    socket: Arc<U>,
}

/// Run a DNS query over tor, returning either a list of answers, or a DNS error code.
async fn do_query<R>(
    tor_client: TorClient<R>,
    queries: &[Query],
    prefs: &StreamPrefs,
) -> Result<Vec<Record>, ResponseCode>
where
    R: Runtime,
{
    let mut answers = Vec::new();

    let err_conv = |error: Error| {
        if tor_error::ErrorKind::RemoteHostNotFound == error.kind() {
            // NoError without any body is considered to be NODATA as per rfc2308 section-2.2
            ResponseCode::NoError
        } else {
            ResponseCode::ServFail
        }
    };
    for query in queries {
        let mut a = Vec::new();
        let mut ptr = Vec::new();

        // TODO if there are N questions, this would take N rtt to answer. By joining all futures it
        // could take only 1 rtt, but having more than 1 question is actually very rare.
        match query.query_class() {
            DNSClass::IN => {
                match query.query_type() {
                    typ @ RecordType::A | typ @ RecordType::AAAA => {
                        let mut name = query.name().clone();
                        // name would be "torproject.org." without this
                        name.set_fqdn(false);
                        let res = tor_client
                            .resolve_with_prefs(&name.to_utf8(), prefs)
                            .await
                            .map_err(err_conv)?;
                        for ip in res {
                            a.push((query.name().clone(), ip, typ));
                        }
                    }
                    RecordType::PTR => {
                        let addr = query
                            .name()
                            .parse_arpa_name()
                            .map_err(|_| ResponseCode::FormErr)?
                            .addr();
                        let res = tor_client
                            .resolve_ptr_with_prefs(addr, prefs)
                            .await
                            .map_err(err_conv)?;
                        for domain in res {
                            let domain =
                                Name::from_utf8(domain).map_err(|_| ResponseCode::ServFail)?;
                            ptr.push((query.name().clone(), domain));
                        }
                    }
                    _ => {
                        return Err(ResponseCode::NotImp);
                    }
                }
            }
            _ => {
                return Err(ResponseCode::NotImp);
            }
        }
        for (name, ip, typ) in a {
            match (ip, typ) {
                (IpAddr::V4(v4), RecordType::A) => {
                    answers.push(Record::from_rdata(name, 3600, RData::A(rdata::A(v4))));
                }
                (IpAddr::V6(v6), RecordType::AAAA) => {
                    answers.push(Record::from_rdata(name, 3600, RData::AAAA(rdata::AAAA(v6))));
                }
                _ => (),
            }
        }
        for (ptr, name) in ptr {
            answers.push(Record::from_rdata(ptr, 3600, RData::PTR(rdata::PTR(name))));
        }
    }

    Ok(answers)
}

/// Given a datagram containing a DNS query, resolve the query over
/// the Tor network and send the response back.
async fn handle_dns_req<R, U>(
    tor_client: TorClient<R>,
    socket_id: usize,
    packet: &[u8],
    addr: SocketAddr,
    socket: Arc<U>,
    current_requests: &Mutex<HashMap<DnsCacheKey, Vec<DnsResponseTarget<U>>>>,
) -> Result<()>
where
    R: Runtime,
    U: UdpSocket,
{
    // if we can't parse the request, don't try to answer it.
    let mut query = Message::from_bytes(packet)?;
    let id = query.id();
    let queries = query.queries();
    let isolation = DnsIsolationKey(socket_id, addr.ip());

    let request_id = {
        let request_id = DnsCacheKey(isolation.clone(), queries.to_vec());

        let response_target = DnsResponseTarget { id, addr, socket };

        let mut current_requests = current_requests.lock().await;

        let req = current_requests.entry(request_id.clone()).or_default();
        req.push(response_target);

        if req.len() > 1 {
            debug!("Received a query already being served");
            return Ok(());
        }
        debug!("Received a new query");

        request_id
    };

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation);

    let mut response = match do_query(tor_client, queries, &prefs).await {
        Ok(answers) => {
            let mut response = Message::new();
            response
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(query.recursion_desired())
                .set_recursion_available(true)
                .add_queries(query.take_queries())
                .add_answers(answers);
            // TODO maybe add some edns?
            response
        }
        Err(error_type) => Message::error_msg(id, OpCode::Query, error_type),
    };

    // remove() should never return None, but just in case
    let targets = current_requests
        .lock()
        .await
        .remove(&request_id)
        .unwrap_or_default();

    for target in targets {
        response.set_id(target.id);
        // ignore errors, we want to reply to everybody
        let response = match response.to_bytes() {
            Ok(r) => r,
            Err(e) => {
                // The response message probably contains the query DNS name, and the error
                // might well do so too.  (Many variants of hickory_proto's ProtoErrorKind
                // contain domain names.)  Digging into these to be more useful is tiresome,
                // so just mark the whole response message, and error, as sensitive.
                error_report!(e, "Failed to serialize DNS packet: {:?}", sv(&response));
                continue;
            }
        };
        let _ = target.socket.send(&response, &target.addr).await;
    }
    Ok(())
}

/// Launch a DNS resolver to listen on a given local port, and run indefinitely.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn run_dns_resolver<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    listen: Listen,
) -> Result<()> {
    if !listen.is_localhost_only() {
        warn!("Configured to listen for DNS on non-local addresses. This is usually insecure! We recommend listening on localhost only.");
    }

    let mut listeners = Vec::new();

    // Try to bind to the DNS ports.
    match listen.ip_addrs() {
        Ok(addrgroups) => {
            for addrgroup in addrgroups {
                for addr in addrgroup {
                    // NOTE: Our logs here displays the local address. We allow this, since
                    // knowing the address is basically essential for diagnostics.
                    match runtime.bind(&addr).await {
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

    let pending_requests = Arc::new(Mutex::new(HashMap::new()));
    while let Some((packet, id)) = incoming.next().await {
        let (packet, size, addr, socket) = match packet {
            Ok(packet) => packet,
            Err(err) => {
                // TODO move crate::socks::accept_err_is_fatal somewhere else and use it here?
                warn_report!(err, "Incoming datagram failed");
                continue;
            }
        };

        let client_ref = tor_client.clone();
        runtime.spawn({
            let pending_requests = pending_requests.clone();
            async move {
                let res = handle_dns_req(
                    client_ref,
                    id,
                    &packet[..size],
                    addr,
                    socket,
                    &pending_requests,
                )
                .await;
                if let Err(e) = res {
                    // TODO: warn_report does not work on anyhow::Error.
                    warn!("connection exited with error: {}", tor_error::Report(e));
                }
            }
        })?;
    }

    Ok(())
}
