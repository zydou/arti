//! Module exposing a [`DnsResolver`] and [`DnsResolverReactor`].

mod err;
mod reactor;

use std::net::IpAddr;

use either::Either;
use futures::SinkExt as _;
use futures::channel::mpsc;
use smallvec::SmallVec;

use oneshot_fused_workaround as oneshot;
use tor_async_utils::oneshot_broadcast;
use tor_cell::relaycell::msg::ResolvedVal;
use tor_error::{Bug, internal, into_internal};

pub(crate) use err::LookupError;
pub(crate) use reactor::{DnsResolverReactor, DnsResponse};

/// Type-alias for the DNS answer list.
pub(crate) type LookupAnswers<T> = SmallVec<[T; 10]>;

/// The record data types currently supported by RESOLVE,
/// for easy conversion to ResolvedVal.
///
/// Note: we need our own record type here, because the hickory Record type
/// is quite big (272 bytes) and includes various fields we don't actually use
/// (such as the domain name that was looked up and the DNS record class).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum RecordData {
    /// An A or AAAA record.
    Ip(IpAddr),
    /// A PTR record
    Hostname(String),
}

impl From<RecordData> for ResolvedVal {
    fn from(record: RecordData) -> ResolvedVal {
        match record {
            RecordData::Ip(addr) => ResolvedVal::Ip(addr),
            RecordData::Hostname(addr) => ResolvedVal::Hostname(addr.into()),
        }
    }
}

/// An incoming DNS query and the channel where to send back the response receiver.
struct DnsRequest {
    /// The ASCII-encoded hostname to lookup
    query: String,
    /// The channel where to send the response receiver.
    tx: oneshot::Sender<DnsResponseReceiver>,
}

/// The response is either from cache (Left),
/// or from a lookup that needs to be .awaited (Right).
struct DnsResponseReceiver(Either<DnsResponse, oneshot_broadcast::Receiver<DnsResponse>>);

impl From<DnsResponse> for DnsResponseReceiver {
    fn from(res: DnsResponse) -> Self {
        Self(Either::Left(res))
    }
}

impl From<oneshot_broadcast::Receiver<DnsResponse>> for DnsResponseReceiver {
    fn from(res: oneshot_broadcast::Receiver<DnsResponse>) -> Self {
        Self(Either::Right(res))
    }
}

impl DnsResponseReceiver {
    /// Wait for the [`DnsResponse`]
    async fn recv(self) -> Result<DnsResponse, Bug> {
        match self.0 {
            Either::Left(res) => {
                // TODO(relay): TIMELESS-SIDE-CHANNEL-MITIGATION:
                //
                // Insert a randomized delay here to create FP for attackers
                // probing for cached domains.
                //
                // This delay will need to be based on past DNS lookup timings,
                // so as not to make the cached responses stand out too much.
                // But we don't want to make this delay too high,
                // because we'd lose out on any UX/perf improvement that
                // we were hoping to get out of caching.
                //
                // Question: how to pick an appropriate delay here?
                // One possibility would be to sample non-uniformly
                // from [0, rolling_avg_lookup_time].
                Ok(res)
            }
            Either::Right(watch_rx) => watch_rx
                .await
                .map_err(into_internal!("DNS reactor task exited?!")),
        }
    }
}

/// A handle to the [`DnsResolverReactor`].
#[derive(Clone)]
pub(crate) struct DnsResolver {
    /// Sender for sending DNS queries to the reactor
    ///
    /// The reactor sends back each response over a DnsResponseReceiver.
    query_tx: mpsc::Sender<DnsRequest>,
}

impl DnsResolver {
    /// Create a new [`DnsResolver`] for use with the `query_tx` reactor MPSC channel.
    fn new(query_tx: mpsc::Sender<DnsRequest>) -> Self {
        Self { query_tx }
    }

    /// Asynchronously resolve the specified query
    pub(crate) async fn resolve(
        &mut self,
        query: &[u8],
    ) -> Result<LookupAnswers<RecordData>, LookupError> {
        let (tx, rx) = oneshot::channel();

        let query = String::from_utf8(query.to_vec()).map_err(LookupError::InvalidHostname)?;
        let req = DnsRequest { query, tx };
        // Send the query to the reactor,
        // which handles the actual DNS resolution,
        // and then wait for it to respond
        self.query_tx
            .send(req)
            .await
            .map_err(into_internal!("DNS resolver reactor shut down?!"))?;

        let response_rx = rx
            .await
            .map_err(into_internal!("DNS resolver reactor shut down?!"))?;

        response_rx.recv().await?.answers
    }
}
