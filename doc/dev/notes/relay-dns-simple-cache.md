This is option 2from [doc/dev/notes/relay-dns.md].

```rust
/// A reactor that performs DNS lookups on behalf of incoming streams (RESOLVE, BEGIN).
///
/// Deduplicates queries, and uses hickory-resolver under the hood.
pub(crate) struct DnsResolverReactor {
    /// The DNS lookups we have launched that we are still waiting on.
    pending: PendingQueries,
    /// Our DNS cache.
    cache: DnsCache,
    /// MPSC channel for receiving DNS queries.
    query_rx: mpsc::Receiver<DnsRequest>,
}

struct PendingQueries {
    /// A list of streams that are waiting on responses to the DNS queries.
    /// Each of these has an entry in self.inflight.
    ///
    /// Option<>, because watch channels need an "initial" value,
    /// and for us, that value is going to be None
    /// (it's always discarded, and we never actually send None ourselves,
    /// so this is a bit of a kludge)
    //
    // TODO: we will probably want to use the oneshot broadcast
    // channel from tor_proto::util instead
    pending_response: HashMap<DnsQuery, watch::Sender<Option<DnsResponse>>>,
    /// DNS queries we're currently waiting a response for.
    ///
    // TODO: we may want to prevent this from growing too large
    // (for example, by limiting the max number of inflight queries)
    //
    // TODO: we should probably use tokio's JoinSet instead;
    // unlike FuturesUnordered, JoinSet allows the tasks in the set
    // to execute on different threads, so it would likely
    // be better for performance
    inflight: FuturesUnordered<BoxFuture<'static, DnsResponse>>,
}

impl PendingQueries {
    fn get_or_insert(&mut self, query: DnsQuery) -> DnsResponseReceiver {
        match self.pending_response.entry(query) {
            Entry::Occupied(e) => {
                // If we already have an inflight query for the same request,
                // we just return a new watcher for that particular query
                DnsResponseReceiver::from_watch(e.get().subscribe())
            }
            Entry::Vacant(v) => {
                let (res_tx, res_rx) = watch::channel(None);
                // Time to launch a new lookup
                v.insert(res_tx);
                // TODO: create the lookup future and push it into self.inflight
                DnsResponseReceiver::from_watch(res_rx)
            }
        }
    }
}

struct DnsRequest {
    /// The DNS lookup
    query: DnsQuery,
    /// The channel where to send the response receiver.
    tx: oneshot::Sender<DnsResponseReceiver>,
}

impl DnsResolverReactor {
    fn new() -> (Self, DnsResolver) {
        // TODO: pick an appropriate buffer size here
        const DNS_QUERY_BUF_SIZE: usize = 512;
        let (query_tx, query_rx) = mpsc::channel(DNS_QUERY_BUF_SIZE);

        // The inflight list has an always-pending future to prevent it from
        // yielding None when empty
        let pending: Box<dyn Future<Output = DnsResponse> + Send> =
            Box::new(futures::future::pending());

        let inflight = [pending.into()]
            .into_iter()
            .collect::<FuturesUnordered<BoxFuture<'static, DnsResponse>>>();

        let pending = PendingQueries {
            pending_response: Default::default(),
            inflight,
        };
        let reactor = Self {
            pending,
            cache: Default::default(),
            query_rx,
        };

        let handle = DnsResolver::new(query_tx);

        (reactor, handle)
    }

    /// Run the reactor.
    async fn run(&mut self) {
        loop {
            select_biased! {
                res = self.pending.inflight.next() => {
                    let res = res.expect("inflight stream ended?!");
                    self.handle_response(res).await
                },
                query = self.query_rx.next() => {
                    let Some(query) = query else {
                        return;
                    };
                    self.handle_request(query).await
                }
            }
        }
    }

    async fn handle_request(&mut self, req: DnsRequest) {
        let DnsRequest { query, tx } = req;

        // TODO: normalize the query addr
        // (in case it has mixed capitalization)

        // First, if the query is already cached,
        // we can respond immediately
        let response_rx = if let Some(res) = self.cache.get_or_remove_expired(&query) {
            DnsResponseReceiver::from_response(res)
        } else {
            // If it's not, we need to launch a new lookup,
            // unless we already have a pending one for this query
            self.pending.get_or_insert(query)
        };

        let _ = tx.send(response_rx);
    }

    async fn handle_response(&mut self, res: DnsResponse) {
        // 1. Remove the inflight entry from self.pending
        // 2. Update the cache (clipping and randomizing the TTL)
        // 3. notify all the tasks waiting on this response (over the watch channel)
    }
}

```
