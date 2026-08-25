This is a DNS resolver implementation sketch
for the global and per-circuit cache DNS ideas
(options 2 and 3) from [./doc/dev/notes/relay-dns.md].

```rust
/// A DNS response.
///
/// To keep things simple, we cache the response as a whole,
/// as opposed to individual records.
#[derive(Clone, Debug)]
struct DnsResponse {
    /// The query this response is for.
    query: Arc<String>,
    /// The answer records from the DNS response, from hickory.
    ///
    /// Each Record has a TTL
    ///
    /// Note: the hickory Record type is quite big (272 bytes),
    /// as it includes various fields we don't actually use
    /// (such as the domain name that was looked up).
    ///
    /// We will likely want to use a different, more compact type here.
    answers: Result<SmallVec<[Record; 10]>, LookupError>,
    /// The timestamp when this response becomes invalid
    ///
    /// This is computed by
    /// clipping + fuzzing the max TTL of all the answers in self.answers.
    /// (We could also use the valid_until of the Lookup object
    //  returned by hickory, but IIUC, that's always set to MAX_TTL = 1 day,
    //  which may or may not be desirable for us)
    ///
    /// This does mean we'll be serving stale Records sometimes,
    /// but I think that might be fine?
    ///
    /// RFC-8767 says resolvers are allowed to serve stale data,
    /// **if** they're unable to refresh it
    /// (that's not necessarily the case here,
    /// although with a flexible enough interpretation of the RFC,
    /// maybe it could be?):
    ///
    /// "If the data is unable to be authoritatively refreshed when the TTL expires,
    /// the record MAY be used as though it is unexpired"
    valid_until: Instant,
}

// The TTL for error responses
const TTL_FOR_ERRORS: u32 = 5 * 60;

// The TTL for empty answers
const TTL_FOR_EMPTY_ANS: u32 = 5 * 60;

impl DnsResponse {
    fn from_hickory_lookup(
        query: Arc<String>,
        lookup: Result<LookupIp, NetError>,
        now: Instant,
    ) -> Self {
        match lookup {
            Ok(l) => Self::from_successful_lookup(query, l.as_lookup(), now),
            Err(e) => Self::from_error(query, e, now),
        }
    }

    fn from_successful_lookup(query: Arc<String>, lookup: &Lookup, now: Instant) -> Self {
        let answers: SmallVec<_> = lookup.answers().into();

        // TODO: if answers.is_empty(), we should probably map
        // answers to an Err() (maybe an NXDOMAIN, or something?)

        let ttl = if answers.is_empty() {
            TTL_FOR_EMPTY_ANS
        } else {
            // Use the max TTL of all the answers
            answers
                .iter()
                .map(|ans: &Record| ans.ttl)
                .max()
                .expect("answers cannot be empty")
        };

        let valid_until = now + Duration::from_secs(clip_and_fuzz_ttl(ttl).into());

        Self {
            query,
            answers: Ok(answers),
            valid_until,
        }
    }


    // Note: there are some errors that shouldn't be cached (e.g. transient errors)
    fn from_error(query: Arc<String>, lookup: NetError, now: Instant) -> Self {
        let valid_until = now + Duration::from_secs(clip_and_fuzz_ttl(TTL_FOR_ERRORS).into());

        // TODO: handle the different possible error cases
        Self {
            query,
            answers: Err(LookupError::Hickory(lookup)),
            valid_until,
        }
    }
}

/// A reactor that performs DNS lookups on behalf of incoming streams (RESOLVE, BEGIN).
///
/// Deduplicates queries, and uses hickory-resolver under the hood.
pub(crate) struct DnsResolverReactor {
    /// The async stub resolver
    resolver: Arc<Resolver<TokioRuntimeProvider>>,
    /// The DNS lookups we have launched that we are still waiting on.
    pending: PendingQueries,
    /// Our DNS cache.
    ///
    /// The exactly details of its implementation are TBD
    cache: DnsCache,
    /// MPSC channel for receiving DNS queries.
    query_rx: mpsc::Receiver<DnsRequest>,
}

struct PendingQueries {
    /// A list of streams that are waiting on responses to the DNS queries.
    /// Each of these has an entry in self.inflight.
    pending_response: HashMap<Arc<String>, oneshot_broadcast::Sender<DnsResponse>>,
    /// DNS queries we're currently waiting a response for.
    inflight: JoinSet<DnsResponse>,
}

impl PendingQueries {
    fn get_or_insert<P: RuntimeProvider>(
        &mut self,
        query: Arc<String>,
        resolver: &Arc<Resolver<P>>,
    ) -> DnsResponseReceiver {
        match self.pending_response.entry(Arc::clone(&query)) {
            Entry::Occupied(e) => {
                // If we already have an inflight query for the same request,
                // we just return a new watcher for that particular query
                DnsResponseReceiver::from_watch(e.get().subscribe())
            }
            Entry::Vacant(v) => {
                // The channel on which to broadcast the lookup result
                // to all the tasks waiting on it
                // (used for deduplicating queries)
                let (res_tx, res_rx) = oneshot_broadcast::channel();
                // Time to launch a new lookup
                v.insert(res_tx);
                let resolver = Arc::clone(resolver);

                self.inflight.spawn(async move {
                    // TODO: use resolver.reverse_lookup() if this is actually a PTR query
                    let lookup_ip = resolver.lookup_ip(query.as_str()).await;
                    let now = Instant::now();
                    DnsResponse::from_hickory_lookup(query, lookup_ip, now)
                });

                DnsResponseReceiver::from_watch(res_rx)
            }
        }
    }

    /// Remove the pending entry that was waiting for the specified `response`
    fn remove_for_response(
        &mut self,
        response: &DnsResponse,
    ) -> Result<oneshot_broadcast::Sender<DnsResponse>, ()> {
        // TODO: return Bug(), because it should be impossible to get a response
        // for a query we never added to pending_response
        self.pending_response
            .remove(&response.query)
            .ok_or_else(|| ())
    }
}

struct DnsRequest {
    /// The DNS lookup
    query: Resolve,
    /// The channel where to send the response receiver.
    tx: oneshot::Sender<DnsResponseReceiver>,
}

impl DnsResolverReactor {
    /// Build a new reactor that uses the specified hickory resolver.
    ///
    /// Note: for per-circuit caches (option 3),
    /// there will be one DnsResolverReactor per circuit,
    /// all of them sharing an Arc::clone of the same underlying
    /// hickory Resolver
    ///
    // Question: should we try to make to make this generic over
    // the runtime? If so, we will need to add a (hickory) RuntimeProvider
    // trait bound to tor_rtcompat::Runtime.
    fn new(resolver: Arc<Resolver<TokioRuntimeProvider>>) -> (Self, DnsResolver) {
        // TODO: pick an appropriate buffer size here
        const DNS_QUERY_BUF_SIZE: usize = 512;
        let (query_tx, query_rx) = mpsc::channel(DNS_QUERY_BUF_SIZE);

        let mut inflight = JoinSet::new();
        // The inflight list has an always-pending task to prevent it from
        // yielding None when empty
        inflight.spawn(std::future::pending());

        let pending = PendingQueries {
            pending_response: Default::default(),
            inflight,
        };

        let reactor = Self {
            resolver,
            pending,
            cache: Default::default(),
            query_rx,
        };

        let handle = DnsResolver::new(query_tx);

        (reactor, handle)
    }

    /// Run the reactor.
    async fn run(mut self) {
        loop {
            select_biased! {
                res = self.pending.inflight.join_next().fuse() => {
                    // inflight can never yield None because
                    // we pushed a forever pending future in it
                    let res = res.expect("pending future resolvewd?!");
                    let Ok(response) = res else {
                        // TODO: log or handle the JoinError?
                        continue;
                    };
                    self.handle_response(response).await
                },
                query = self.query_rx.next() => {
                    let Some(query) = query else {
                        return;
                    };
                    self.handle_request(query).await
                }

                // TODO: periodically garbage-collect the expired entries?
                // get_or_remove_expired() helps a little bit, but
                // we will still accumulate expired entries unless
                // we remove them periodically
                //
                // Alternatively, we can make DnsCache a fixed-sized LRU cache,
                // and let the LRU policy take care of any stale records
            }
        }
    }

    /// Handles new queries coming from DnsResolver::resolve()
    async fn handle_request(&mut self, req: DnsRequest) {
        let DnsRequest { query, tx } = req;

        // TODO: normalize the query addr
        // (in case it has mixed capitalization)

        let now = Instant::now();

        // TODO: return an error if the RESOLVE doesn't have an ASCII query
        let query = Arc::new(String::from_utf8(query.query).unwrap());

        // First, if the query is already cached,
        // we can respond immediately
        let response_rx = if let Some(res) = self.cache.get_or_remove_expired(&query, now) {
            DnsResponseReceiver::from_response(res)
        } else {
            // If it's not, we need to launch a new lookup,
            // unless we already have a pending one for this query
            self.pending.get_or_insert(query, &self.resolver)
        };

        let _ = tx.send(response_rx);
    }

    /// Called when one of our pending queries completes.
    async fn handle_response(&mut self, res: DnsResponse) {
        let response_tx = self.pending.remove_for_response(&res).unwrap();
        // Update the cache
        self.cache.insert(res.clone());
        // Notify all the tasks waiting on this response
        response_tx.send(res);
    }
}

#[derive(Default)]
pub(crate) struct DnsCache {
    /// Our DNS cache, keyed by RESOLVE queries
    //
    // TODO: make this memquota-aware, and have memquota
    // evict entries using an LRU policy if we're under
    // memory pressure
    //
    //
    // Note: if we're implementing per-circuit caches,
    // we should make this fixed-size, allowing for 20-30 entries
    inner: HashMap<Arc<String>, DnsResponse>,
}

impl DnsCache {
    fn get_or_remove_expired(&mut self, query: &Arc<String>, now: Instant) -> Option<DnsResponse> {
        match self.inner.entry(Arc::clone(query)) {
            Entry::Occupied(e) => {
                let entry = e.get();
                if entry.valid_until > now {
                    Some(entry.clone())
                } else {
                    // The entry is expired, we should remove it from the cache
                    let _ = e.remove();
                    None
                }
            }
            Entry::Vacant(_) => None,
        }
    }

    fn insert(&mut self, res: DnsResponse) {
        self.inner.insert(Arc::clone(&res.query), res);
    }
}
```
