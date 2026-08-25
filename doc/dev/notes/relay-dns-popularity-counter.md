This a proposed implementation sketch for
the popularity counter caching approach (option 5)
from [./doc/dev/notes/relay-dns.md].

This shares quite a bit with [./doc/dev/notes/relay-dns-simple-cache.md],
so I've omitted some of the details here
(I recommend reading relay-dns-simple-cache.md first).

Inspired by Nick's proposed sketch from
https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4259#note_3450925.

```rust
// How long _before_ a popular domain's expiration should we try to refetch it?
//
// Note: having this be a constant will leak our randomized `expiration`.
const REFETCH_GRACE_PERIOD: Duration = 1 minute;

// How long _before_ an unpopular domain's expiration should we try to refetch it?
//
// Note: having this be a constant will leak our randomized `expiration`.
const UNPOPULAR_REFETCH_GRACE_PERIOD: Duration = 1 minute;

// Threshold of how popular a domain must be
const POPULARITY_THRESHOLD: u32 = Lazy::new(||
   // QUESTION: how should the operator be expected to configure these?
   // Won't it depend on traffic?
   rand::rng().sample(configured_min..configured_max)
);

// How long should we try to hang on to a popular domain
// after it has become popular?
const RETAIN_POPULAR_DOMAINS: Duration = 1 week;

/// A DNS response.
///
/// To keep things simple, we cache the response as a whole,
/// as opposed to individual records.
#[derive(Clone, Debug)]
struct DnsResponse {
    /// The query this response is for.
    query: Arc<String>,
    /// The answer records from the DNS response, from hickory.
    answers: Result<SmallVec<[Record; 10]>, LookupError>,
    // When have we decided that this entry expires (if not refereshed)?
    //
    // (This is based on a randomized-and-clipped version of the max TTL
    // in // self.answers.)
    // (TODO: here and elsewhere, using Duration and Instant wastes a lot of RAM.)
    unpopular_valid_until: Instant,
    // If this entry becomes popular, when will we throw it away unconditionally?
    if_popular_valid_until: Instant,
    // What is the current popularity counter for this entry?
    popularity_counter: u32,
    /// Is this entry currently popular?
    ///
    /// If so, it will remain popular until `self.if_popular_valid_until`.
    is_popular: bool,
}

impl DnsResponse {
    // The constructor is similar to the one in ./doc/dev/notes/relay-dns.md,
    // except it also initializes the popularity counter to 1
    // and the *valid_until params:
    //
    //
    //  Self {
    //      query,
    //      answers,
    //      unpopular_valid_until: now + clip_and_fuzz_ttl(ttl),
    //      if_popular_retain_until: Instant::now() + randomize(RETAIN_POPULAR_DOMAINS),
    //      popularity_counter: 1,
    //      is_popular: false,
    //  }

   // True if this entry is popular
   fn is_popular(&self) -> bool {
       self.is_popular
   }

   // True if this entry is expired at `now`
   //
   // Indicates whether the entry should be removed from the cache.
   //
   // Will return a different result, depending on whether the entry
   // is currently popular or not.
   fn is_expired(&self, now: Instant) -> bool {
       if self.is_popular() {
           self.if_popular_valid_until < now
       } else {
           self.unpopular_valid_until < now
       }
   }

   /// Increment the popularity counter of this entry
   //
   // TODO: to introduce some FPs, we could randomize the value
   // we increment by?
   //
   // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4259#note_3450928
   fn inc_popularity_counter(&mut self) {
        self.popularity_counter += 1;
        if self.popularity_counter >= POPULARITY_THRESHOLD {
            self.is_popular = true;
        }
   }

   // True if we should launch an automatic re-fetch for this entry.
   fn should_refetch_now(&self, now: Instant) -> bool {
       let expiration = if self.is_popular() {
           self.if_popular_valid_until + REFETCH_GRACE_PERIOD
       } else {
           self.unpopular_valid_until + UNPOPULAR_REFETCH_GRACE_PERIOD
       };

       expiration >= now
   }
}

// Trackers for how well our cache is actually working.
//
// - Cache hits are cases where we serve a popular result.
// - Cache misses are cases where we had no entry in the cache at all.
// - The 'Unpopular' counter is for cases where we have a cached entry
//   but it was not populer enough to serve.
static HIT: AtomicUsize::new(0);
static UNPOPULAR: AtomicUsize::new(0);
static MISS: AtomicUsize::new();

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
    // The constructor is similar to the one in ./doc/dev/notes/relay-dns.md

    /// Run the reactor.
    async fn run(mut self) {
        loop {
            select_biased! {
                res = self.pending.inflight.join_next().fuse() => {
                    self.handle_response(response).await
                },
                query = self.query_rx.next() => {
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
            if res.should_refetch_now() {
                // Start refetching this entry in the background
                // Refetching resets the popularity counter of the domain,
                // but popularity is "sticky": once a domain becomes popular,
                // it stays popular until the retention period is over
                let _rx = self.pending.get_or_insert(query, &self.resolver);
            }

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
        // Update the cache, resetting the popularity counter back to 0
        // but preserving the is_popular property
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
    inner: HashMap<Arc<String>, DnsResponse>,
}

impl DnsCache {
    /// Get the cached entry for the specified query,
    /// if it is popular and not expired.
    fn get_or_remove_expired(&mut self, query: &Arc<String>, now: Instant) -> Option<DnsResponse> {
        match self.inner.entry(Arc::clone(query)) {
            Entry::Occupied(e) => {
                let entry = e.get();
                if entry.is_expired() {
                    // The entry is expired, we should remove it from the cache
                    let _ = e.remove();
                    return None;
                }

                entry.inc_popularity();
                if entry.is_popular() {
                    HIT.increment();
                    return Some(entry.clone());
                } else {
                    UNPOPULAR.increment();
                    // If the domain is unpopular, we trigger another lookup
                    //
                    // TODO: we could, in theory, make this return the entry
                    // on subsequent lookups on the same circuit,
                    // but we neeed some logic here to keep track of the
                    // circuits each entry was looked up on
                    return None;
                }
            }
            Entry::Vacant(_) => {
                MISS.increment();
                None
            }
        }
    }

    /// Insert a new response in the cache,
    /// preserving the current popularity status of its query.
    fn insert(&mut self, mut res: DnsResponse) {
        match self.inner.entry(Arc::clone(&res.query)) {
            Entry::Occupied(e) => {
                let entry = e.get();
                // Preserve the popularity, but nothing else
                res.is_popular = entry.is_popular;
                e.insert(res);
            }
            Entry::Vacant(v) => {
                v.insert(res);
            }
        }
    }
}
```
