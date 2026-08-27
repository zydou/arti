//! The DNS resolver reactor, for resolving DNS queries asynchronously.
//!
//! The [`DnsResolverReactor`] is meant to be run as a background task.
//! It is paired with a [`DnsResolver`], which exposes an async interface
//! for sending DNS queries to the reactor.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use derive_more::Constructor;
use futures::FutureExt as _;
use futures::channel::mpsc;
use futures::select_biased;
use futures::stream::StreamExt as _;
use tokio::task::JoinSet;

use tor_async_utils::oneshot_broadcast;
use tor_error::{Bug, internal, into_internal};
use tor_rtcompat::{DynTimeProvider, SleepProvider as _};

use crate::stream::dns::resolver::{
    DnsRequest, DnsResolver, DnsResponseReceiver, LookupAnswers, LookupError, RecordData,
};

/// A reactor that performs DNS lookups on behalf of incoming streams (RESOLVE, BEGIN).
///
/// De-duplicates queries, and uses hickory-resolver under the hood.
///
/// Queries are de-duplicated using [`PendingQueries`], which keeps track
/// of all the currently running lookup tasks.
#[must_use = "the reactor doesn't do anything unless you run it"]
pub(crate) struct DnsResolverReactor<M: MockableAsyncResolver> {
    /// The async stub resolver.
    resolver: Arc<M>,
    /// The time provider.
    runtime: DynTimeProvider,
    /// The DNS lookups we have launched that we are still waiting on.
    pending: PendingQueries,
    /// The DNS cache.
    ///
    /// The exactly details of its implementation are TODO(#2697)
    cache: DnsCache,
    /// MPSC channel for receiving DNS queries.
    query_rx: mpsc::Receiver<DnsRequest>,
}

/// A DNS response.
///
/// We cache the response as a whole, not the individual answers.
#[derive(Clone, Debug, Constructor)]
pub(crate) struct DnsResponse {
    /// The query this response was for.
    query: Arc<str>,
    /// The answer records.
    pub(crate) answers: Result<LookupAnswers<RecordData>, LookupError>,
    /// The timestamp when this response becomes invalid.
    ///
    /// This is computed by clipping + fuzzing the max TTL of all the answers.
    ///
    // TODO(relay): This does mean we'll be serving stale Records sometimes,
    // but I think that might be fine?
    //
    // RFC-8767 says resolvers are allowed to serve stale data,
    // **if** they're unable to refresh it
    // (that's not necessarily the case here,
    // although with a flexible enough interpretation of the RFC,
    // maybe it could be?):
    //
    // "If the data is unable to be authoritatively refreshed when the TTL expires,
    // the record MAY be used as though it is unexpired"
    #[allow(dead_code)]
    valid_until: Instant,
}

/// An answer record.
#[derive(Clone, Debug, Constructor)]
pub(crate) struct AnswerRecord {
    /// The answer record.
    data: RecordData,
    /// The TTL
    #[expect(unused)] // TODO(relay): use this to compute the valid_until of the DnsResponse
    ttl: u32,
}

/// A mockable stub resolver.
///
/// Used for mocking the hickory resolver in the
/// [`DnsResolverReactor`] tests.
#[async_trait]
pub(crate) trait MockableAsyncResolver: Send + Sync + 'static {
    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    async fn lookup_ip(&self, query: &str) -> Result<LookupAnswers<AnswerRecord>, LookupError>;

    /// Performs a lookup for the associated type.
    #[allow(dead_code)] // TODO(relay)
    async fn reverse_lookup(&self, query: &str)
    -> Result<LookupAnswers<AnswerRecord>, LookupError>;
}


/// A response cache for the [`DnsResolverReactor`].
#[derive(Default)]
struct DnsCache {/* TODO(#2697): implement */}

impl DnsCache {
    /// Return the cached response for `query` if it still fresh at `now`,
    /// or `None` otherwise.
    ///
    /// If the query response is cached, but is expired at `now`,
    /// this will remove it from the cache.
    fn get_or_remove_expired(&mut self, _query: &Arc<str>, _now: Instant) -> Option<DnsResponse> {
        // TODO(#2697): implement
        None
    }
}

/// A collection of in-flight DNS queries.
///
/// Used by the [`DnsResolverReactor`] to prevent launching multiple lookups for the same query.
struct PendingQueries {
    // TODO(relay): investigate if it would make sense to use the InternCache
    // from tor-basic-utils for the for the hostnames
    /// A list of streams that are waiting on responses to the DNS queries.
    /// Each of these has an entry in self.inflight.
    ///
    /// Keyed by the ASCII-encoded hostname from the RESOLVE, in canonical form.
    pending_response: HashMap<Arc<str>, oneshot_broadcast::Sender<DnsResponse>>,
    /// DNS queries we're currently waiting a response for.
    //
    // TODO(relay): this uses a tokio JoinSet, as opposed to a runtime-agnotic
    // tor-rtcompat thing. Eventually, we might want to eventually replace this
    // with an equivalent tor-rtcompat type, so that we can control the execution
    // of these tasks in the tests.
    inflight: JoinSet<DnsResponse>,
}

impl PendingQueries {
    /// Returns a [`DnsResponseReceiver`] for the specified `query`
    /// if there is currently an in-flight lookup for it,
    /// or spawn a new lookup, returning the [`DnsResponseReceiver`] for awaiting the response.
    fn get_or_insert<M: MockableAsyncResolver>(
        &mut self,
        query: Arc<str>,
        resolver: &Arc<M>,
        now: Instant,
    ) -> DnsResponseReceiver {
        let should_spawn_lookup =
            if let Entry::Occupied(e) = self.pending_response.entry(Arc::clone(&query)) {
                // If we already have an inflight query for the same request,
                // we just return a new watcher for that particular query
                if let Ok(rx) = e.get().subscribe() {
                    return DnsResponseReceiver::from(rx);
                } else {
                    // All the other receivers that were waiting on this query were dropped!
                    // This can happen, for example, if all the other pending DnsResolver::resolve()
                    // futures for this `guery` are canceled, for whatever reason.
                    //
                    // In practice, however, this won't happen, because in arti-relay,
                    // each RESOLVE is handled in a separate task,
                    // but it's better to handle it gracefully, rather than by returning an error,
                    // because returning an error here will cause the DnsResolverReactor to shut down.

                    // The existing pending_response entry is unusable,
                    // because its broadcast channel has closed.
                    e.remove();

                    // We will insert a new pending_response entry below
                    false
                }
            } else {
                // If we *don't* already have an in-flight lookup,
                // we need to launch one.
                true
            };

        // The channel on which to broadcast the lookup result
        // to all the tasks waiting on it
        // (used for deduplicating queries)
        let (res_tx, res_rx) = oneshot_broadcast::channel();

        let previous = self.pending_response.insert(Arc::clone(&query), res_tx);

        // This should be impossible, because we remove any dangling channels above
        debug_assert!(previous.is_none());

        if should_spawn_lookup {
            let resolver = Arc::clone(resolver);

            // Time to launch a new lookup
            self.inflight
                .spawn(async move { resolve_query(query, resolver, now).await });
        }

        DnsResponseReceiver::from(res_rx)
    }

    /// Remove the pending entry that was waiting for an answer to the specified `query`.
    fn remove(&mut self, query: &str) -> Result<oneshot_broadcast::Sender<DnsResponse>, Bug> {
        self.pending_response
            .remove(query)
            .ok_or_else(|| internal!("got response for a query we didn't ask for?!"))
    }
}

/// Try to resolve the specified `host`,
/// returning a `DnsResponse` to send back to the client.
///
/// The `host` must be a hostname.
/// If it ends in `in-addr.arpa.` or `ip6.arpa.`, this function will perform a reverse lookup.
///
// TODO(relay): The returned `DnsResponse` has an associated `valid_until`,
// which will be used for deciding how long to cache the response for.
// Currently unused
async fn resolve_query<M: MockableAsyncResolver>(
    host: Arc<str>,
    resolver: Arc<M>,
    now: Instant,
) -> DnsResponse {
    // Note the trailing dot (this expects canonicalize_hostname() to turn
    // the hostname into a FQDN)
    let lookup = if host.ends_with(".in-addr.arpa.") || host.ends_with(".ip6.arpa.") {
        resolver.reverse_lookup(&host)
    } else {
        resolver.lookup_ip(&host)
    };

    let (answers, valid_until) = match lookup.await {
        Ok(res) => {
            // TODO(relay): compute valid_until based on the TTLs of the answers
            // Note: see C Tor's clip_dns_fuzzy_ttl(ttl)
            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4420#note_3471238
            let valid_until = now;
            let answers = res.into_iter().map(|res| res.data).collect();
            (Ok(answers), valid_until)
        }
        Err(e) => {
            // TODO(relay): declare a constant for the TTL of negative answers
            let valid_until = now;
            (Err(e), valid_until)
        }
    };

    DnsResponse::new(host, answers, valid_until)
}

impl<M: MockableAsyncResolver> DnsResolverReactor<M> {
    /// Build a new reactor that uses the specified mockable resolver.
    ///
    /// Note: for per-circuit caches (option 3),
    /// there will be one DnsResolverReactor per circuit,
    /// all of them sharing an Arc::clone of the same underlying
    /// hickory Resolver
    ///
    // Question: should we try to make to make this generic over
    // the runtime? If so, we will need to add a (hickory) RuntimeProvider
    // trait bound to tor_rtcompat::Runtime.
    pub(crate) fn new(runtime: DynTimeProvider, resolver: Arc<M>) -> (Self, DnsResolver) {
        // TODO(relay-tuning): pick an appropriate buffer size here
        //
        // Alternatively, we might want to rework this so that this cannot becomes a bottleneck
        // (maybe it wants to be an unbounded channel? Or maybe we can somehow make it
        // memquota-aware?)
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
            runtime,
            pending,
            cache: Default::default(),
            query_rx,
        };

        let handle = DnsResolver::new(query_tx);

        (reactor, handle)
    }

    /// Run the reactor.
    pub(crate) async fn run(mut self) -> Result<(), Bug> {
        loop {
            select_biased! {
                res = self.pending.inflight.join_next().fuse() => {
                    // inflight can never yield None because
                    // we pushed a forever pending future in it
                    let res = res.expect("pending future resolvewd?!");

                    // This can only happen if a task panics, or is aborted.
                    // We never abort tasks, so this can only happen on panic.
                    let response = res.map_err(into_internal!("A DNS lookup panicked?!"))?;

                    self.handle_response(response)?;
                },
                query = self.query_rx.next() => {
                    let Some(query) = query else {
                        // All DnsResolvers were dropped
                        return Ok(());
                    };
                    self.handle_request(query);
                }

                // TODO: periodically garbage-collect the expired cache entries?
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
    fn handle_request(&mut self, req: DnsRequest) {
        let DnsRequest { query, tx } = req;

        let query = canonicalize_hostname(&query).into();
        let now = self.runtime.now();

        let response_rx = if let Some(res) = self.cache.get_or_remove_expired(&query, now) {
            // First, if the query is already cached,
            // we can respond immediately
            DnsResponseReceiver::from(res)
        } else {
            // If we don't have a cached answer,
            // we need to launch a new lookup,
            // unless we already have a pending one for this query
            self.pending.get_or_insert(query, &self.resolver, now)
        };

        let _ = tx.send(response_rx);
    }

    /// Called when one of our pending queries completes.
    fn handle_response(&mut self, res: DnsResponse) -> Result<(), Bug> {
        let response_tx = self.pending.remove(&res.query)?;

        // TODO(relay): Insert the response into the cache

        // Notify all the tasks waiting on this response.
        // If all the receivers have gone away, this will be ignored
        // (and the lookup response will be dropped).
        response_tx.send(res);

        Ok(())
    }
}

/// Return the hostname in canonical form.
///
/// Converts `hostname` to lowercase, and trims any leading or trailing whitespace.
/// The returned hostname is in FQDN form (it ends with '.').
///
/// This function assumes that `hostname` is an ASCII string.
fn canonicalize_hostname(hostname: &str) -> String {
    let mut hostname = hostname.trim().to_lowercase();
    if !hostname.ends_with('.') {
        hostname.push('.');
    }

    hostname
}

// TODO(relay): tests!
