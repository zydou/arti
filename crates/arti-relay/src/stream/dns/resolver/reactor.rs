//! The DNS resolver reactor, for resolving DNS queries asynchronously.
//!
//! The [`DnsResolverReactor`] is meant to be run as a background task.
//! It is paired with a [`DnsResolver`], which exposes an async interface
//! for sending DNS queries to the reactor.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use derive_more::Constructor;
use futures::FutureExt as _;
use futures::channel::mpsc;
use futures::select_biased;
use futures::stream::StreamExt as _;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use smallvec::SmallVec;
use tokio::task::JoinSet;

use tor_async_utils::oneshot_broadcast;
use tor_error::{Bug, internal, into_internal};
use tor_rtcompat::{DynTimeProvider, SleepProvider as _};

use crate::stream::dns::resolver::{
    DnsRequest, DnsResolver, DnsResponseReceiver, LookupAnswers, LookupError, RecordData,
};

/// The hickory stub resolver.
pub(crate) type HickoryResolver = hickory_resolver::Resolver<TokioRuntimeProvider>;

/// The ASCII-encoded hostname from a RESOLVE, in canonical form.
type Query = Arc<str>;

// TODO(relay): check the TTLs against C Tor and the relevant DNS RFCs
// to make sure they're fit for purpose

/// The TTL to use for responses that have an empty answer section (not NXDOMAIN).
const TTL_FOR_EMPTY_ANS: Duration = Duration::from_mins(5);

/// The TTL for error responses.
const TTL_FOR_ERRORS: Duration = Duration::from_mins(5);

/// Our "low" TTL value. Any TTLs below this are clipped to this value.
///
/// Must be greater than FUZZY_DNS_TTL_SECONDS, otherwise our calculations can underflow.
const MIN_DNS_TTL: Duration = Duration::from_mins(5);

/// Our "high" TTL value. Any TTLs above MIN_DNS_TTL are clipped to this value.
const MAX_DNS_TTL: Duration = Duration::from_mins(60);

/// The amount we +- to the clipped TTL to make it "fuzzy".
///
/// Must be less than MIN_DNS_TTL, otherwise our calculations can underflow.
///
/// See "The effect of DNS on Tor's Anonymity" by Greschbach et al.
const FUZZY_DNS_TTL: Duration = Duration::from_mins(4);

/// A reactor that performs DNS lookups on behalf of incoming streams (RESOLVE, BEGIN).
///
/// De-duplicates queries, and uses hickory-resolver under the hood.
///
/// Queries are de-duplicated using [`PendingQueries`], which keeps track
/// of all the currently running lookup tasks.
#[must_use = "the reactor doesn't do anything unless you run it"]
pub(crate) struct DnsResolverReactor<M: MockableAsyncResolver = HickoryResolver> {
    /// The async stub resolver.
    resolver: Arc<M>,
    /// The time provider.
    runtime: DynTimeProvider,
    /// The DNS lookups we have launched that we are still waiting on.
    pending: PendingQueries,
    /// The DNS cache.
    cache: DnsCache,
    /// MPSC channel for receiving DNS queries.
    query_rx: mpsc::Receiver<DnsRequest>,
}

/// A DNS response.
///
/// We cache the response as a whole, not the individual answers.
#[derive(Clone, Debug, Constructor)]
pub(crate) struct DnsResponse {
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
    valid_until: Instant,
}

/// An answer record.
#[derive(Clone, Debug, Constructor)]
pub(crate) struct AnswerRecord {
    /// The answer record.
    data: RecordData,
    /// The TTL, used to compute the valid_until of the corresponding [`DnsResponse`].
    ttl: u32,
}

/// Type-alias for the hickory record type, for convenience
type HickoryRecord = hickory_proto::rr::Record<hickory_proto::rr::RData>;

impl TryFrom<&HickoryRecord> for AnswerRecord {
    type Error = LookupError;

    fn try_from(rec: &HickoryRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            data: RecordData::try_from(&rec.data)?,
            ttl: rec.ttl,
        })
    }
}

/// A mockable stub resolver.
///
/// Used for mocking the hickory resolver in the
/// [`DnsResolverReactor`] tests.
#[async_trait]
pub(crate) trait MockableAsyncResolver: Send + Sync + 'static {
    /// A random number generator
    type Rng: rand::Rng + rand::CryptoRng;

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    async fn lookup_ip(&self, query: &str) -> Result<LookupAnswers<AnswerRecord>, LookupError>;

    /// Performs a lookup for the associated type.
    async fn reverse_lookup(&self, query: &str)
    -> Result<LookupAnswers<AnswerRecord>, LookupError>;

    /// Return a random number generator
    fn thread_rng(&self) -> Self::Rng;
}

// TODO(relay): do we want hickory_resolver::ConnectionProvider to be a supertrait of tor_rtcompat::Runtime?
// It would enable us to write some unit tests involving the hickory resolver,
// without having to mock the whole thing like we do today.
//
// For now, this seems more trouble than it's worth.

#[async_trait]
impl MockableAsyncResolver for HickoryResolver {
    type Rng = rand::rngs::ThreadRng;

    async fn lookup_ip(&self, query: &str) -> Result<LookupAnswers<AnswerRecord>, LookupError> {
        let lookup = self.lookup_ip(query).await?;

        extract_hickory_answers(lookup.as_lookup())
    }

    async fn reverse_lookup(
        &self,
        query: &str,
    ) -> Result<LookupAnswers<AnswerRecord>, LookupError> {
        let lookup = self.reverse_lookup(query).await?;

        extract_hickory_answers(&lookup)
    }

    fn thread_rng(&self) -> Self::Rng {
        rand::rng()
    }
}

/// Convert a hickory [`Lookup`] into a collection of [`AnswerRecord`]s.
///
/// Note: we need our own AnswerRecord type here, because the hickory Record type
/// is quite big (272 bytes) and includes various fields we don't actually use
/// (such as the domain name that was looked up and the DNS record class).
fn extract_hickory_answers(lookup: &Lookup) -> Result<LookupAnswers<AnswerRecord>, LookupError> {
    // Note on TTLs: you might think we could use the valid_until timestamp
    // from the Lookup object here. However, that wouldn't give us
    // the real TTL, because hickory-resolver always sets this to the maximum
    // allowed TTL of 1 day (see the Future impl for LookupIpFuture in hickory_resolver).
    lookup
        .answers()
        .iter()
        .map(AnswerRecord::try_from)
        .collect::<Result<_, LookupError>>()
}

/// A response cache for the [`DnsResolverReactor`].
///
/// Maps [`Query`]s to [`DnsResponse`]s. In other words, we cache whole responses,
/// which may contain multiple answer records, each with its own TTL.
/// The TTL of a *cache entry* is calculated using the TTLs of the answers it contains:
///
///   * if the lookup failed, we use [`TTL_FOR_ERRORS`]
///   * if the lookup succeeded, but the answer section is empty,
///     we use [`TTL_FOR_EMPTY_ANS`]
///   * if the lookup succeded, and we got some answers, we calculate the TTL of the response
///     by taking the maximum TTL of the answers it contains
///
/// Finally, we clip and fuzz the resulting TTL before using it to calculate the
/// `valid_until` expiration timestamp of the cache entry (see [`clip_dns_fuzzy_ttl`]).
#[derive(Default)]
struct DnsCache {
    /// Our DNS cache, keyed by the ASCII encoded address extracted
    /// from RESOLVE queries.
    //
    // TODO(relay): make this memquota-aware, and have memquota
    // evict entries using an LRU policy if we're under
    // memory pressure
    inner: HashMap<Query, DnsResponse>,
}

impl DnsCache {
    /// Return the cached response for `query` if it still fresh at `now`,
    /// or `None` otherwise.
    ///
    /// If the query response is cached, but is expired at `now`,
    /// this will remove it from the cache.
    fn get_or_remove_expired(&mut self, query: &Query, now: Instant) -> Option<DnsResponse> {
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

    /// Insert the specified response into the cache.
    fn insert(&mut self, query: Query, res: DnsResponse) {
        self.inner.insert(query, res);
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
    pending_response: HashMap<Query, oneshot_broadcast::Sender<DnsResponse>>,
    /// DNS queries we're currently waiting a response for.
    //
    // TODO(relay): this uses a tokio JoinSet, as opposed to a runtime-agnotic
    // tor-rtcompat thing. Eventually, we might want to eventually replace this
    // with an equivalent tor-rtcompat type, so that we can control the execution
    // of these tasks in the tests.
    inflight: JoinSet<(Query, DnsResponse)>,
}

impl PendingQueries {
    /// Returns a [`DnsResponseReceiver`] for the specified `query`
    /// if there is currently an in-flight lookup for it,
    /// or spawn a new lookup, returning the [`DnsResponseReceiver`] for awaiting the response.
    fn get_or_launch_lookup<M: MockableAsyncResolver>(
        &mut self,
        query: Query,
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
            self.inflight.spawn(async move {
                let res = resolve_query(Arc::clone(&query), resolver, now).await;
                (query, res)
            });
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
async fn resolve_query<M: MockableAsyncResolver>(
    host: Query,
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

    let (answers, ttl) = match lookup.await {
        Ok(res) => {
            let answers: SmallVec<_> = res;
            let ttl = if answers.is_empty() {
                TTL_FOR_EMPTY_ANS
            } else {
                // Use the max TTL of all the answers
                let ttl = answers
                    .iter()
                    .map(|ans: &AnswerRecord| ans.ttl)
                    .max()
                    .expect("answers cannot be empty");

                Duration::from_secs(ttl.into())
            };
            let answers = answers.into_iter().map(|res| res.data).collect();

            (Ok(answers), ttl)
        }
        Err(e) => (Err(e), TTL_FOR_ERRORS),
    };

    let valid_until = now + clip_dns_fuzzy_ttl(ttl, &mut resolver.thread_rng());
    DnsResponse::new(answers, valid_until)
}

/// Clip the `ttl` to be either 5 minutes or 60 minutes.
///
/// If `ttl` is below 5 minutes, returns a TTL of 5 minutes.
/// If `ttl` is 5 minutes or above, returns a TTL of 60 minutes.
///
/// Like in C Tor, this logic is a defense against [DefectTor]
/// DNS-based traffic confirmation attacks.
///
/// [DefectTor]: https://nymity.ch/tor-dns/tor-dns.pdf
fn clip_dns_ttl(ttl: Duration) -> Duration {
    if ttl < MIN_DNS_TTL {
        MIN_DNS_TTL
    } else {
        MAX_DNS_TTL
    }
}

/// Clip and randomize the specified `ttl`.
///
/// This clips the `ttl` (see [`clip_dns_ttl`]),
/// and adds a random duration (sampled uniformly from [-4 min, 4min]),
/// in order to make it harder to infer when the corresponding domain
/// was visited from this exit relay (see "Website Fingerprinting with Website Oracles").
fn clip_dns_fuzzy_ttl<R: rand::Rng + rand::CryptoRng>(ttl: Duration, rng: &mut R) -> Duration {
    use tor_basic_utils::RngExt;

    let fuzzy_ttl_seconds = FUZZY_DNS_TTL.as_secs() as i32;

    let fuzz: i32 = rng
        .gen_range_checked(-fuzzy_ttl_seconds..=fuzzy_ttl_seconds)
        .expect("low as not < high");

    let ttl_secs: i32 = clip_dns_ttl(ttl)
        .as_secs()
        .try_into()
        .expect("clip_dns_ttl returned a humonguous TTL?!");

    debug_assert!(ttl_secs > fuzz, "FUZZY_DNS_TTL > MIN_DNS_TTL?!");

    let fuzzed_ttl_secs: u64 = (ttl_secs + fuzz)
        .try_into()
        .expect("a TTL of minutes does not fit in a u64?!");

    Duration::from_secs(fuzzed_ttl_secs)
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

        #[allow(clippy::disallowed_methods)]
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
                    let (query, response) = res.map_err(into_internal!("A DNS lookup panicked?!"))?;

                    self.handle_response(query, response)?;
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
            self.pending
                .get_or_launch_lookup(query, &self.resolver, now)
        };

        let _ = tx.send(response_rx);
    }

    /// Called when one of our pending queries completes.
    fn handle_response(&mut self, query: Query, res: DnsResponse) -> Result<(), Bug> {
        let response_tx = self.pending.remove(&query)?;

        // Update the cache
        self.cache.insert(query, res.clone());

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
