# Relay DNS resolution

This is up to date as of 3 August 2026

## Motivation

This document describes several possibilities for arti-relay's DNS resolver
and corresponding DNS cache, based on the recent discussions from [#1448].
None of these ideas are new; they've all been come up in the past,
most notably in the C Tor issue tracker.
This doc tries to put all of these historical discussions
in the context of Arti, and to propose an implementation plan.

The trickiest part of this work is going to be the DNS cache.

> For context, reducing latency is not the only reason we need some sort of DNS cache;
> without a cache, exits will be leaking all domain lookups to the resolver.
> This is less of a problem for exits that use their ISP's resolver,
> because the ISP already sees all the outgoing connections;
> it's more of an issue if the exit is using a third-party resolver
> (such as Google's resolver), as that would unnecessarily leak the DNS queries
> to an additional, potentially-malicious entity.
>
> On the other hand, a poorly implemented cache can also leak information.
> Specifically, we need to design our cache to prevent two types of attacks:
>
>   * active probing attacks (e.g. "timeless timing attacks"): it shouldn't
>     possible for attackers to use our DNS cache as an oracle, by probing (for
>     example, using `RESOLVE`) for cached domains. See [TROVE-2021-009] for full
>     details on the sort of attack this design aims to prevent
>   * correlation attacks by adversaries that are able to monitor some of the
>     traffic going in and out of the Tor network
>
> Additional factors to consider: in the very worst case, the attacker controls
> the target DNS domain, and controls which addresses the client connects to
> (e.g., by embedding them in a website).


## The status quo

C Tor has an in-memory cache, which cannot be disabled (see [tor#40942]).

The Tor exit relay guide currently recommends that exit operators
[run a caching recursive resolver][exit-guide] like `unbound` alongside their relay,
and it recommends against relying on third-party resolvers like 8.8.8.8.
IIUC, this means a Tor exit relay has two local DNS caches,
one in C Tor, and one in unbound (or whatever the local resolver is).
This seems wasteful in terms of memory usage,
especially if the resolver is only used by a single exit relay
(but it beats the centralization/info leak that would result from instructing
relays to use any one particular third-party resolver).

> Note: the status quo is considered suboptimal,
> and running a recursive resolver on the exit is not a good idea:
> even with QNAME minimisation, we'd still be leaking the lookup to multiple ASes.
> IIUC, the Tor exit relay guide says one local recursive resolver
> is helpful for working around DNS-based censorship (by the ISP, for example),
> but it is unclear how big of an issue this is.
>
> For more context, see [this thread](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4259#note_3444638)

I suppose this setup makes most sense if the resolver is shared by
multiple different exits.

C Tor's internal cache uses fuzzy (randomized) clipped TTLs:

```c
/** Given a TTL (in seconds), determine what TTL an exit relay should use by
 * first clipping as usual and then adding some randomness which is sampled
 * uniformly at random from [-FUZZY_DNS_TTL, FUZZY_DNS_TTL].  This facilitates
 * fuzzy TTLs, which makes it harder to infer when a website was visited via
 * side-channels like DNS (see "Website Fingerprinting with Website Oracles").
 *
 * Note that this can't underflow because FUZZY_DNS_TTL < MIN_DNS_TTL.
 */
uint32_t
clip_dns_fuzzy_ttl(uint32_t ttl)
{
  // NOTE: clip_dns_ttls clips the TTL to be
  //
  //   * 5 minutes, if ttl < 5 minutes
  //   * 60 minutes, if ttl >= 5 minutes
  //
  // In arti, we might want to make this tunable
  return clip_dns_ttl(ttl) +
    crypto_rand_uint(1 + 2*FUZZY_DNS_TTL) - FUZZY_DNS_TTL;
}
```

In the `RESOLVED` responses, C Tor lies to clients and always returns
the same, hard-coded TTL:

```c
/** The clipped TTL sent back in the RESOLVED cell for every DNS queries.
 *
 * See https://gitlab.torproject.org/tpo/core/tor/-/issues/40979 for a thorough
 * explanation but this is first and foremost a security fix in order to avoid
 * an exit DNS cache oracle. */
#define RESOLVED_CLIPPED_TTL (60)
```

## Preliminaries

  * to keep things simple, we will only resolve and cache A, AAAA, PTR queries.
    Supporting other record types would require protocol changes,
    and is outside the scope of this work, see [prop-219]
  * we will cache both the successful responses and the failures
  * we will not persist the DNS cache to disk,
    because it is too sensitive to store: a malicious actor
    wanting to get their hands on it could intimidate/compel
    exit operators to give away the cached domains and associated TTLs.
    The only exception would be the DNS preload cache (option 3 below),
    which can be safely persisted, as its entries are fetched on a timer,
    and consist of the top N domains from a hard-coded list
    (so this cache wouldn't have any user data)

## TTL considerations

To protect against correlation attacks (see ["DefecTor"]),
we should use fuzzy, clipped TTls,
and lie to clients about the TTL in our `RESOLVED` responses,
just like C Tor.


## Concurrency

The DNS cache will be used for DNS and exit streams,
and so it will need to be shared between different tasks.
We should aim for a lockless implementation,
because a lock can easily become a bottleneck here.

## Part 1: the resolver

In terms of the actual DNS resolution, we plan to

  * stop instructing exit operators to run `unbound` or other local recursive
    resolvers; instead, we will recommend using the ISP's resolver
  * internally, `arti-relay` will use a caching stub resolver,
    ideally one that supports DoE and DNSSEC


### Implementation

I think we'll want to use an async resolver like [`hickory-resolver`],
but I don't think we're going to want to use its internal cache:

  * `hickory-resolver`'s cache is based on on `moka`,
    which has has a questionable [safety record][moka-safety-record]
  * ideally our cache should be hooked up to the memquota system (see "Memquota
    considerations" below), and that won't be possible unless we roll our own
    cache

The `hickory-resolver` maintainers seem open to making `moka` an optional dependency though,
so we could submit a patch to gate it behind a feature flag.

In terms of extra security features, `hickory-resolver` supports both DoE
(in the form of DoT or DoH) and DNSSEC (we will likely enable both).


## Part 2: the cache

> I think it would be useful to know exit/DNS statistics
> such as
>
>  * how many DNS requests (either via RESOLVE or BEGIN)
>    does the average circuit make?
>  * how many circuits does a busy exit typically have?
>    how many of them have open streams?

The options I have considered are, in order of difficulty:

  1. No internal DNS caching at all; relay operators must run their
    own caching resolvers
  2. Cross-circuit ("global") DNS cache (like C Tor)
  3. Per-circuit cache, no cross-circuit sharing
  4. Per-circuit cache + DNS preload cache
  5. Per-circuit cache + global cache for popular domains w/ auto-refresh

### Option 1: No DNS caching in arti-relay

The simplest option for us would be for arti-relay to not have a DNS cache at all.
Instead, arti-relay would rely on an external process (such as unbound) for caching.
This avoids us reinventing the DNS cache wheel,
at the expense of having little-to-no control over the caching logic.

The [exit relay guide][exit-guide] already instructs exit operators to run
their own resolvers, so this wouldn't change anything
from an operational perspective
(we'd just forgo the in-process cache).

Pros:
  - no-op or almost no-op to implement

Cons:
  - less control over the caching logic; cannot randomize TTLs,
    which opens us up to traffic correlation attacks
  - we would be relying on exit operators to set this up correctly,
    which leaves room for error/misconfiguration

AFAIK `unbound` et al don't support randomized TTLs,
and I think the lack of fuzzy TTLs will be a problem
(because of traffic correlation), so this option is a no-go.

### Option 2: Global DNS cache

All circuits share the same DNS cache.

Pros:
  - simple to implement and reason about

Cons:
  - possibly vulnerable to timing attacks


In C Tor, this approach was vulnerable to ["timeless timing attacks"].
This attack can be used to check if any given domain is cached at an exit,
with 100% success rate. Mike summarized it well in
[this comment](https://gitlab.torproject.org/tpo/core/arti/-/work_items/1448#note_3435613):

> In brief, two RESOLVE are sent: one for the probed "example.com" domain, and
> one for a known-cached "evil.com" domain. When C-Tor answers from the cache,
> it answers immediately. So if the "example.com" is cached, these RESOLVED
> responses arrive in the same order. If "example.com" is not cached, "evil.com"
> comes back before "example.com"

Arti will process each incoming RESOLVE stream in a new task.
So while we won't have a lot of control over the order
in which the RESOLVE requests are handled,
the actual ordering will be less predictable than it is in C Tor,
which in theory, turns the "timeless timing attach" into more of a timing attack.
That said, it's very likely that in practice, the cached responses will consistently
resolve before the non-cached ones, so Arti would likely still be vulnerable
to the timeless timing attack.

As Mike suggests [here](https://gitlab.torproject.org/tpo/core/arti/-/work_items/1448#note_3435613),
one solution would be to introduce a randomized delay in each
cached response (but that diminishes any latency improvement we might otherwise
be getting from caching).


-----

On the [nothing to hide] blog, there's another interesting potential mitigation:

> From the moment a domain is looked up once, the domain will be continuously
> refreshed close to the end of their respective TTL cycle (ideally with a
> randomized offset) for a long retention period (e.g. 7 or even 30 days). Every
> time a domain’s record is requested, the ‘purge timer’ will be reset to zero.
> If a domain’s record has not been requested for the retention period, it gets
> purged from the cache to not let it linger around indefinitely.

"Option 5" below is a variation of this idea.


### Option 3: per-circuit cache, no cross-circuit sharing

Each circuit will have its own DNS cache.

Pros:
  * mitigates all DNS-related timing side-channels,
    because the caches aren't shared

Cons:
  * the more popular domains will have duplicated their cache entries duplicated
    over multiple circuits, so this will increase memory usage

### Option 4: per-circuit cache + DNS preload cache

This option would involve adding a preload cache on top of the per-circuit
cache.

Pulls gave a detailed description of the approach in
[this comment](https://gitlab.torproject.org/tpo/core/arti/-/work_items/1448#note_3435613).

Pros:
  * mitigates the timeless side-channel, and has a much lower memory footprint
    than option 3

Cons:
  * more costly to implement and maintain than the previous options
  * we would need to trust the organization/entity that generates
    the domain list
  * it is unclear who would be generating and maintaining the *extended* domain
    list (I suspect it would be the Network Health team,
    which makes this option a cross-team effort,
    which comes with additional operational and communication overhead)

### Option 5: Per-circuit cache + global cache for popular domains

This idea was [proposed by Mike][popularity-counters-with-auto-ref],
and is essentially a combination of [nothing to hide]s auto-refresh idea
mentioned above and the popularity counter idea from [tor#32678].
Mike also suggests combining this with the probabilistic caching ideas
from [tor#40674][TROVE-2021-009].

I propose we implement a somewhat simplified version of this
(credit goes to David for the TTL-based counter reset idea):

  * all lookups are cached in a global cache;
  * in addition to the response and associated TTL, each cache entry has a
    popularity counter
  * when a domain is looked up, its popularity counter is incremented by 1.
    The domain becomes "popular" if its popularity counter has reached
    the "popularity threshold" (this threshold would be sampled from
    a configurable `[min, max]` range)
  * unpopular items are removed from the cache as soon as their TTL expires
  * unpopular items are *never* served from the cache
  * each time a domain's TTL expires, its popularity counter is reset to 0.
    This applies to all domains, regardless of popularity
  * popular domains are given a long retention period (7-30 days),
    during which they are continually refreshed by a background task
    (they are refetched when their TTL is due to expire),
    and are only purged from the cache if they become unpopular again.
    A domain becomes unpopular if its popularity counter is below
    the popularity threshold when its retention period elapses
  * when we receive a lookup request, we will only serve the response from the
    global cache if the lookup is for a popular domain.
    Otherwise, if the domain is unpopular, we will perform the lookup again,
    and update its entry with the new TTL

Pros:
  * maybe(?) mitigates the timeless side-channel;
    concerns about the lack of false positives for unpopular domains

Cons:
  * complex implementation

----

## Proposed Rust APIs

Whether we implement a per-circuit cache or a global one, our DNS resolver
should deduplicate requests, and be asyncrhonous. The APIs will be roughly the
same in both cases.

`arti-relay`'s DNS subsystem will consist of a reactor (`DnsResolverReactor`)
that runs in the background, and a handle to that reactor (`DnsResolver`).
Each BEGIN and RESOLVE stream is handled in a separate task,
each of which  gets a clone of the `DnsResolver`.

In `TorRelay::run()`:

```rust
    // Use the host's /etc/resolv.conf
    //
    // TODO: enable DNSSEC and DoT, disable hickory's internal cache
    let resolver = Arc::new(Resolver::builder_tokio()?.build()?);

    // Spin up a new DNS resolver for this relay.
    //
    // There is only one resolver per arti-relay process,
    // shared by all circuits. IOW, all circuits share the same cache
    // (this is Option 2 from above).
    let (reactor, resolver) = DnsResolverReactor::new(resolver);

    // Note: if we want per-circuit caches instead,
    // we will need to spawn a new DnsResolverReactor
    // for each circuit, in `handle_circuit_incoming_streams()`,
    /// all of them sharing an Arc::clone of the same underlying
    /// hickory Resolver
    runtime.spawn(async move { reactor.run().await });

```

The `DnsResolver` will be used in `handle_resolve()` and `handle_begin()`.
For example:


```rust
/// Handle an incoming DNS stream
pub(crate) async fn handle_resolve(
   incoming: IncomingStream,
   resolver: DnsResolver
) -> anyhow::Result<()> {
    // TODO: error handling + checks against opening a RESOLVE stream
    // on a non-exit

    // 1. extract the Resolve relay msg from incoming
    let resolve = ...

    // 2. Pass the RESOLVE to the resolver
    // (note: we may want to pass a different type here),
    // and perform the lookup
    let ans = resolver.resolve(resolve).await?;

    let resolved = Resolved::new_empty();
    // 3. push the answers into resolved

    // TODO(#2572): add an IncomingStream::resolved() API
    // for sending RESOLVED:
    incoming.resolved(resolved).await;
}
```

The reactor implementation depends on whether
we implement a simple cache (options 2 and 3),
or a popularity-based cache (option 5).

But in either case, the handle to the reactor, the `DnsResolver`,
will have same API, and roughly the same implementation:

```rust
/// A handle to the [`DnsResolverReactor`].
#[derive(Clone)]
pub(crate) struct DnsResolver {
    /// Sender for sending DNS queries to the reactor
    ///
    /// The reactor sends back each response over a DnsResponseReceiver.
    query_tx: mpsc::Sender<DnsRequest>,
}

struct DnsResponseReceiver {
    /// The response is either from cache (Left),
    /// or from a lookup that needs to be .awaited (Right).
    res: Either<DnsResponse, oneshot_broadcast::Receiver<DnsResponse>>,
}

impl DnsResponseReceiver {
    fn from_response(res: DnsResponse) -> Self {
        Self {
            res: Either::Left(res),
        }
    }

    fn from_watch(watch_rx: oneshot_broadcast::Receiver<DnsResponse>) -> Self {
        Self {
            res: Either::Right(watch_rx),
        }
    }

    async fn recv(self) -> DnsResponse {
        match self.res {
            Either::Left(res) => {
                // TIMELESS-SIDE-CHANNEL-MITIGATION:
                //
                // (this is not needed if we're implementing per-circuit caches)
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
                res
            }
            Either::Right(watch_rx) => watch_rx.await.unwrap(),
        }
    }
}

impl DnsResolver {
    fn new(query_tx: mpsc::Sender<DnsRequest>) -> Self {
        Self { query_tx }
    }

    async fn resolve(&mut self, query: Resolve) -> Result<DnsResponse> {
        let (tx, rx) = oneshot::channel();

        let req = DnsRequest { query, tx };
        // Send the query to the reactor,
        // which handles the actual DNS resolution,
        // and then wait for it to respond
        self.query_tx.send(req).await?;

        let response_rx = rx.await?;
        response_rx.recv().await
    }
}

```

And the proposed reactor implementations are

  * [./doc/dev/notes/relay-dns-simple-cache.md] (options 2 and 3)
  * [./doc/dev/notes/relay-dns-popularity-counter.md] (option 5)


## Memquota considerations


At the time of writing (July 2026), we don't have a way of using memquota for our caches.
See [doc/dev/notes/memory-limit.md] and [!1997] for context.

For our purposes, I think the memquota integration for the DNS cache
(be it global or per circuit) needs to

  * count all cached data towards the total usage
  * start evicting cache entries when it enters the reclamation phase

TODO: needs discussion with Diziet

## Configuration considerations

C Tor has a number of config options for its DNS subsystem:

  * `ServerDNSAllowBrokenConfig`
  * `ServerDNSAllowNonRFC953Hostnames`
  * `ServerDNSDetectHijacking`
  * `ServerDNSRandomizeCase`
  * `ServerDNSResolvConfFile`
  * `ServerDNSSearchDomains`
  * `ServerDNSTestAddresses`

We might want to also add an option for disabling DNS caching entirely
(see the reasoning from [tor#40942]).

We will need to decide which of these are relevant for Arti ([#2643]).


## Misc

### What if DNS appears to be broken?

> See discussion in [tor#21989] for C Tor background

C Tor runs periodic checks to see if DNS is working correctly
(see `dns_launch_correctness_checks()` and `check_dns_honesty_callback()`).
These checks can be disabled using the `ServerDNSDetectHijacking` option.

We may want something similar in Arti ([#2644]).

## Short-to-medium-term implementation plan 1: **rejected**

For the purposes of p141, I see see two possible options here,
both of which have tradeoffs:

  * we can implement a global cache, and run some experiments to see if the
    timeless timing attack is actually still effective against arti-relay. We
    can also introduce some randomized delays (based on the average DNS lookup
    latency) in the cached responses to mitigate it. We need to be careful here,
    because too high of a delay can also serve as a side-channel: if we make the
    delay too large,  we could end up in the unfortunate situation where all
    the cached responses consistently arrive *later* than the non-cached ones,
    which would not only be bad for performance, but it would also be a
    timeless timing attack side-channel
  * we could do per-circuit caches, and revisit the decision if the memory usage
    turns out to be an issue

I have a slight preference for the per-circuit caches, because in principle, I
think it's better to sacrifice performance than security. In terms of memory
usage, my back-of-the-envelope calculation is as follows:

Let's assume we have an exit with 1M circuits and a conservative 20 DNS lookups per
circuit (note: these are all made up numbers; actual data would help here).

From the "timeless timing attack" paper:

> To summarize, Tor’s DNS cache has a cache-hit ratio over 80% using a
> modestly sized DNS cache. About 11–17% of these hits are due to sharing the
> cache across circuits. The number of lookups are weakly correlated to exit
> probability.

Assuming the size of a cached DNS response is ~512 bytes, the per-circuit cache size
will be ~10 KB, so the total size of the cache will be 10 GB.
About 20% of each of the per-circ caches is duplicated,
so we would be wasting about ~2 GB in total by not using a global cache, which is not great.

Tentative plan:

  * [ ] Implement the resolver APIs described above
  * [ ] Add an `IncomingStream::resolved()` API for sending RESOLVED ([#2572])
  * [ ] Make the `DnsResolverReactor` operate as a recursive resolver, if
    configured to do so, or as a stub resolver if not
  * [ ] Implement option 3 above (per circuit caches), giving each circuit its
    own `DnsResolver`
  * [ ] If time permits, patch hickory-resolver to make its cache impl
    conditionally compiled

## Short-to-medium-term implementation plan 2

  * [ ] Implement the resolver APIs described above
  * [ ] Add an `IncomingStream::resolved()` API for sending RESOLVED ([#2572])
  * [ ] Make the `DnsResolverReactor` operate as a stub resolver,
    with a custom global cache on top
  * [ ] Implement option 2 above (global cache)
  * [ ] Design and implement the necessary memquota APIs for evicting entries
    when we're under memory pressure
  * [ ] If time permits, patch hickory-resolver to make its cache impl
    conditionally compiled

## Medium-to-long-term plan

  * [ ] Introduce randomized delays in the cached responses. These will need to
    be based on our previously observed lookup timings, to avoid delaying by too
    much or too little (if we consistently delay too much, or too little, the
    cached responses will still be distinguishable from the non-cached ones,
    so we need to be careful here)
  * [ ] Run experiments to determine how vulnerable we are to the timing attacks
    that were/are possible in C Tor
  * [ ] Obtain grant to implement a more sophisticated solution
    (such as a preload cache)

[#1448]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1448
[#2643]: https://gitlab.torproject.org/tpo/core/arti/-/issues/2643
[#2644]: https://gitlab.torproject.org/tpo/core/arti/-/issues/2644
[#2572]: https://gitlab.torproject.org/tpo/core/arti/-/issues/2572
[doc/dev/notes/memory-limit.md]: ./memory-limit.md
[!1997]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1997#note_2998981
[tor#40942]: https://gitlab.torproject.org/tpo/core/tor/-/work_items/40942
[tor#21989]: https://gitlab.torproject.org/tpo/core/tor/-/work_items/21989
[tor#32678]: https://gitlab.torproject.org/tpo/core/tor/-/work_items/32678
["timeless timing attacks"]: https://www.usenix.org/conference/usenixsecurity23/presentation/dahlberg
["DefecTor"]: https://nymity.ch/tor-dns/tor-dns.pdf
[TROVE-2021-009]: https://gitlab.torproject.org/tpo/core/tor/-/work_items/40674
[`hickory-resolver`]: https://crates.io/crates/hickory-resolver
[moka-safety-record]: https://github.com/hickory-dns/hickory-dns/issues/3270#issuecomment-4106238083
[nothing to hide]: https://nothingtohide.nl/blog/improving-dns-privacy/
[prop-219]: https://spec.torproject.org/proposals/219-expanded-dns.html
[exit-guide]: https://community.torproject.org/relay/setup/exit/
[`recurse`]: https://github.com/hickory-dns/hickory-dns/blob/f1258042ad358273d7e6cabc0ebdd7fce8b7df69/util/src/bin/recurse.rs#L51-L98
[popularity-counters-with-auto-ref]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4259#note_3444513
