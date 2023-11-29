# HS service IPTs and descriptor publication algorithms

## Code structure

There are three main pieces:

 * IPT Establisher:
   One per IPT.
   Given a single IPT relay attempts to set up,
   verify, maintain, and report on the introduction point.
   Persistent (on-disk) state: none.

 * IPT Manager:
   One per HS.
   Selects IPTs, creates and destroys IPT establishers,
   monitors their success/failure, etc.
   Persistent (on-disk) state:
   current set of IPT Relays.
   Optional persistent (on-disk) state:
   current list of IPTs and their (last) states, fault counters, etc.,
   including secret keys necessary to re-stablish that IPT;
   all previous descriptor contents (`IptSetForDescriptor`)
   issued to hsdir publisher,
   that have not yet expired.

 * hsdir publisher:
   One per HS.
   Identifies the hsdirs for the relevant time periods.
   Constructs descriptors according to the IPT manager's instructions,
   and publishes them to the hsdirs.
   Persistent (on-disk) state (optional):
   which versions (`IptSetForDescriptor`) are published where.

Output of the whole thing:
Stream of introduction requests,
done by passing an mpsc sender into the IPT Manager's constructor,
which is simply cloned and given to each IPT Establisher.

(Each IPT Establisher is told by the IPT Manager
when a descriptor mentioning that IPT is about to be published,
so that the IPT Establisher can reject introduction attempts
using an unpublished IPT.)

I think there are too many possible IPTs
to maintain experience information about IPTs we used to use;
the list of experience information would grow to the size of the network.
Is this true?
If not, would recording *all* our IPT experiences
lead to distinguishability ?

Some of the persistent state is optional:
for a persistent hidden service, we prefer to store this information,
to improve resilience after service restarts.
But we can work without it,
for example when we are operating an ephemeral service.

## IPT selection and startup for a new HS, overall behaviour

 * Select N suitable relays randomly to be IPTs

 * Attempt to establish and verify them, in parallel

 * Wait a short time
   and then publish a short-lifetime descriptor listing the ones
   set up so far (this gets us some working descriptors right away)

 * When we have all the IPTs set up, republish the descriptor.

(This behaviour follows from the detailed algorithm below.)

## Verification and monitoring (optional, probably not in v1)

After ESTABLISH_INTRO,
we attempt (via a 2nd set of circuits)
an INTRODUCE probe, to see if the IPT is working.

We do such probes periodically at random intervals.

NOTE: there is a behaviour/privacy risk here,
which should be properly considered before implementation.

## General operation, IPT selection

We maintain records of each still-possibly-relevant IPT.
(We distinguish "IPT",
an intended or established introduction point with particular keys etc.,
from an "IPT Relay", which is a relay at which we'll establish the IPT.)

We attempt to maintain a pool of N established and verified IPTs,
at N IPT Relays.

When we have fewer than N IPT Relays
that have `Establishing` or `Good` IPTs (see below)
and fewer than k*N IPT Relays overall,
we choose a new IPT Relay at random from the consensus
and try to establish an IPT on it.

(Rationale for the k*N limit:
we do want to try to replace faulty IPTs, but
we don't want an attacker to be able to provoke us into
rapidly churning through IPT candidates.)

When we select a new IPT Relay, we randomly choose a planned replacement time,
after which it becomes `Retiring`.

Additionally, any IPT becomes `Retiring`
after it has been used for a certain number of introductions
(c.f. C Tor `#define INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS 16384`.)
When this happens we retain the IPT Relay,
and make new parameters to make a new IPT at the same Relay.

An IPT is removed from our records, and we give up on it,
when it is no longer `Good` or `Establishing`
and all descriptors that mentioned it have expired.

(Until all published descriptors mentioning an IPT expire,
we consider ourselves bound by those previously-published descriptors,
and try to maintain the IPT.
TODO: Allegedly this is unnecessary, but I don't see how it could be.)

When we lose our circuit to an IPT,
we look at the `ErrorKind` to try to determine
if the fault was local (and would therefore affect all relays and IPTs):

 * `TorAccessFailed`, `LocalNetworkError`, `ExternalToolFailed`
   and perhaps others:
   Return the IPT to `Establishing`.

 * Others: declare the IPT `Faulty`.

If our verification probe fails,
but the circuit to the IPT appears to remain up:

 * If we didn't manage to build the test circuit to the IPT,
   check the `ErrorKind`, as above.

 * If we managed to build the test circuit to the IPT,
   but the probe failed (or the probe payload didn't arrive),
   declare the IPT `Faulty`.

## IPT sets and lifetimes

We remember every IPT we have published that is still valid.

At each point in time we have an idea of set of IPTs we want to publish.
The possibilities are:

 * `Certain`:
   We are sure of which IPTs we want to publish.
   We try to do so, talking to hsdirs as necessary,
   updating any existing information.
   (We also republish to an hsdir if its descriptor will expire soon,
   or we haven't published there since Arti was restarted.)

 * `Unknown`:
   We have no idea which IPTs to publish.
   We leave whatever is on the hsdirs as-is.

 * `Uncertain`:
   We have some IPTs we could publish,
   but we're not confident about them.
   We publish these to a particular hsdir if:
    - our last-published descriptor has expired
    - or it will expire soon
    - or if we haven't published since Arti was restarted.

The idea of what to publish is calculated as follows:

 * If we have at least N `Good` IPTs: `Certain`.
   (We publish the "best" N IPTs for some definition of "best".
   TODO: should we use the fault count?  recency?)

 * Unless we have at least one `Good` IPT: `Unknown`.

 * Otherwise: if there are IPTs in `Establishing`,
   and they have been in `Establishing` only a short time [1]:
   `Unknown`; otherwise `Uncertain`.

The effect is that we delay publishing an initial descriptor
by at most 1x the fastest IPT setup time,
at most doubling the initial setup time.

Each update to the IPT set that isn't `Unknown` comes with a
proposed descriptor expiry time,
which is used if the descriptor is to be actually published.
The proposed descriptor lifetime for `Uncertain`
is the minimum (30 minutes).
Otherwise, we double the lifetime each time,
unless any IPT in the previous descriptor was declared `Faulty`,
in which case we reset it back to the minimum.
TODO: Perhaps we should just pick fixed short and long lifetimes instead,
to limit distinguishability.

(Rationale: if IPTs are regularly misbehaving,
we should be cautious and limit our exposure to the damage.)

[1] NOTE: We wait a "short time" between establishing our first IPT,
and publishing an incomplete (<N) descriptor -
this is a compromise between
availability (publishing as soon as we have any working IPT)
and
exposure and hsdir load
(which would suggest publishing only when our IPT set is stable).
One possible strategy is to wait as long again
as the time it took to establish our first IPT.
Another is to somehow use our circuit timing estimator.

## Descriptor publication

The descriptor output from the IPT maintenance algorithm is
an updated (`postage::watch`) `IptSetStatus`:

```
enum IptSetStatus {
    Unknown,
    Certain(IptSetForDescriptor),
    Uncertain(IptSetForDescriptor),
}
struct IptSetForDescriptor {
    ipts: list of introduction points for descriptor
    expiry_time: Instant,
}
```

We run a publication algorithm separately for each hsdir:

We record for each hsdir what we have published.

We attempt publication in the following cases:

 * `Certain`, if: the IPT list has changed from what was published,
   and we haven't published a `Certain` set recently
 * `Uncertain`, if: nothing is published,
   or what is published will expire soon,
   or we haven't published since Arti was restarted

If a publication attempt failed
we block further attempts
according to an exponential backoff schedule;
when the timer expires we reconsider
if and what we want to publish.

## Tuning parameters

TODO: Review these tuning parameters both for value and origin.
Some of these may be in `param-spec.txt` section "8. V3 onion service parameters"
Some of them may be in C Tor.

 * N, number of IPTs to try to maintain:
   configurable, default is 3, max is 20.
   (rend-spec-v3 2.5.4 NUM_INTRO_POINT)

 * k*N: Maximum number of IPTs including replaced faulty ones.
   (We may actually maintain more than this when we are have *retiring* IPTs,
   but this doesn't expose us to IPT churn since attackers can't
   force us to retire IPTs.

 * IPT replacement time: 4..7 days (uniform random)
   TODO: what is the right value here?  (Should we do time-based rotation at all?)

 * "Soon" for "if the published descriptor will expire soon":
   10 minutes.

 * Verification probe interval:
   descriptor expiry time minus 15 minutes.

 * Backoff schedule for hsdir publication.

## Load balancing (and maybe failover)

This is a sketch, only.
TODO: Look at what Onion Balance does before implementing this.

If it's desired to allow multiple Arti processes to serve a single HS:

The shards will have the IPT Establishers.

There will be one central IPT Manager
(perhaps with a failover).

Each shard will have an IPT Manager Stub
which receives instructions from,
and reports experiences to, 
the central IPT Manager.
