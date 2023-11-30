# HS service IPTs and descriptor publication algorithms

## Code structure

There are three and a half main pieces:

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
   Persistent (on-disk) state:
   current list of IPTs and their (last) states, fault counters, etc.,
   including secret keys necessary to re-stablish that IPT.
   Information about previously published
   descriptor contents (`PublishIptSet`)
   issued to hsdir publisher,
   that have not yet expired.

 * hsdir Publisher:
   One per HS.
   Identifies the hsdirs for the relevant time periods.
   Constructs descriptors according to the IPT manager's instructions,
   and publishes them to the hsdirs.

 * `ipt_set`, persistent data structure,
   shared between Manager and Publisher.
   Persistent (on-disk) state:
   which IPTs are published where.

Output of the whole thing:
Stream of introduction requests,
done by passing an mpsc sender into the IPT Manager's constructor,
which is simply cloned and given to each IPT Establisher.

(Each IPT Establisher is told by the IPT Manager
when a descriptor mentioning that IPT is about to be published,
so that the IPT Establisher can reject introduction attempts
using an unpublished IPT.)

(There are too many possible IPTs
to maintain experience information about IPTs we used to use;
the list of experience information would grow to the size of the network.
And recording *all* our IPT experiences might
lead to distinguishability.)

We might of course also operate a completely ephemeral hidden service,
which doesn't store anything on disk,
(and therefore gets a new K_hs_id each time it is started.)

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

When we lose our circuit to an IPT,
we look at the `ErrorKind` to try to determine
if the fault was local (and would therefore affect all relays and IPTs):

 * `TorAccessFailed`, `LocalNetworkError`, `ExternalToolFailed`
   and perhaps others:
   Return the IPT to `Establishing`.

 * Others: declare the IPT `Faulty`.

If we are doing verification, and
our verification probe fails,
but the circuit to the IPT appears to remain up:

 * If we didn't manage to build the test circuit to the IPT,
   check the `ErrorKind`, as above.

 * If we managed to build the test circuit to the IPT,
   but the probe failed (or the probe payload didn't arrive),
   declare the IPT `Faulty`.

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
