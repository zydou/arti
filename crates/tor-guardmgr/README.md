# tor-guardmgr

Guard node selection for Tor network clients.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

"Guard nodes" are mechanism that Tor clients uses to limit the
impact of hostile relays. Approximately: each client chooses a
small set of relays to use as its "guards".  Later, when the
client picks its paths through network, rather than choosing a
different first hop randomly for every path, it chooses the best
"guard" as the first hop.

This crate provides [`GuardMgr`], an object that manages a set of
guard nodes, and helps the `tor-circmgr` crate know when to use
them.

Guard nodes are persistent across multiple process invocations.

More Arti users won't need to use this crate directly.

## Motivation

What's the point?  By restricting their first hops to a small set,
clients increase their odds against traffic-correlation attacks.
Since we assume that an adversary who controls both ends of a
circuit can correlate its traffic, choosing many circuits with
random entry points will eventually cause a client to eventually
pick an attacker-controlled circuit, with probability approaching
1 over time.  If entry nodes are restricted to a small set,
however, then the client has a chance of never picking an
attacker-controlled circuit.

(The actual argument is a little more complicated here, and it
relies on the assumption that, since the attacker knows
statistics, exposing _any_ of your traffic is nearly as bad as
exposing _all_ of your traffic.)

## Complications

The real algorithm for selecting and using guards can get more
complicated because of a variety of factors.

- In reality, we can't just "pick a few guards at random" and use
  them forever: relays can appear and disappear, relays can go
  offline and come back online, and so on.  What's more, keeping
  guards for too long can make targeted attacks against those
  guards more attractive.

- Further, we may have particular restrictions on where we can
  connect. (For example, we might be restricted to ports 80 and
  443, but only when we're on a commuter train's wifi network.)

- We need to resist attacks from local networks that block all but a
  small set of guard relays, to force us to choose those.

- We need to give good, reliable performance while using the
  guards that we prefer.

These needs complicate our API somewhat.  Instead of simply asking
the `GuardMgr` for a guard, the circuit-management code needs to
be able to tell the `GuardMgr` that a given guard has failed (or
succeeded), and that it needs a different guard in the future (or
not).

Further, the `GuardMgr` code needs to be able to hand out
_provisional guards_, in effect saying "You can try building a
circuit with this guard, but please don't actually _use_ that
circuit unless I tell you it's safe."

For details on the exact algorithm, see `guard-spec.txt` (link
below) and comments and internal documentation in this crate.

## Limitations

* Our circuit blocking algorithm is simplified from the one that Tor uses.
  See comments in `GuardSet::circ_usability_status` for more information.
  See also [proposal 337](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/337-simpler-guard-usability.md).

## References

Guard nodes were first proposed (as "helper nodes") in "Defending
Anonymous Communications Against Passive Logging Attacks" by
Matthew Wright, Micah Adler, Brian N. Levine, and Clay Shields in
the Proceedings of the 2003 IEEE Symposium on Security and
Privacy.  (See <https://www.freehaven.net/anonbib/#wright03>)

Tor's current guard selection algorithm is described in Tor's
[Guard Specification](https://spec.torproject.org/guard-spec/)
document.

## Compile-time features

* `bridge-client`: Build with support for bridges. (Bridges are relays
  that are not listed in the Tor network directory, which can be
  used for anti-censorship purposes.)

* `pt-client`: Build with support for guards that can be contacted
   using pluggable transports. (A pluggable transport is an alternative
   mechanism for contacting a Tor relay, for censorship avoidance.)

* `full`: Enable all features above.

License: MIT OR Apache-2.0
