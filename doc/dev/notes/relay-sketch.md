# First steps and initial design for Arti relay work

(April 2024)

First, I'll sketch what we should do
in order to get arti relay work started.

Then, I'll try to sketch out some initial answers
to some of the design issues that arise during the startup plan.

(May 2024)

Updated from notes at Lisbon Tor meeting.


## Planning the work

### What do we do first?

I think the first phase of our relay development
should focus on getting a minimally functional relay
that can participate in the Tor protocols.

Once that's done, we can add more features,
improve performance,
hunt bugs,
and check other things off our list of deliverables.

With that in mind, here's what we need to build
to get a relay implementation
that can function on a testing network.

- DESIGN: We need a sketch of our [high-level code layout](#high-level),
  including what the major pieces are,
  which modules own [which objects](#proto-objects),
  and how it all generally looks.
  This doesn't need to be final. ([#1431])

- We need to support the relay variants of
  the channel establishment handshake.
  See <https://spec.torproject.org/tor-spec/negotiating-channels.html>.
  ([#1433])

  - This will require us to extend our `TlsProvider` API
    in `tor-rtcompat`
    so that it allows key material exporters. ([#1432])

    - DESIGN: How does the API for this work?
      Do we continue to allow the nativetls crate,
      which does not expose key material exporters?

- Extend ChanMgr to handle relay-style channels.
  - Ability to launch channels ([#1440])
  - Ability to manage incoming channels ([#1439]), including those with no
    identities ([#1435])
      - (Unauthenticated channels are technically not needed for
        middle relays, but they will matter a lot for the design of
        the system in the end.)
  - Soon after:
    - Ability to discard long-unused channels according to relay rule
      ([#1436])
    - Limit channels per IP. ([#1437])
    - Ability to de-duplicate channel according to relay rules ([#1438])
    - Ability to select _best_ channel among several with same ID? ([#1438])

- Code to listen for incoming OR connections. ([#1442])
  - DESIGN: [Where does this live](#high-level)?

- Support for incoming CREATE2 cells on channels. ([#1444])
  - ~~DESIGN: Is this the same Channel type or a new type?~~
    We decided: same channel type.
  - DESIGN: We need a way for the code that handles these cells
    to get the latest set ntor keys as needed.  Probably giving it
    a keymgr is overkill; some kind of `Arc<ExtendKeyHandle>` or
    `Arc<dyn ExtendKeyProvider>` or `Arc<RwLock<ExtendKeys>>`
    may be in order. ([#1443])

- A new `RelayCirc` type, crated by CREATE2 cells. ([#1445])
  - DESIGN: [How much code](#proto-objects) can this share internally
    with ClientCirc?
    The reactor logic is very similar,
    but the API is quite different.
  - Needs to accept cells, encrypt/decrypt, and re-transmit.
    - We'll want to refactor all of our "cells moving around" logic
      during the relay time, but we can do so more slowly.
  - Need to handle more types of command cells than currently
    handled.
  - There may need to be a corresponding manager type. ([#1446])

- Support for EXTEND2/EXTENDED2 cells on RelayCircuits ([#1447])
  - This will require initial design in the circuit reactor

- Exit logic for circuits. ([#1448])
  - Including exit policy support.
  - DESIGN: best practices for DNS and DNS caching.

- Support for generating ([#1450]) and publishing ([#1451]) relay
  descriptors. ([#1452])
  - DESIGN: Can/should this share any logic
    with publishing HS descriptors? 
  - Protocol changes may be needed to remove TAP keys from descriptors
    and microdescriptors ([torspec#264])
     - Possible short-term workaround: Genearate RSA TAP key and then
       throw away the private half

- Key management for relays. [#1449]

- Dirmgr support for making requests to authorities via HTTP. ([#1451])




Once all of the above is done,
we should be able run a mixed test network.
(We will still need C relays to be the directory caches,
and C directory authorities.)
Performance will be poor.

Next will come:

- Directory cache support ([#1453])
  - Handle BEGINDIR requests
  - Cache documents other than the latest versions
  - Generate and cache consensus diffs
  - Respond to HTTP-over-BEGINDIR requests for resources

- Support for [Happy Families](https://spec.torproject.org/proposals/321).
  (no ticket yet; not in minimal middle support.)


### What can we work on when we're blocked on the above?

If for some reason we get blocked doing one of the steps above,
we can spend our time on some other stuff
that won't be useful until later.

- Directory authority low-level operation
- Directory cache logic
- Designs for KIST+EWMA etc.
- Ensuring that we don't block important threads
  on expensive public-key crypto.

## Designing an Arti relay

NOTE:
None of the design here is complete or final!
The goal is to get us enough direction
so that we can start working.


### Design question: How do our high level crates work?

<a name="high-level"></a>

I propose the following:

- `arti` remains the top-level entry point.

- There is a new experimental `relay` feature.

- `arti` runs as a relay or a proxy; not both.
  (Running this way has created _tons_ of problems
  in C tor.)

- There is a new `arti-relay` crate underneath `arti`
  but above `arti-client`.
  It is responsible for launching and orchestrating
  our other modules, in the same way `arti-client` is.

  - It defines a `TorRelay` type.

- The `arti` crate still handles all the incoming TCP connections.
  It passes incoming OR connections to the TorRelay crate.

### Design: How do we handle channels, circuits, and streams?

<a name="proto-objects"></a>

Relay channels still use the `Channel` type.
There is some API to use when constructing a channel,
to tell the channel to negotiate using the relay protocol,
and to accept incoming circuits.

Relay channels are owned by the same `ChanMgr` object
as clients use.  We add new features to `ChanMgr` as needed.

Relay circuits use a new `RelayCirc` type,
since their API is radically different from `ClientCirc`.
Ideally, `RelayCirc` and `ClientCirc`
share much of their backend and reactor code.
(If this is feasible.)
But we have to do this in such a way that
we do not risk exposing one variety's features
as if they were the other's.

The `RelayCirc` type should not be owned by `CircMgr`,
since that module is extremely specialized
for launching multihop client circuits for particular needs.
Instead, `RelayCircs` are kept alive by the channels
that they're on.
There's probably a `RelayCircMgr` type somewhere
to handle enumerating or killing circuits
if we need to do so.

> NOTE: Conceivably there should be a single reactor for every
> RelayCirc on a given channel, or something like that.
> If so, the shared reactor logic above is probably not what we need.

Relay streams can continue to use `DataStream`,
in the same way that onion service streams do today.
We'll need an `exitproxy` implementation
sort of like our current `hsproxy` code.

[#1431]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1431
[#1432]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1432
[#1433]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1433
[#1435]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1435
[#1436]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1436
[#1437]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1437
[#1438]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1438
[#1439]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1439
[#1440]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1440
[#1442]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1442
[#1443]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1443
[#1444]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1444
[#1445]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1445
[#1446]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1446
[#1447]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1447
[#1448]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1448
[#1449]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1449
[#1450]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1450
[#1451]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1451
[#1452]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1452
[#1453]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1453
[torspec#264]: https://gitlab.torproject.org/tpo/core/torspec/-/issues/264

