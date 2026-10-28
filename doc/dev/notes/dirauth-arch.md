# arti dirauth architecture

See `dirauth-sketch.md` too.
Information is split across these two design documents,
and may be duplicated.
(We will transfer this information to code comments,
spec, etc. as the implementation proceeds.)

## Fundamental approach

### State management

There will be a sqlite database.
The database will be used for as much state as possible.
Work will be performed by async tasks.

Each task will be driven by the database,
and attempt to make forward progress on its objectives.

### db schema, modularity

As a general rule, tables (or groups of tables)
in the database will be considered
owned by a particular Rust module in the source code.
Queries and updates should be built only by the module for that table,
since other modules should not assume knowledge of those parts of the schema.

Such a module will exchange data with other modules
using normal Rust types.
(albeit perhaps types implementing useful to/from sql conversion traits,
for the benefit of the implementation).

This table ownership cannot be enforced by the compiler but
will be documented in the code.

Normally, a module's API exposing functionality which handles db state,
will take a db transaction handle.
It is up to the caller(s) to decide what things need to be
in the same transaction, and to manage those transactions.

### Tasks

Async tasks that relate to a specific area of the state
can be implemented near the Rust module for that database state,
or even part of the same module.

But there are also tasks that straddle various aspects,
including notably the task which makes our own vote.

### External programs

The database will be accessed only by Rust code
in the dirauth (and dirserver) implementation.
Most of the work will be done within the single dirauth process.

External processes, data sources, etgc. (eg, the bandwidth scanner)
will have corresponding code (and, if necessary, tasks)
within the dirauth implementation.

## Principal components (tasks, modules, etc.)

### Principal contents of the DB

 * Router identity key pinning.
 * Routerdescs.  Similar requirements to dirmirror, but:
   - we can insert things other than via the fetcher
   - expiry is handled differently.
   - routerdesc fetches must be triggered by mentions in votes,
     not just in consensuses.
 * Microdescs.  Almost identical to the dirmirror.
 * Extra-info.  TBD.
   Will probably be a dirauth-specific wrapper around shared dirserver code.
 * Votes for the current voting period (other authorities', and our own).
 * Previous and current consensus.
   Unlike dirmirror, dirauth does not retain many consensus versions
   and does not compute diffs.
   We leave that to downstream dirmirrors.
   So we have three network statuses in play: previous consensus,
   current consensus, and the consensus currently being built and
   voted on ("nascent consensus").

### dirauth-dirauth data pump(s)

Task(s) that try to make sure that every other authority has our
documents and vice versa.

Documents that need to be transferred include:

 * Our votes (outbound)
 * Their votes (inbound)
 * Routerdescs, microdescs and extra-infos (both directions)
 * Consensus documents and their signatures (both directions)

**Data**:
We record some information in the db
about who we think has which documents already,
and also futile transfers (apparently invalid documents).

**In-memory status**:
Just a short queue of todo list items
and maybe stats/times for retries.

### voter

Gathers information from the database and calculates a vote.

(Idempotent; operates db->db; runs when we don't yet have a vote for
the current voting period.)

### shared random

Offers entrypoints to the voter to drive the shared random protocol.
Not a task.

**Data**:
We record our own shared random state
(commitments etc.)

### stability scanner

Scans each known relay by making a 2-hop connection back to itself.
(Maintains the dirauth's ORport which is used only for this purpose.)

**Data**:
See `dirauth-sketch.md`.

### Parser for bandwidth file

We read a configured bandwidth file.

### Parser for shared operational data

There is a `dir-config.git` which contains data about bad relays,
flags, network parameters, etc.
It also contains machinery for resolving all that into a torrc.

Arti dirauth will be able to read files containing those torrc directives.
(There are about 8 such directives, AIUI.)

They are plain text input files, not stored in the database.
Arti will reread these files every time Arti makes a vote.

The arti dirauth configuration can be used to
specify one or more files, or perhaps glob patterns.

torrc directives not understood by arti will be considered an error,
not ignored.
The `dir-config.git` machinery may need to be adjusted/enhanced
slightly for dirauth operators' convenience.

### Errors reading input files

If the bandwidth or operational data is not processable for whatever reason,
or reading the files fails,
and the old data will be used (for a bit, at least).

### Key management

Authcerts typically have long expiries and are handled manually.
So there is no task in arti dirauth for generating authcerts.

There will be an `arti-dirauth` subcommand for generating 
a KS_auth_sign, and an authcert using the keystore's KS_auth_id,
and writing those to another keystore.
Multiple such authcerts can exist in parallel, with overlapping
validity periods.

Offline key management is required for arti-dirauth
and the implementation/design work will be shared with HSS
and maybe relays.
(This will involve providing a way to to store non-SSH-format certs
in Arti keystores.)

### dirport

We run in the general case, two dirports -
a public one, and one for other dirauths.
(See below.)

These are thin HTTP endpoints which access our database.
(Documents we receive via the dirport are checked at reception time.)

## Exposure, defence in depth

A directory authority communicates in real-time
with other entities as follows:

 1. **relays**:
    Receiving routerdescs uploaded by routers.
 2. **public**:
    Providing rds, mds, and consensuses to relays' dirmirrors.
    Providing votes etc. to monitoring and audit systems (eg, metrics).
 3. **dirauths**:
    Exchanging information with other dirauths
    (votes, mds, rds, consensuses, and consensus signatures).
 5. **stability**:
    A dirauth has a stability scanner which acts like a client on the
    Tor network, and therefore talks to relays.
 6. **bandwith**:
    A dirauth has a bandwidth scanner, which again acts like a client.
    But, this is not done in an arti process.  See below.

Insofar as possible these functions will use separate endpoints.

### Specific mitigations

#### ORport

Arti dirauth will not advertise its ORport or upload a routerdesc.
dirauths do not function as routers.

The stability scanner needs to make connections back to the dirauth,
and it wouldn't be hard for relays to spot this so the dirauth's
ORport won't be secret.

But the ORport could be tunnelled or proxied,
so would not necessarily need to be the dirauth's real IP address.

#### Separate dirauth-to-dirauth communications

Arti dirauth will have the capability to use different addresses for
its peer dirauths, to the `dirport` appearing in public network docs.

The mechanism for distributing these addresses is TBD,
but it will be the configuration, or the `dir-config.git`
operational data.

Until C Tor dirauths are retired,
Arti dirauth will need to accept voting protocol communications
on its public `dirport`.
After that, we intend to change the code to only accept
the expected transactions via each endpoint.

At some point we will probably want to set up a
(conventional) VPN between the dirauths.

#### dirport proxy (future)

It will often be desirable to run a separate dirmirror,
to serve public requests.

Currently there is only one dirport advertised,
and anyway, the upload port is a vulnerable attack surface
and can't be hidden.

So in the initial veersion of arti dirauth,
the dirauth's real dirport will be exposed
(as with C Tor).

As a future improvement, we could add a
"pass through rd and extra-info uploads"
function to dirmirror, with suitable DoS mitigations, rate limits, etc.
Then we could put a dirmirror in front of each dirauth,
so the dirauth's real dirport wouldn't need to be on the open internet.

#### bandwidth scanner

In the current overall system design,
the bandwidth scanner is an entirely separate program,
which reads the public consensus and outputs a bandwidth file.

This will continue to be the case.

We do not plan for the initial version of Arti dirauth
to have any built-in way for getting a bandwidth file from another host,
or some such.
It will just read the file.
