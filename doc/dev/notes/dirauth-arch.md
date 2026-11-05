# arti dirauth architecture

See `dirauth-sketch.md` too.
Information is split across these two design documents,
and may be duplicated.
(We will transfer this information to code comments,
spec, etc. as the implementation proceeds.)

## Fundamental approach

### dirmirror/dirauth split

The whole authority consists of two parts:

 * auth part, which handles routerdescs and generates votes and 
   microdescs.

 * proxy part, which is a lightly enhanced dirmirror.
 
Ultimately we expect the dirmirror proxy to be deployed on a separate host,
so that the actual authorities aren't exposed directly.
The authority part will deal only with parts that are necessary for voting.

These two parts will always run as separate instances.
In the initial version, they'll be combined into the same single
dirauth process, but with separate databases
(so separate copies of data that both need to have).

They will share code as much as possible,
including much of the database schema.
So, dirauth will reuse as much of the dirmirror code as possible.

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
   - we can insert routerdescs via upload
   - expiry is handled differently.
   - routerdesc fetches must be triggered by mentions in votes,
     not just in consensuses.
 * Microdescs.  We retain only our own locally-generated microdescs,
   and do not download microdescs from anywhere.
   We retain multiple microdescs for each router (for different consensus methods).
 * Extra-info.  TBD.
   Not clear if authorities need to check extra-info documents
   before incorporating a routerdesc in the consensus.
   If not, then an authority never needs to have routerdescs at all.
   Otherwise, will probably be a dirauth-specific wrapper around shared dirserver code.
 * Votes for the current voting period (other authorities', and our own).
 * Previous and current consensus,
   So we have three network statuses in play: previous consensus,
   current consensus, and the consensus currently being built and
   voted on ("nascent consensus").

The database will **not** contain:

 * Consensus diffs.
   These are computed and managed by the authority's dirmirror proxy.
 * Microdescs from other authorities.

### dirauth-dirauth data pump(s)

Task(s) that try to make sure that every other authority has our
documents and vice versa.

Documents that need to be transferred include:

 * Our votes (outbound)
 * Their votes (inbound)
 * Routerdescs and maybe extra-infos (both directions)
 * Consensus documents and their signatures (both directions)

**Data**:
We record some information in the db
about who we think has which documents already,
and also futile transfers (apparently invalid documents).

**In-memory status**:
Just a short queue of todo list items
and maybe stats/times for retries.

### dirmirror enhancements

Unlike a dirmirror dirport, a public dirauth dirport also
accepts uploads, of routerdescs and extra-info docs.
We will enhance the dirmirror code to be able to pass through such uploads.
(In the future, the dirmirror could buffer incoming routerdescs
in its own database, and they could be copied to the authority asynchronously,
giving better DoS resistance etc.)

And, a dirauth proxy dirmirror ought to attempt to maintain copies of
recent votes, for transparency etc.

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

In the future we might split the network-facing part into a separate program;
maybe it could run on the same host as the dirmirror proxy,
and report results to its authority.

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

In the future we hope to change the format read by Arti dirauth,
replacing the torrc-format file(s) with something better, probably TOML.

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

The public dirport is actually owned by the proxy.

These are thin HTTP endpoints which access our database.
(Documents we receive via the dirport are checked at reception time.)

## Exposure, defence in depth

A directory authority communicates in real-time
with other entities as follows:

 1. **relays**:
    Receiving routerdescs uploaded by routers.
 2. **dirauths**:
    Exchanging information with other dirauths
    (votes, mds, rds, consensuses, and consensus signatures).
 3. **stability**:
    A dirauth has a stability scanner which acts like a client on the
    Tor network, and therefore talks to relays.
 4. **bandwith**:
    A dirauth has a bandwidth scanner, which again acts like a client.
    But, this is not done in an arti process.  See below.

Insofar as possible these functions will use separate endpoints.

The dirauth's dirmirror has this public-facing entrypoint:

 1. **public**:
    Providing rds, mds, and consensuses to relays' dirmirrors.
    Providing votes etc. to monitoring and audit systems (eg, metrics).
    This part 

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

Arti dirauth will use different addresses for
its peer dirauths, to the `dirport` appearing in public network docs.

The mechanism for distributing these addresses is TBD,
but it will be the configuration, or the `dir-config.git`
operational data.

It will also be possible to exchange votes with the dirauth
via its dirmirror proxy.

Until C Tor dirauths are retired,
Arti dirauth will need to accept voting protocol communications
on its public `dirport`.
After that, we intend to change the code to only accept
the expected transactions via each endpoint.

At some point we will probably want to set up a
(conventional) VPN between the dirauths.

#### bandwidth scanner

In the current overall system design,
the bandwidth scanner is an entirely separate program,
which reads the public consensus and outputs a bandwidth file.

This will continue to be the case.

We do not plan for the initial version of Arti dirauth
to have any built-in way for getting a bandwidth file from another host,
or some such.
It will just read the file.
