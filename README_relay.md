# Relay and directory authority support in Arti

## ⚠️ WARNING ⚠️

Don't run the `arti-relay` code now.

As of August 2026, relay support is a work in progress.
Internally, we've tested out some of the features we've built,
but it's not at all ready for general deployment.

Relay support is currently experimental!
Please do not try to run an Arti relay on the public Tor network.

Below is a rough guide to which pieces of relay support are done
and which remain to be built.
This is an informative guide;
it is _not_ a substitute for our actual
[issue tracker](https://gitlab.torproject.org/tpo/core/arti/-/issues/).

As of 11 August 2026, this list below has not yet been edited by the team
to check things off, or add missing items.

## Relay

- [ ] **Basic operations**
  - [x] Refactor `tor-proto`
  - [x] Update TLSProvider with server support
  - [ ] Handle incoming channels
  - [ ] Bidirectional channel authentication
  - [ ] Manage list of client channels
  - [ ] Limit channels per IP
  - [ ] Discard unused channels
  - [x] Process and deliver relay cells
  - [x] Handle CREATE2 cells
  - [x] Handle CREATE_FAST cells
  - [x] Handle EXTEND2 messages
  - [ ] Create router keys
  - [ ] Rotate keys as needed
  - [ ] Publish router descriptors
  - [ ] Congestion control
  - [x] Listen on ORPort
  - [ ] Cap overall bandwidth usage

- [ ] **Exit support**
  - [ ] Basic DNS support
  - [ ] DNS cacheing
  - [ ] Handle BEGIN requests
  - [ ] Handle RESOLVE requests
  - [ ] Exit policies

- [ ] **Directory cache**
  - [ ] Fetch from authorities
    - [ ] Consensus documents
    - [ ] Authority certificates
    - [ ] Microdescriptors
    - [ ] Router descriptors
    - [ ] Extra-info documents
  - [ ] Serve documents based on client requests
    - [ ] Plain documents
    - [ ] Compression support
    - [ ] Serve consensus diffs
    - [ ] Pre-generate compressed docs+diffs if needed
  - [ ] Clean expired documents from cache
  - [ ] Minimize memory usage during concurrent requests

- [ ] **Self-testing**
  - [ ] Self-test ORPort reachability
  - [ ] Self-test bandwidth
  - [ ] Self-test DNS

- [ ] **Onion service support**
  - [ ] HsDir support
  - [ ] Introduction protocol
  - [ ] Rendezvous protocol

- [ ] **Security features**
  - [ ] Offline identity-key management
  - [ ] Maybenot-based padding support
  - [ ] Defenses for memory-based DOS
  - [ ] Defenses for socket-based DOS

- [ ] **Performance features**
  - [ ] Buffer size tuning
  - [ ] Circuit scheduling
  - [ ] KIST or similar
  - [ ] Offload CPU-intensive operations to worker threads
  - [ ] Conflux


## Directory authority

- [ ] **Preliminaries**
  - [ ] Parsers and generators for directory documents

- [ ] **Network data collection**
  - [ ] Receive router descriptors and extrainfo docs.
  - [ ] Track relay up/down status
  - [ ] Track relay WMTBF
  - [ ] Track relay WFU
  - [ ] Accept relay bandwidth data

- [ ] **Vote generation**
  - [ ] SRV voting process
  - [ ] Generate votes from network data

- [ ] **Consensus generation**
  - [ ] Upload vote to other authorities
  - [ ] Serve vote via directory system.
  - [ ] Fetch missing votes
  - [ ] Vote parsing
  - [ ] Generate ns consensus
  - [ ] Generate md consensus
  - [ ] Generate microdescriptors

- [ ] **Consensus signing**
  - [ ] Detached signature document generation
  - [ ] Signature fetching, publishing, collection

- [ ] **Orchestration**
  - [ ] Schedule voting operations
  - [ ] Take operations at appropriate times.

- [ ] **Integration**
  - [ ] C Tor plugin
  - [ ] Integrate with directory cache server code


