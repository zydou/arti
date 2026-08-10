# Relay and directory authority support in Arti

As of August 2026, relay support is a work in progress.
Internally, we've tested out some of the features we've built,
but it's not at all ready for general deployment.

Relay support is currently experimental!
Please do not try to run an Arti relay on the public Tor network.

Here is a rough guide to which pieces of relay support are done
and which remain to be built.

## Relay

- [ ] **Basic operations**
  - [x] Refactor `tor-proto`
  - [x] Update TLSProvider with server support
  - [ ] Handle incoming channels
  - [ ] Bidirectional channel authentication
  - [ ] Manage list of client channels
  - [ ] Limit channels per IP
  - [ ] Discard unused channels
  - [ ] Process and deliver relay cells
  - [ ] Handle CREATE2 cells
  - [ ] Handle CREATE_FAST cells
  - [ ] Handle EXTEND2 messages
  - [ ] Create router keys
  - [ ] Rotate keys as needed
  - [ ] Publish router descriptors
  - [ ] Congestion control
  - [ ] Listen on ORPort
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


