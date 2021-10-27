# tor-circmgr

`tor-circmgr`: circuits through the Tor network on demand.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

In Tor, a circuit is an encrypted multi-hop tunnel over multiple
relays.  This crate's purpose, long-term, is to manage a set of
circuits for a client.  It should construct circuits in response
to a client's needs, and preemptively construct circuits so as to
anticipate those needs.  If a client request can be satisfied with
an existing circuit, it should return that circuit instead of
constructing a new one.

## Limitations

But for now, this `tor-circmgr` code is extremely preliminary; its
data structures are all pretty bad, and it's likely that the API
is wrong too.

License: MIT OR Apache-2.0
