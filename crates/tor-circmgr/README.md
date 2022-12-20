# tor-circmgr

circuits through the Tor network on demand.

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

## Compile-time features

* `specific-relay`: Support for connecting to a relay via
   specifically provided connection instructions, rather than
   using information from a Tor network directory.

* `full`: Enable all features above.

### Experimental and unstable features

Note that the APIs enabled by these features are NOT covered by
semantic versioning[^1] guarantees: we might break them or remove
them between patch versions.

* `experimental-api`: Add additional non-stable APIs to our public
  interfaces.

* `experimental`: Enable all the above experimental features.

[^1]: Remember, semantic versioning is what makes various `cargo`
features work reliably. To be explicit: if you want `cargo update`
to _only_ make safe changes, then you cannot enable these
features.

License: MIT OR Apache-2.0
