# tor-dirmgr

Code to fetch, store, and update Tor directory information.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

In its current design, Tor requires a set of up-to-date
authenticated directory documents in order to build multi-hop
anonymized circuits through the network.

This directory manager crate is responsible for figuring out which
directory information we lack, downloading what we're missing, and
keeping a cache of it on disk.

## Compile-time features

* `mmap` (default) -- Use memory mapping to reduce the memory load for
  reading large directory objects from disk.

* `routerdesc` -- (Incomplete) support for downloading and storing
  router descriptors.

* `compression` (default) -- Build support for downloading compressed
  documents. Requires a C compiler.

* `bridge-client`: Provide APIs used to fetch
  and use bridge information.

* `full` -- Enable all features above.

### Non-additive features

* `static` -- Try to link with a static copy of sqlite3.

### Experimental and unstable features

Note that the APIs enabled by these features are NOT covered by
semantic versioning[^1] guarantees: we might break them or remove
them between patch versions.

* `experimental-api`: Add additional non-stable APIs to our public
  interfaces.

* `dirfilter`: enable an experimental mechanism to modify incoming
  directory information before it is used.

* `experimental`: Enable all the above experimental features.

[^1]: Remember, semantic versioning is what makes various `cargo`
features work reliably. To be explicit: if you want `cargo update`
to _only_ make safe changes, then you cannot enable these
features.

License: MIT OR Apache-2.0
