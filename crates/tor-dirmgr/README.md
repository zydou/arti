# tor-dirmgr

`tor-dirmgr`: Code to fetch, store, and update Tor directory information.

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

`mmap` (default) -- Use memory mapping to reduce the memory load for
reading large directory objects from disk.

`static` -- Try to link with a static copy of sqlite3.

`routerdesc` -- (Incomplete) support for downloading and storing
     router descriptors.

License: MIT OR Apache-2.0
