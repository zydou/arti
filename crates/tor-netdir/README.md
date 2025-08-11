# tor-netdir

Represents a clients'-eye view of the Tor network.

## Overview

The `tor-netdir` crate wraps objects from tor-netdoc, and combines
them to provide a unified view of the relays on the network.
It is responsible for representing a client's knowledge of the
network's state and who is on it.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.  Its purpose
is to expose an abstract view of a Tor network and the relays in
it, so that higher-level crates don't need to know about the
particular documents that describe the network and its properties.

There are two intended users for this crate.  First, producers
like [`tor-dirmgr`] create [`NetDir`] objects fill them with
information from the Tor network directory.  Later, consumers
like [`tor-circmgr`] use [`NetDir`]s to select relays for random
paths through the Tor network.

## Limitations

Only modern consensus methods and microdescriptor consensuses are
supported.

License: MIT OR Apache-2.0

[`tor-dirmgr`]: https://docs.rs/tor-dirmgr
[`tor-circmgr`]: https://docs.rs/tor-circmgr

