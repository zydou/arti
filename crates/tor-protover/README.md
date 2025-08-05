# tor-protover

Implementation of Tor's "subprotocol versioning" feature.

## Overview

The Tor system is built out of numerous "subprotocols" that are
versioned more or less independently. The `tor-protover` crate
implements parsing and handling for these subprotocol versions, so
that different Tor instances know which parts of the protocol
they support.

Subprotocol versions are also used to determine which versions of
the protocol are required to connect to the network (or just
recommended).

For more details, see [tor-spec.txt](https://spec.torproject.org/tor-spec)
section 9.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It's unlikely to be of general interest
unless you are writing a Tor implementation, or a program that
needs to examine fine-grained details of the Tor network.

### Design notes

We're giving `tor-protover` its own crate within arti because it
needs to be used to multiple higher level crates that do not
themselves depend on one another.  (For example, [`tor-proto`]
needs to know which variant of a subprotocol can be used with a
given relay, whereas [`tor-netdoc`] needs to parse lists of
subprotocol versions from directory documents.  Eventually,
[`arti-client`] will need to check its own list of supported
protocols against the required list in the consensus.)

License: MIT OR Apache-2.0

[`arti-client`]: https://docs.rs/arti-client
[`tor-netdoc`]: https://docs.rs/tor-netdoc/
[`tor-proto`]: https://docs.rs/tor-proto/

