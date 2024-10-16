# tor-hscrypto

`tor-hscrypto`: Basic cryptography used by onion services 

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

Onion services and the clients that connect to them need a few cryptographic
operations not used by the rest of Tor.  These include:

  * A set of key-blinding operations to derive short-term public keys 
    from long-term public keys.
  * An ad-hoc SHA3-based message authentication code.
  * Operations to encode and decode public keys as `.onion` addresses.
  * A set of operations to divide time into different "periods".  These periods
    are used as inputs to the DHT-style hash ring, and to the key-blinding
    operations.
  * Proof of work schemes for resisting denial of service attacks

This crate implements those operations, along with a set of wrapper types to
keep us from getting confused about the numerous keys and nonces used for the
onion services.

## Compile-time features

* `memquota-memcost` -- implement `tor_memquota::HasMemoryCost` for many types.
  (Does not actually force compiling in memory quota tracking;
  that's `memquota` in `tor-memquota` and higher-level crates.)

* `ope` -- support for Order Preserving Encryption

* `pow-v1` -- Tor Hidden Services Proof of Work (`v1` scheme only)

* `pow-full` -- Tor Hidden Services Proof of Work
  (metafeature, enables all non-experimental schemes: currently, implies only `pow-v1`).

* `full` -- Enable all features above.

## License

MIT OR Apache-2.0

When the `pow` feature is used, we link with LGPL licensed dependencies.
