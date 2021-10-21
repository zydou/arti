# arti-client

High-level functionality for accessing the Tor network as a client.

## Overview

The `arti-arti-client` crate aims to provide a safe, easy-to-use API for
applications that want to use Tor network to anonymize their
traffic.  It hides most of the underlying detail, letting other
crates decide how exactly to use the Tor crate.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It is the highest-level library crate in
Arti, and the one that nearly all client-only programs should use.
Most of its functionality is provided by lower-level crates in Arti.

### ⚠️️ Warnings ⚠️
️
**Do not expect ANY privacy from this code yet.**

Arti is a work in progress, and there are currently certain
missing features that _will_ make it far less private than the
standard Tor implementation.  In fact, the absence of these makes
Arti clients vulnerable to certain classes of well known attacks
that the standard Tor implementation defends against.

At present, do not expect Arti to give you _any privacy at all_.  (We'll
remove or soften this warning once we're more confident in our privacy.)

**Do not use this code in production yet.**

All of the APIs for this crate, and for Arti in general, are not
the least bit stable.  If you use this code, please expect your
software to break on a regular basis.

### Design considerations, privacy considerations.

As we build the APIs for this crate, we've been aiming for
simplicity and safety: we want it to be as easy as possible to use
`arti-client`, while trying to make certain kinds of privacy or security
violation hard to write accidentally.

Privacy isn't just a drop-in feature, however.  There are still
plenty of ways to accidentally leak information, even if you're
anonymizing your connections over Tor.  We'll try to document
those in a user's guide at some point as Arti becomes more mature.

## Using `arti-client`

The `arti-client` crate provides an async Rust API.  It is
compatible with the `tokio` and `async_std` asynchronous backends.

TODO: Good examples here once the crate setup API is more simple.

## Feature flags

`tokio` -- (Default) Build with support for the Tokio backend.

`async-std` -- Build with support for the `async_std` backend.

`experimental-api` -- Build with experimental, unstable API support.
Note that these APIs are NOT covered by semantic versioning guarantees:
we might break them or remove them between patch versions.

License: MIT OR Apache-2.0
