# tor-relay-crypto

`tor-relay-crypto`: Cryptography module for a relay.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

Relays need some cryptographic operations to be able to publish their
descriptors and authenticate channels in order to prove their identity.

  * A set of keys that are long-term, mid-term and short-term mostly used for
    channel authentication.

This crate implements operations around those keys, along with a set of
wrapper types to keep us from getting confused about the numerous keys.
Semantic around objects is always better than generic names ;)!

License: MIT OR Apache-2.0

