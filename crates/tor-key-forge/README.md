# tor-keys

Crate for the cryptographic keys in the Tor landscape.

## Overview

The `tor-keys` crate manages all high level wrappers around lower-level
cryptographic primitives found in `tor-llcrypto`.

More specifically, wrappers are used in order to bring semantic on top of
lower-level crypto keys which helps avoid mixing keys in the code base.

For example, defining a long term identity relay signing keypair around a lower
level ed25519 keypair makes it so that we can't use that key to be used for
another purpose.

This crate is part of [Arti](https://gitlab.torproject.org/tpo/core/arti/), a
project to implement [Tor](https://www.torproject.org/) in Rust.

License: MIT OR Apache-2.0
