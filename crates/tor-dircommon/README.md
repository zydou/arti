# tor-dircommon

Common primitives for crates implementing the Tor directory specification.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

In Tor, there is a certain set of technologies related to the
*directory specifcation*.  These technologies need to be accessed by several
crates.  In order to avoid circular dependencies or long supply-chains, this
crate serves the purpose to implement the primitives making up the lowest common
denominator for all such crates.

License: MIT OR Apache-2.0
