# tor-relay-selection

Logic to select Tor relays for specific purposes

## Overview

The `tor-relay-selection` crate provides higher-level functions
in order to select Tor relays for specific purposes,
or check whether they are suitable for those purposes.
It wraps lower-level functionality from `tor-netdir`.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

License: MIT OR Apache-2.0
