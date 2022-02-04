# tor-error

`tor-error`: Support for error handling in Tor and Ari

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

Primarily, this crate provides the [`tor_error::ErrorKind`] enum,
which can be used by an application embedding the Arti/Tor code to
categorise errors so as to respond to them.

You probably don't want to use this separately from the `tor-*` and `arti-*` crates.

## Compile-time features

 * `backtrace`: Enables the capturing stack backtraces in internal errors,
   (via a dependency on the `backtrace` crate).  Enabled by default.

License: MIT OR Apache-2.0
