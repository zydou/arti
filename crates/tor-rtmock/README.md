# tor-rtmock

Support for mocking with `tor-rtcompat` asynchronous runtimes.

## Overview

The `tor-rtcompat` crate defines a `Runtime` trait that represents
most of the common functionality of .  This crate provides mock
implementations that override a `Runtime`, in whole or in part,
for testing purposes.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It is used to write tests for higher-level
crates in Arti that rely on asynchronous runtimes.

This crate should only be used for writing tests.

Currently, we support mocking the passage of time (via
[`MockSleepRuntime`]), and impersonating the internet (via
[`MockNetRuntime`]).

(TODO: Add an example for the timeout case.)

License: MIT OR Apache-2.0
