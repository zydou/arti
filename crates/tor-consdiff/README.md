# tor-consdiff

Restricted ed diff and patch formats for Tor.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Tor uses a restricted version of the "ed-style" diff format to
record the difference between a pair of consensus documents, so that
clients can download only the changes since the last document they
have.

This crate provides a function to apply one of these diffs to an older
consensus document, to get a newer one.

TODO: Eventually, when we add relay support, we will need to generate
these diffs as well as consume them.

License: MIT OR Apache-2.0
