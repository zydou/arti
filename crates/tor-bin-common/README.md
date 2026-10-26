# tor-bin-common

Shared facilities for use in Arti binaries

## Overview

This crate provides functionality that is shared
(or potentially shareable)
by higher-level arti executable code.

Specifically, it is meant for code that makes sense
for `arti` (the client binary) or `arti-relay`,
but which doesn't necessarily belong in Rust code
that is only using e.g. `arti-client` as a library.

License: MIT OR Apache-2.0
