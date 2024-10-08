# `arti_rpc_tests`

This package is a set of integration tests
that attempts to test all of the following:

- The `arti_rpc` client wrapper library.
- The `arti-rpc-client-core` RPC client library and its FFI interface.
- `arti`'s RPC capabilities
- Arti functionality, as exposed over RPC.

For now (Oct 2024) it tests very few of these things.

The clever parts of the design here are inspired by stem's tests.
The bad parts of the design here are my own.



