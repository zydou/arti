# arti-hyper

High-level layer for making http(s) requests the Tor network as a client.

## Feature flags

`experimental-api` -- Build with experimental, unstable API support.
Note that these APIs are NOT covered by semantic versioning guarantees:
we might break them or remove them between patch versions.

`error_detail` -- Make the `TorError` type transparent, and expose the `Error` within.
Note that the resulting APIs are not stable.

`native-tls` (default), `rustls` -- Select TLS libraries to support. 

License: MIT OR Apache-2.0
