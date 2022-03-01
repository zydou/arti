# arti-hyper

High-level layer for making http(s) requests the Tor network as a client.

## Feature flags

`experimental-api` -- Build with experimental, unstable API support.
Note that these APIs are NOT covered by semantic versioning guarantees:
we might break them or remove them between patch versions.

`native-tls` (default), `rustls` -- Select TLS libraries to use for Tor's purposes.
(The end-to-end TLS to the origin server is separate, and handled via `tls-api`.)

License: MIT OR Apache-2.0
