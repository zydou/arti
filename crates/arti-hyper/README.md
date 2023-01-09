# arti-hyper

High-level layer for making http(s) requests the Tor network as a client.

This can be used by applications which embed Arti,
and could also be used as an example of how to build on top of [`arti_client`].

There is an example program [`hyper.rs`] which uses `arti-hyper`
to connect to Tor and make a single HTTP\[S] request.

[`hyper.rs`]: <https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-hyper/examples/hyper.rs>

## Warning 

On `apple-darwin` targets only the `tls-api-openssl` tls implementation is working.
If you get a issue related to tls failure, please refer to issue [#715](https://gitlab.torproject.org/tpo/core/arti/-/issues/715).

License: MIT OR Apache-2.0
