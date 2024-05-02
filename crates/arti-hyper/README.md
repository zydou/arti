# arti-hyper

**THIS CRATE IS OBSOLETE AND UNMAINTAINED**

Using Arti with `hyper` version 1.x is fairly straightforward,
and does not need this shim crate.

See the following examples in the Arti source tree:

 * [hyper-http-client-example](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/hyper/hyper-http-client-example?ref_type=heads)
 * [hyper-http-hs-example](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/hyper/hyper-http-hs-example?ref_type=heads)

You may continue to use this crate, but it
**will not receive security patches**
if any vulnerabilities are found.

## Description

High-level layer for making http(s) requests the Tor network as a client,
**when using `hyper` prior to 1.0.**

This can be used by applications which embed Arti,
and could also be used as an example of how to build on top of [`arti_client`].

There is an example program [`hyper.rs`] which uses `arti-hyper`
to connect to Tor and make a single HTTP\[S] request.

[`hyper.rs`]: <https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-hyper/examples/hyper.rs>

License: MIT OR Apache-2.0
