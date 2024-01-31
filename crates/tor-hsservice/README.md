# tor-hsservice

Provide an [onion service](https://community.torproject.org/onion-services/)
on the Tor network.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/),
a project to implement [Tor](https://www.torproject.org/) in Rust.

It provides a service-side implementation of the onion service protocol,
which enables Tor clients to provide
a responder-anonymous service on the network.
Other parties can connect to an onion service without learning where it is hosted.

This crate provides a low-level implementation of the onion service protocol
that may not be suitable for typical users.
Most users will instead want to use the `arti` binary
to run an onion service proxy, or use the `TorClient::launch_onion_service` API
in the `arti-client` crate.

## Limitations

This crate is a work in progress.

As of February 2024, there are some features missing that are necessary for
running a secure, private onion service.  Notably these include:

 * Resistance to denial of service attacks
    * Support for proof-of-work checking and validation
    * Detection and response to out-of-memory conditions
 * Vanguard relays for resistance to path discovery
 * Descriptor encryption keys,
   so that only certain clients to connect to the service.

## Reference

You can learn more about the protocols here as part of the onion services
[Specification](https://spec.torproject.org/rend-spec/index.html).

LICENSE: MIT OR Apache-2.0
