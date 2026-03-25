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

## Reference

You can learn more about the protocols here as part of the onion services
[Specification](https://spec.torproject.org/rend-spec/index.html).

LICENSE: MIT OR Apache-2.0

When the `hs-pow-full` feature is used, we link with LGPL licensed dependencies.
