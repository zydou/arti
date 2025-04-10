# Examples for arti-ureq

This directory contains examples demonstrating the usage of the `arti-ureq` crate.

## Overview

| Example | Run | Description |
| --- | --- | --- |
| [arti-ureq-simple-get-request](src/bin/arti-ureq-simple-get-request.rs) | `cargo run --bin arti-ureq-simple-get-request` | Most basic and minimal example to make a `GET` request. |
| [arti-ureq-simple-post-request](src/bin/arti-ureq-simple-post-request.rs) | `cargo run --bin arti-ureq-simple-post-request` | Most basic and minimal example to make a `POST` request. |
| [arti-ureq-tor-client](src/bin/arti-ureq-tor-client.rs) | `cargo run --bin arti-ureq-tor-client` | Use your own instance of `arti_client::TorClient` with `arti-ureq`. |
| [arti-ureq-builder-and-configs](src/bin/arti-ureq-builder-and-configs.rs) | `cargo run --bin arti-ureq-builder-and-configs` | Use custom configurations for `ureq::Agent` and `arti_client::TorClient` together with the `ConnectorBuilder`. |


## Example details

### arti-ureq-simple-get-request

**This example demonstrates how to make a `GET` request over the Tor network using the [`ureq`](https://docs.rs/ureq/latest/ureq) crate.**

It makes a `GET` request to `https://check.torproject.org/api/ip`. If the response contains `"IsTor:true"`, you successfully used the Tor network to make the request.


### arti-ureq-simple-post-request

**This example demonstrates how to make a `POST` request over the Tor network using the [`ureq`](https://docs.rs/ureq/latest/ureq) crate.**

It makes a `POST` request to `https://check.torproject.org/api/ip`. If the response contains `"IsTor:true"`, you successfully used the Tor network to make the request. 


### arti-ureq-tor-client

**You can use your own instance of `arti_client::TorClient` to make requests over the Tor network with `arti-ureq`.**

This example makes a `GET` request over the Tor network with a custom `arti_client::TorClient` instance.

Visit the [docs](https://docs.rs/arti-client/latest/arti_client) of `arti_client` to learn how to expand this example
to e.g use a custom `arti_client::config::TorClientConfig`, or build your own client with `arti_client::TorClientBuilder`.


### arti-ureq-builder-and-configs

**`arti-ureq` provides the flexibility to use custom configuration for the `TorClient` and the `ureq::Agent`.
Using `arti_ureq::ConnectorBuilder` you can build your own instance of `arti_ureq::Connector`.**

This example makes a `GET` request over the Tor network with custom configurations.

Visit the [docs](https://docs.rs/ureq/latest/ureq) for `ureq` and the [docs](https://docs.rs/arti-client/latest/arti_client)
for `arti_client` to learn more about how to configure `ureq::Agent` and `arti_client::TorClient` to leverage this example.


## Relevant documentation

Some understanding of `ureq` and `arti_client` can be helpful to leverage the full potential of `arti-ureq`.
Because `arti-ureq` provides the possibility to use custom configurations it is recommended to study how to 
configure `ureq::Agent` and `arti_client::TorClient`.

- [Docs.rs arti_client](https://docs.rs/arti-client/latest/arti_client)
- [Docs.rs ureq](https://docs.rs/ureq/latest/ureq)

