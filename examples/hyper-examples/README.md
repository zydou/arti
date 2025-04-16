# Examples using hyper with Arti

This directory contains examples demonstrates how to use `hyper` in combination with Arti.

## Overview

| Example | Run | Description |
| --- | --- | --- |
| [hyper-custom-connector-example](src/bin/hyper-custom-connector-example.rs) | `cargo run --bin hyper-custom-connector-example` | Create custom `ArtiHttpConnector` to use with hyper. |
| [hyper-http-client-example](src/bin/hyper-http-client-example.rs) | `cargo run --bin hyper-http-client-example` | Make single HTTP/1.1 request using Arti. |
| [hyper-http-hs-example](src/bin/hyper-http-hs-example.rs) | `cargo run --bin hyper-http-hs-example` | Implements a simple HTTP/1.1 hidden service using Arti and hyper. |


## Example details

### hyper-custom-connector-example

**Create a custom `ArtiHttpConnector` to use inject in hyper to make Tor requests using a hyper client.**

It makes a `GET` request to `https://check.torproject.org/api/ip`. If the response contains `"IsTor:true"`, you successfully used the Tor network to make the request.


### hyper-http-client-example

**Make a single request over Tor using hyper.**

It makes a `GET` request to `https://check.torproject.org/api/ip`. If the response contains `"IsTor:true"`, you successfully used the Tor network to make the request.

### hyper-http-hs-example

**Create a hidden service using hyper.**

This example makes an instance of a hidden service using hyper in combination with Arti.

## Relevant documentation

Read the hyper documentation to learn more about how to use hyper to understand these examples better.

- [Docs.rs hyper](https://docs.rs/hyper/latest/hyper/)

