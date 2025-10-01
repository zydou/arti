# Examples using hyper with Arti

This directory contains examples demonstrates how to use `hyper` in combination with Arti.

## Overview

| Example | Run | Description |
| --- | --- | --- |
| [hyper-http-client-example](src/bin/hyper-http-client-example.rs) | `cargo run --bin hyper-http-client-example` | Make single HTTP/1.1 request using Arti. |
| [hyper-http-hs-example](src/bin/hyper-http-hs-example.rs) | `cargo run --bin hyper-http-hs-example` | Implements a simple HTTP/1.1 hidden service using Arti and hyper. |


## Example details

### hyper-http-client-example

**Make a single request over Tor using hyper.**

It makes a `GET` request to `https://check.torproject.org/api/ip`. If the response contains `"IsTor:true"`, you successfully used the Tor network to make the request.

### hyper-http-hs-example

**Create a hidden service using hyper.**

This example makes an instance of a hidden service using hyper in combination with Arti.

## Relevant documentation

Read the hyper documentation to learn more about how to use hyper to understand these examples better.

- [Docs.rs hyper](https://docs.rs/hyper/latest/hyper/)

> [!WARNING]
> **Notice for MacOS users:** This example uses `native-tls` which on MacOS might fail to perform a TLS handshake due to a known bug.
> This will be fixed once `security-framework` 3.5.1 is used by `native-tls`. View issue [#2117](https://gitlab.torproject.org/tpo/core/arti/-/issues/2117) for more details.
