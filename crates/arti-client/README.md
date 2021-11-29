# arti-client

High-level functionality for accessing the Tor network as a client.

## Overview

The `arti-client` crate aims to provide a safe, easy-to-use API for
applications that want to use Tor network to anonymize their
traffic.  It hides most of the underlying detail, letting other
crates decide how exactly to use the Tor crate.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It is the highest-level library crate in
Arti, and the one that nearly all client-only programs should use.
Most of its functionality is provided by lower-level crates in Arti.

### ⚠ Warnings ⚠

Note that Arti is a work in progress; although we've tried to
write all the critical security components, you probably shouldn't
use Arti in production until it's a bit more mature.

Also note that all of the APIs for this crate, and for Arti in
general, are not the least bit stable.  If you use this code,
please expect your software to break on a regular basis.

## Using `arti-client`

The main entry point for this crate is the [`TorClient`], an object that lets you make
connections over the Tor network.

Calling [`TorClient::bootstrap`] establishes a connection to the Tor network, pulling in
necessary state about network consensus as required. This state gets persisted to the
locations specified in the [`TorClientConfig`].

A client can then be used to make connections over Tor with [`TorClient::connect`], which
accepts anything implementing [`IntoTorAddr`]. This returns a [`DataStream`], an anonymised
TCP stream type that implements [`AsyncRead`](futures::io::AsyncRead) and
[`AsyncWrite`](futures::io::AsyncWrite), as well as the Tokio versions of those traits if
the `tokio` crate feature is enabled.

The [`TorAddr`] type is intended to ensure that DNS lookups are done via the Tor network
instead of locally. Doing local DNS resolution can leak information about which hostnames you're
connecting to to your local DNS resolver (i.e. your ISP), so it's much better to let Arti
do it for you to maintain privacy.

If you really want to connect to a raw IP address and know what you're doing, take a look at
[`TorAddr::dangerously_from`] -- but be careful!

### Example: making connections over Tor

```rust
use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tokio_crate as tokio;

use futures::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    tracing_subscriber::fmt::init();

    // The client config includes things like where to store persistent Tor network state.
    // The "sane defaults" provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::sane_defaults()?;
    // Arti needs an async runtime handle to spawn async tasks.
    // (See "Multiple runtime support" below.)
    let rt = tor_rtcompat::tokio::current_runtime()?;

    eprintln!("connecting to Tor...");

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::bootstrap(rt, config).await?;

    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    let mut stream = tor_client.connect(("example.com", 80), None).await?;

    eprintln!("sending request...");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    // IMPORTANT: Make sure the request was written.
    // Arti buffers data, so flushing the buffer is usually required.
    stream.flush().await?;

    eprintln!("reading response...");
    
    // Read and print the result.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
```

### More advanced usage

This version of Arti includes basic support for "stream isolation": the ability to ensure that
different TCP connections ('streams') go over different Tor circuits (and thus different exit
nodes, making them originate from different IP addresses).

This is useful to avoid deanonymising
users by correlation: for example, you might want a Tor connection to your bank and a Tor
connection to an online forum to use different circuits, to avoid the possibility of the two
identities being linked by having the same source IP.

Streams can be isolated in two ways:

- by calling [`TorClient::isolated_client`], which returns a new [`TorClient`] whose streams
  will use a different circuit
- by generating [`IsolationToken`]s, and passing them in via [`ConnectPrefs`] to
  [`TorClient::connect`].

## Multiple runtime support

Arti uses the [`tor_rtcompat`] crate to support multiple asynchronous runtimes; currently,
both [Tokio](https://tokio.rs) and [async-std](https://async.rs) are supported.

Functions in this crate, like [`TorClient::bootstrap`],
will expect a type that implements [`tor_rtcompat::Runtime`], which can be obtained:

- for Tokio:
  - by calling [`tor_rtcompat::tokio::current_runtime`], if a Tokio reactor is already running
  - by calling [`tor_rtcompat::tokio::create_runtime`], to start a new reactor if one is not
    already running
  - by manually creating a [`TokioRuntimeHandle`](tor_rtcompat::tokio::TokioRuntimeHandle) from
    an existing Tokio runtime handle
- for async-std:
  - by calling [`tor_rtcompat::async_std::current_runtime`], which will create a runtime or
    retrieve the existing one, if one has already been started


## Feature flags

`tokio` -- (Default) Build with support for the Tokio backend.

`async-std` -- Build with support for the `async_std` backend.

`static` -- Link with static versions of your system dependencies,
including sqlite and/or openssl.

`experimental-api` -- Build with experimental, unstable API support.
Note that these APIs are NOT covered by semantic versioning guarantees:
we might break them or remove them between patch versions.

License: MIT OR Apache-2.0
