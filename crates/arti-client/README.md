# arti-client

High-level functionality for accessing the Tor network as a client.

## Overview

The `arti-client` crate aims to provide a safe, easy-to-use API for
applications that want to use the Tor network to anonymize their traffic.

This crate is part of [Arti](https://gitlab.torproject.org/tpo/core/arti/),
a project to implement [Tor](https://www.torproject.org/) in Rust. It is the
highest-level library crate in Arti, and the one that nearly all client-only
programs should use. Most of its functionality is provided by lower-level
crates in Arti.

### Shape of the API, and relationship to other crates

The API here is great if you are building an application in async Rust
and want your Tor connections as async streams (`AsyncRead`/`AsyncWrite`).

If you are trying to glue Arti to some other programming language,
right now your best bet is probably to spawn the
[`arti` CLI](https://tpo.pages.torproject.net/core/doc/rust/arti/index.html)
SOCKS proxy,
as a subprocess.
We don't yet offer an API that would be nice to expose via FFI;
we intend to add this in the future.

### ⚠ Warnings ⚠

Also note that the APIs for this crate are not all yet completely stable.
We'll try not to break things without good reason, and we'll follow semantic
versioning when we do, but please expect a certain amount of breakage
between now and us declaring `arti-client` 1.x.

The APIs exposed by lower-level crates in Arti are _even more unstable_;
they will break more often than those from `arti-client`, for less reason.

## Using `arti-client`

The main entry point for this crate is the [`TorClient`], an object that
lets you make connections over the Tor network.

### Connecting to Tor

Calling [`TorClient::create_bootstrapped`] establishes a connection to the
Tor network, pulling in necessary state about network consensus as required.
This state gets persisted to the locations specified in the
[`TorClientConfig`].

(This method requires you to initialize the client in an `async fn`.
Consider using the builder method, below, if that doesn't work for you.)

```rust,ignore
// The client configuration describes how to connect to the Tor network,
// and what directories to use for storing persistent state.
let config = TorClientConfig::default();

// Start the Arti client, and let it bootstrap a connection to the Tor network.
// (This takes a while to gather the necessary directory information.
// It uses cached information when possible.)
let tor_client = TorClient::create_bootstrapped(config).await?;
```

### Creating a client and connecting later

You might wish to create a Tor client immediately, without waiting for it to
bootstrap (or having to use an `await`). This can be done by making a
[`TorClientBuilder`] with [`TorClient::builder`], and calling
[`TorClientBuilder::create_unbootstrapped`].

The returned client can be made to bootstrap when it is first used (the
default), or not; see [`BootstrapBehavior`] for more details.

```rust,ignore
// Specifying `BootstrapBehavior::OnDemand` means the client will automatically
// bootstrap when it is used. `Manual` exists if you'd rather have full control.
let tor_client = TorClient::builder()
    .bootstrap_behavior(BootstrapBehavior::OnDemand)
    .create_unbootstrapped()?;
```

### Using the client

A client can then be used to make connections over Tor with
[`TorClient::connect`], which accepts anything implementing [`IntoTorAddr`].
This returns a [`DataStream`], an anonymized TCP stream type that implements
[`AsyncRead`](futures::io::AsyncRead) and
[`AsyncWrite`](futures::io::AsyncWrite), as well as the Tokio versions of
those traits if the `tokio` crate feature is enabled.

### Example: making connections over Tor

```rust,ignore
#
// Initiate a connection over Tor to example.com, port 80.
let mut stream = tor_client.connect(("example.com", 80)).await?;

use futures::io::{AsyncReadExt, AsyncWriteExt};

// Write out an HTTP request.
stream
    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await?;

// IMPORTANT: Make sure the request was written.
// Arti buffers data, so flushing the buffer is usually required.
stream.flush().await?;

// Read and print the result.
let mut buf = Vec::new();
stream.read_to_end(&mut buf).await?;

println!("{}", String::from_utf8_lossy(&buf));
#
```

### Bridge usage

Bridges and Pluggable Transports (PT) can be used as censorship circumvention tools
to connect to Tor in places where it is otherwise blocked. In arti, they are
configured through [`config::BridgesConfig`]. You will need to enable the feature
`pt-client` for PT support. Note that pluggable transports need to be installed
separately and that Arti does not provide them on its own. You can read more about
PTs in [TB manual](https://tb-manual.torproject.org/circumvention/).

### More advanced usage

This version of Arti includes basic support for "stream isolation": the
ability to ensure that different TCP connections ('streams') go over
different Tor circuits (and thus different exit nodes, making them originate
from different IP addresses).

This is useful to avoid deanonymizing users by correlation: for example, you
might want a Tor connection to your bank and a Tor connection to an online
forum to use different circuits, to avoid the possibility of the two
identities being linked by having the same source IP.

Streams can be isolated in two ways:

- by calling [`TorClient::isolated_client`], which returns a new
  [`TorClient`] whose streams will use a different circuit
- by generating [`IsolationToken`]s, and passing them in via [`StreamPrefs`]
  to [`TorClient::connect`].

## Multiple runtime support

Arti uses the [`tor_rtcompat`] crate to support multiple asynchronous
runtimes; currently, both [Tokio](https://tokio.rs) and
[async-std](https://async.rs) are supported.

The backend Arti uses for TCP connections ([`tor_rtcompat::NetStreamProvider`])
and for creating TLS sessions ([`tor_rtcompat::TlsProvider`]) is also
configurable using this crate. This can be used to embed Arti in custom
environments where you want lots of control over how it uses the network.

[**View the `tor_rtcompat` crate documentation**](tor_rtcompat) for more
about these features.

## Reporting Arti errors

Arti often outputs very long Debug messages that are hard to understand,
even for developers. In order to have a better idea of what went wrong in your
program, `match` every `Error` and have `err.report()` be logged, where `err`
is the caught error.

For example, the previous example can be modified to report one of the errors:

```rust,ignore
// Initiate a connection over Tor to example.com, port 80.
// Note: here we try to handle the potential error using match
match tor_client.connect(("example.com", 80)).await {
    Ok(mut stream) => {
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
    }
    Err(err) => {
        // Use .report() on an error to get a nicer error message
        // Raw Debug output will be much harder to decipher for all parties involved
        eprintln!("{}", err.report());
    }
}
```

## Feature flags

### Additive features

* `tokio` (default) -- build with [Tokio](https://tokio.rs/) support
* `native-tls` (default) -- build with the
  [native-tls](https://github.com/sfackler/rust-native-tls) crate for TLS
  support
* `async-std` -- build with [async-std](https://async.rs/) support
* `compression` (default) -- Build support for downloading compressed
  documents. Requires a C compiler.
* `bridge-client` -- Build with support for bridges.
* `onion-service-client` -- Build with support for connecting to onion 
  services. Note that this is not yet as secure as C-Tor and shouldn't be used
  for security-sensitive purposes.
* `onion-service-service` -- Build with support for running onion services.
  Note that this is not yet as secure as C-Tor and shouldn't
  be used for security-sensitive purposes.
* `pt-client` -- Build with support for pluggable transports.
* `anyhow` -- Build with support for extracting `ErrorHint`s from
  anyhow::Error.

* `full` -- Build with all features above, along with all stable additive
  features from other arti crates.  (This does not include experimental
  features. It also does not include features that select a particular
  implementation to the exclusion of another, or those that set a build
  flag.)

* `rustls` -- build with the [rustls](https://github.com/rustls/rustls)
  crate for TLS support.  This is not included in `full`, since it uses the
  `ring` crate, which uses the old (3BSD/SSLEay) OpenSSL license, which may
  introduce licensing compatibility issues.

Note that flags `tokio`, `native-tls`, `async-std`, `rustls` and `static`
will enable the flags of the same name on the [`tor_rtcompat`] crate.

### Build-flag related features

* `static` -- link with static versions of Arti's system dependencies, like
  SQLite and OpenSSL (⚠ Warning ⚠: this feature will include a dependency on
  native-tls, even if you weren't planning to use native-tls.  If you only
  want to build with a static sqlite library, enable the `static-sqlite`
  feature.  We'll look for better solutions here in the future.)
* `static-sqlite` -- link with a static version of sqlite.
* `static-native-tls` -- link with a static version of `native-tls`. Enables
  `native-tls`.

### Cryptographic acceleration features

Libraries should not enable these by default, since they replace one
implementation with another.

* `accel-sha1-asm` -- Accelerate cryptography by using an assembly
  implementation of SHA1, if one is available.
* `accel-openssl` -- Accelerate cryptography by using openssl as a backend.

### Experimental and unstable features

 Note that the APIs enabled by these features are NOT covered by semantic
 versioning[^1] guarantees: we might break them or remove them between patch
 versions.

* `experimental-api` -- build with experimental, unstable API support.
* `error_detail` -- expose the `arti_client::Error` inner error type.
* `dirfilter` -- expose the `DirFilter` API, which lets you modify a network
  directory before it is used.
* `experimental` -- Build with all experimental features above, along with
  all experimental features from other arti crates.

[^1]: Remember, semantic versioning is what makes various `cargo` features
work reliably. To be explicit: if you want `cargo update` to _only_ make safe
changes, then you cannot enable these features.

License: MIT OR Apache-2.0
