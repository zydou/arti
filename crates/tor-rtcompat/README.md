# tor-rtcompat

Compatibility between different async runtimes for Arti

## Overview

Rust's support for asynchronous programming is powerful, but still
a bit immature: there are multiple powerful runtimes you can use,
but they do not expose a consistent set of interfaces.

The [`futures`] API abstracts much of the differences among these
runtime libraries, but there are still areas where no standard API
yet exists, including:
 - Network programming.
 - Time and delays.
 - Launching new tasks
 - Blocking until a task is finished.

Additionally, the `AsyncRead` and `AsyncWrite` traits provide by
[`futures`] are not the same as those provided by `tokio`, and
require compatibility wrappers to use.

To solve these problems, the `tor-rtcompat` crate provides a set
of traits that represent a runtime's ability to perform these
tasks, along with implementations for these traits for the `tokio`
and `async-std` runtimes.  In the future we hope to add support
for other runtimes as needed.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
As such, it does not currently include (or
plan to include) any functionality beyond what Arti needs to
implement Tor.

We hope that in the future this crate can be replaced (or mostly
replaced) with standardized and general-purpose versions of the
traits it provides.

## Using `tor-rtcompat`

The `tor-rtcompat` crate provides several traits that
encapsulate different runtime capabilities.

 * A runtime is a [`BlockOn`] if it can block on a future.
 * A runtime is a [`SleepProvider`] if it can make timer futures that
   become Ready after a given interval of time.
 * A runtime is a [`TcpProvider`] if it can make and receive TCP
   connections
 * A runtime is a [`TlsProvider`] if it can make TLS connections.

For convenience, the [`Runtime`] trait derives from all the traits
above, plus [`futures::task::Spawn`] and [`Send`].

You can get a [`Runtime`] in several ways:

  * If you already have an asynchronous backend (for example, one
    that you built with tokio by running with
    `#[tokio::main]`), you can wrap it as a [`Runtime`] with
    [`current_user_runtime()`].

  * If you want to construct a default runtime that you won't be
    using for anything besides Arti, you can use [`create_runtime()`].

  * If you want to use a runtime with an explicitly chosen backend,
    name its type directly as [`async_std::AsyncStdNativeTlsRuntime`],
    [`async_std::AsyncStdRustlsRuntime`], [`tokio::TokioNativeTlsRuntime`],
    or [`tokio::TokioRustlsRuntime`]. To construct one of these runtimes,
    call its `create()` method.  Or if you have already constructed a
    tokio runtime that you want to use, you can wrap it as a
    [`Runtime`] explicitly with `current()`.

## Cargo features

`tokio` -- (Default) Build with Tokio support.

`async-std` -- Build with async_std support.

`native-tls`, `rustls` -- Select TLS libraries to support. 

`static` -- Try to link with a static copy of our native TLS library,
if possible.

## Design FAQ

### Why support `async_std`?

Although Tokio currently a more popular and widely supported
asynchronous runtime than `async_std` is, we believe that it's
critical to build Arti against multiple runtimes.

By supporting multiple runtimes, we avoid making tokio-specific
assumptions in our code, which we hope will make it easier to port
to other environments (like WASM) in the future.

### Why a `Runtime` trait, and not a set of functions?

We could simplify this code significantly by removing most of the
traits it exposes, and instead just exposing a single
implementation.  For example, instead of exposing a
[`BlockOn`] trait to represent blocking until a task is
done, we could just provide a single global `block_on` function.

That simplification would come at a cost, however.  First of all,
it would make it harder for us to use Rust's "feature" system
correctly.  Current features are supposed to be _additive only_,
but if had a single global runtime, then support for different
backends would be _mutually exclusive_.  (That is, you couldn't
have both the tokio and async-std features building at the same
time.)

Secondly, much of our testing in the rest of Arti relies on the
ability to replace [`Runtime`]s.  By treating a runtime as an
object, we can override a runtime's view of time, or of the
network, in order to test asynchronous code effectively.
(See the [`tor-rtmock`] crate for examples.)

License: MIT OR Apache-2.0
