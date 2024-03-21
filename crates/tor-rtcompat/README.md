# tor-rtcompat

Compatibility between different async runtimes for Arti.

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
 * A runtime is a [`CoarseTimeProvider`] if it provides a monotonic clock
   which is fast to query,
   but perhaps has lower-precision or lower-accuracy.
 * A runtime is a [`TcpProvider`] if it can make and receive TCP
   connections
 * A runtime is a [`TlsProvider`] if it can make TLS connections.

For convenience, the [`Runtime`] trait derives from all the traits
above, plus [`futures::task::Spawn`] and [`Send`].

You can get a [`Runtime`] in several ways:

  * If you already have an asynchronous backend (for example, one
    that you built with tokio by running with
    `#[tokio::main]`), you can wrap it as a [`Runtime`] with
    [`PreferredRuntime::current()`].

  * If you want to construct a default runtime that you won't be
    using for anything besides Arti, you can use [`PreferredRuntime::create()`].

Both of the above methods use the "preferred runtime", which is usually Tokio.
However, changing the set of Cargo features available can affect this; see
[`PreferredRuntime`] for more.

  * If you want to use a runtime with an explicitly chosen backend,
    name its type directly as [`async_std::AsyncStdNativeTlsRuntime`],
    [`async_std::AsyncStdRustlsRuntime`], [`tokio::TokioNativeTlsRuntime`],
    or [`tokio::TokioRustlsRuntime`]. To construct one of these runtimes,
    call its `create()` method.  Or if you have already constructed a
    Tokio runtime that you want to use, you can wrap it as a
    [`Runtime`] explicitly with `current()`.

## Advanced usage: implementing runtimes yourself

You might want to implement some of the traits above (especially [`TcpProvider`] and
[`TlsProvider`]) if you're embedding Arti, and want more control over the resources it uses.
For example, you might want to perform actions when TCP connections open and close, replace the
TLS stack with your own, or proxy TCP connections over your own custom transport.

This can be more easily accomplished using the [`CompoundRuntime`] type, which lets you
create a [`Runtime`] from various implementors of the various traits (which don't all need to
be the same).

See [`arti-client/examples/hook-tcp.rs`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-client/examples/hook-tcp.rs)
for a full example of this.

## Cargo features

Features supported by this crate:

* `tokio` -- build with [Tokio](https://tokio.rs/) support
* `async-std` -- build with [async-std](https://async.rs/) support
* `native-tls` --  build with the [native-tls](https://github.com/sfackler/rust-native-tls)
  crate for TLS support
* `static` -- link the native TLS library statically (enables the `vendored` feature of the
  `native-tls` crate).
* `rustls` -- build with the [rustls](https://github.com/rustls/rustls) crate for TLS support.  Note that `rustls` uses the `ring` crate, which uses
   the old (3BSD/SSLEay) OpenSSL license, which may introduce licensing
   compatibility issues.

By default, *this* crate doesn't enable any features. However, you're almost certainly
using this as part of the `arti-client` crate, which will enable `tokio` and `native-tls` in
its default configuration.

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
