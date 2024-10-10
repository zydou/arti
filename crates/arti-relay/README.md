# arti-relay

A relay implementation that can join the Tor network and act as a relay.

This crate is the reference implementation of a Tor relay for the
[Arti](https://gitlab.torproject.org/tpo/core/arti/) project implementing Tor
in Rust.

# ⚠️ Warning! ⚠️

This is currently in **very active** development and thus highly experimental.
No guarantees that this binary can run or work correctly. In other words, this
is very **unstable** and can change at anytime.

There is even no guarantee at this point that the binary will keep this
`arti-relay` name.

## Compile-time features

* `full` -- Build with all features above, along with all stable additive
  features from other arti crates.  (This does not include experimental
  features. It also does not include features that select a particular
  implementation to the exclusion of another, or those that set a build
  flag.)

* `async-std` -- Use the async-std runtime library as our backend. This
  feature has no effect unless building with `--no-default-features` to
  disable tokio.
* `rustls` (default) -- Build with the [rustls](https://github.com/rustls/rustls)
  TLS backend.  This is not included in `full`, since it uses the `ring`
  crate, which uses the old (3BSD/SSLEay) OpenSSL license, which may
  introduce licensing compatibility issues.
* `tokio` (default): Use the tokio runtime library as our backend.
