# arti

A minimal command line program for connecting to the tor network

(If you want a more general Tor client library interface, use
[`arti_client`].)

This crate is the primary command-line interface for
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to implement
[Tor](https://www.torproject.org/) in Rust. Many other crates in Arti depend
on it.

Note that Arti is a work in progress; although we've tried to write all the
critical security components, you probably shouldn't use Arti in production
until it's a bit more mature.

More documentation will follow as this program improves.  For now, just know
that it can run as a simple SOCKS proxy over the Tor network. It will listen
on port 9150 by default, but you can override this in the configuration.

## Command-line interface

(This is not stable; future versions will break this.)

`arti` uses the [`clap`](https://docs.rs/clap/) crate for command-line
argument parsing; run `arti help` to get it to print its documentation.

The only currently implemented subcommand is `arti proxy`; try `arti help
proxy` for a list of options you can pass to it.

## Configuration

By default, `arti` looks for its configuration files in a platform-dependent
location.

| OS      | Configuration File                                 |
|---------|----------------------------------------------------|
| Unix    | `~/.config/arti/arti.toml`                         |
| macOS   | `~/Library/Application Support/arti/arti.toml`     |
| Windows | `\Users\<USERNAME>\AppData\Roaming\arti\arti.toml` |

The configuration file is TOML.  (We do not guarantee its stability.) For an
example see [`arti_defaults.toml`](./arti_defaults.toml).

## Compile-time features

### Additive features

* `tokio` (default): Use the tokio runtime library as our backend.
* `async-std`: Use the async-std runtime library as our backend. This
  feature has no effect unless building with `--no-default-features` to
  disable tokio.
* `native-tls` -- Build with support for the `native_tls` TLS backend.
  (default)
* `journald` -- Build with support for logging to the `journald` logging
  backend (available as part of systemd.)
* `dns-proxy` (default) -- Build with support for proxying certain simple
  DNS queries over the Tor network.
* `harden` (default) -- Build with support for hardening the Arti process by
  disabling debugger attachment and other local memory-inspection vectors.

* `full` -- Build with all features above, along with all stable additive
  features from other arti crates.  (This does not include experimental
  features. It also does not include features that select a particular
  implementation to the exclusion of another, or those that set a build
  flag.)

* `rustls` -- build with the [rustls](https://github.com/rustls/rustls)
  TLS backend.  This is not included in `full`, since it uses the
  `ring` crate, which uses the old (3BSD/SSLEay) OpenSSL license, which may
  introduce licensing compatibility issues.

### Build-flag related features

* `static` -- Link with static versions of your system dependencies,
  including sqlite and/or openssl.  (⚠ Warning ⚠: this feature will include
  a dependency on native-tls, even if you weren't planning to use
  native-tls.  If you only want to build with a static sqlite library,
  enable the `static-sqlite` feature.  We'll look for better solutions here
  in the future.)
* `static-sqlite` -- Link with a static version of sqlite.
* `static-native-tls` -- Link with a static version of `native-tls`. Enables
  `native-tls`.

### Cryptographic acceleration features

Libraries should not enable these by default, since they replace one
implementation with another.

* `accel-sha1-asm` -- Accelerate cryptography by using an assembly
  implementation of SHA1, if one is available.
* `accel-openssl` -- Accelerate cryptography by using openssl as a backend.

### Experimental features

 Note that the APIs enabled by these features are NOT covered by semantic
 versioning[^1] guarantees: we might break them or remove them between patch
 versions.

* `experimental-api` -- build with experimental, unstable API support.
   (Right now, most APIs in the `arti` crate are experimental, since this
   crate was originally written to run as a binary only.)
* `experimental` -- Build with all experimental features above, along with
  all experimental features from other arti crates.

[^1]: Remember, semantic versioning is what makes various `cargo` features
work reliably. To be explicit, if you want `cargo update` to _only_ make
correct changes, then you cannot enable these features.

## Limitations

There are many missing features.  Among them: there's no onion service
support yet. There's no anti-censorship support.  You can't be a relay.
There isn't any kind of proxy besides SOCKS.

See the [README
file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md) for
a more complete list of missing features.

## Library for building command-line client

This library crate contains code useful for making a command line program
similar to `arti`. The API should not be considered stable.

License: MIT OR Apache-2.0
