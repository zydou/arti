# arti

A minimal command line program for connecting to the Tor network

(If you want a more general Tor client library interface, use
[`arti_client`].)

This crate is the primary command-line interface for
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to implement
[Tor](https://www.torproject.org/) in Rust.

Currently Arti can run as a simple SOCKS proxy over the Tor network.
It will listen on port 9150 by default,
but you can override this in the configuration.
You can direct programs to connect via that SOCKS port,
and their connections will be anonymized via Tor.
Note: you might not want to run a conventional web browser this way.
Browsers leak much private information.
To browse the web anonymously,
we recommend [using Tor Browser](#using-arti-with-tor-browser).

Arti is still advancing rapidly; we are adding features and eventually
we hope it will be able to replace C Tor.

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
| macOS   | `~/Library/Application Support/org.torproject.arti/arti.toml`     |
| Windows | `\Users\<USERNAME>\AppData\Roaming\arti\arti.toml` |

The configuration file is TOML.
For an example see `arti-example-config.toml`
(a copy of which is in the source tree,
and also
[in the Arti repository](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml)).
That example config file documents the configuration options.

More detailed information about for the individual fields is available in the documentation
for the Rust APIs [`ApplicationConfigBuilder`] and
[`TorClientConfigBuilder`](arti_client::config::TorClientConfigBuilder).

## Using Arti with Tor Browser

It is possible to hook up Arti with
[Tor Browser](https://www.torproject.org/download/).

To do so, we will launch arti independently from Tor Browser. Build arti with
`cargo build --release`.  After that launch it with some basic
configuration parameters:

```text
$ ./target/release/arti proxy -l debug -p 9150
```

This will ensure that arti sets its SOCKS port on 9150. Now we need to launch
Tor Browser and instruct it to use that SOCKS port.

#### Linux

```text
$ TOR_SKIP_LAUNCH=1 TOR_SOCKS_PORT=9150 TOR_SKIP_CONTROLPORTTEST=1 ./start-tor-browser.desktop
```

#### OS X

```text
$ TOR_SKIP_LAUNCH=1 TOR_SOCKS_PORT=9150 TOR_SKIP_CONTROLPORTTEST=1 /path/to/Tor\ Browser/Contents/MacOS/firefox
```

#### Windows

Create a shortcut with the `Target` set to:

```text
C:\Windows\System32\cmd.exe /c "SET TOR_SKIP_LAUNCH=1&& SET TOR_SOCKS_PORT=9150&& SET TOR_SKIP_CONTROLPORTTEST=1&& START /D ^"C:\path\to\Tor Browser\Browser^" firefox.exe"
```

and `Start in` set to:

```text
"C:\path\to\Tor Browser\Browser"
```

(You may need to adjust the actual path to wherever you have put your Tor
Browser.)

The resulting Tor Browser should be using arti.  Note that onion services
and bridges won't work (Arti doesn't support them yet), and neither will
any feature depending on Tor's control-port protocol. Features not depending
on the control-port such as the "New circuit for this site" button should
work.

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
* `compression` (default) -- Build support for downloading compressed
  documents. Requires a C compiler.
* `bridge-client` (default) -- Build with support for bridges.
* `onion-service-client` (default) -- Build with support for connecting to
  onion services. Note that this is not yet as secure as C-Tor and shouldn't
  be used for security-sensitive purposes.
* `onion-service-service` -- Build with support for running onion services.
  Note that this is not yet as secure as C-Tor and shouldn't
  be used for security-sensitive purposes.
* `pt-client` (default) -- Build with support for pluggable transports.

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

See the [repository README
file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md) for
a more complete list of missing features.

## Library for building command-line client

This library crate contains code useful for making a command line program
similar to `arti`. The API should not be considered stable.

License: MIT OR Apache-2.0
