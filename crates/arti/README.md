# arti

A minimal client for connecting to the tor network

This crate is the primary command-line interface for
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Many other crates in Arti depend on it.

Note that Arti is a work in progress; although we've tried to
write all the critical security components, you probably shouldn't
use Arti in production until it's a bit more mature.

More documentation will follow as this program improves.  For now,
just know that it can run as a simple SOCKS proxy over the Tor network.
It will listen on port 9150 by default, but you can override this in
the configuration.

## Command-line interface

(This is not stable; future versions will break this.)

`arti` uses the [`clap`](https://docs.rs/clap/) crate for command-line
argument parsing; run `arti help` to get it to print its documentation.

The only currently implemented subcommand is `arti proxy`; try
`arti help proxy` for a list of options you can pass to it.

## Configuration

By default, `arti` looks for its configuration files in a
platform-dependent location.  That's `~/.config/arti/arti.toml` on
Unix. (TODO document OSX and Windows.)

The configuration file is TOML.  (We do not guarantee its stability.)
For an example see [`arti_defaults.toml`](./arti_defaults.toml).

## Compile-time features

`tokio` (default): Use the tokio runtime library as our backend.

`async-std`: Use the async-std runtime library as our backend.
This feature has no effect unless building with `--no-default-features`
to disable tokio.

`static`: Try to link a single static binary.

## Limitations

There are many missing features.  Among them: there's no onion
service support yet. There's no anti-censorship support.  You
can't be a relay.  There isn't any kind of proxy besides SOCKS.

See the [README
file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md)
for a more complete list of missing features.

License: MIT OR Apache-2.0
