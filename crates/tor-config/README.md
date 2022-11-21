# tor-config

`tor-config`: Tools for configuration management in Arti

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

It provides types for handling configuration values,
and general machinery for configuration management.

## Configuration in Arti

The configuration for the `arti` command line program,
and other programs which embed Arti reusing the configuration machinery,
works as follows:

 1. We use [`tor_config::ConfigurationSources`](ConfigurationSources)
    to enumerate the various places
    where configuration information needs to come from,
    and configure how they are to be read.
    `arti` uses [`ConfigurationSources::from_cmdline`].

 2. [`ConfigurationSources::load`] actually *reads* all of these sources,
    parses them (eg, as TOML files),
    and returns a [`config::Config`].
    This is a tree-structured dynamically typed data structure,
    mirroring the input configuration structure, largely unvalidated,
    and containing everything in the input config sources.

 3. We call one of the [`tor_config::resolve`](resolve) family.
    This maps the input configuration data to concrete `ConfigBuilder `s
    for the configuration consumers within the program.
    (For `arti`, that's `TorClientConfigBuilder` and `ArtiBuilder`).
    This mapping is done using the `Deserialize` implementations on the `Builder`s.
    `resolve` then calls the `build()` method on each of these parts of the configuration
    which applies defaults and validates the resulting configuration.

    It is important to call `resolve` *once* for *all* the configuration consumers,
    so that it sees a unified view of which config settings in the input
    were unrecognized, and therefore may need to be reported to the user.
    See the example in the [`load`] module documentation.

 4. The resulting configuration objects (eg, `TorClientConfig`, `ArtiConfig`)
    are provided to the code that must use them (eg, to make a `TorClient`).

See the
[`tor_config::load` module-level documentation](load).
for an example.

License: MIT OR Apache-2.0
