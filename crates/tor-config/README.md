# tor-config

Tools for configuration management in Arti

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
    and returns a [`ConfigurationTree`].
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

## Facilities and approaches for particular situations

### Lists

When the configuration contains a list of items
which the user is likely to want to add entries to piecemeal,
modify, filter, and so on,
use the list builder helper facilities
in the [list_builder] module.

### Configuration items which are conditionally compiled

If the user requests, via the configuration,
a feature which is compiled out (due to the non-selection of cargo features),
it is usually right to have the code simply ignore it.

This can be achieved by applying the appropriate `#[cfg]`
to configuration fields and structs.
The result is that if the user *does* specify the relevant options,
Arti will generate an "unknown configuration item" warning.
(In the future it might be nice to
provide a message saying what feature was missing.)

#### Config items which must be detected and rejected even when compiled out

For example, if Arti is compiled without bridge support,
a configuration specifying use of bridges should result in failure,
rather than a direct connection.

In those cases, you should 
*unconditionally include* the configuration fields
which must be detected and rejected.

Then provide alternative "when-compiled-out" versions of the types for those fields.
(If the field is a list which, when enabled, uses [`list_builder`],
provide alternative "when-compiled-out" versions of the *entry* types.)

The *built* form of the configuration (`Field` or `Entry` in the case of a list),
should be a `#[non_exhaustive]` empty enum.
It should implement all the same standard traits as the compiled-in version.
So everything will compile.
But, since it is an uninhabited type, no such value can ever actually appear.

The *builder* form (`FieldBuilder` or `EntryBuilder`)
should be an empty `#[non_exhaustive]` struct.
It should have a trivial `Deserialize` impl which always returns successfully,
and a derived `Serialize` impl (and the usual traits).
This will allow configurations which attempt to specify such a value
to be recognised.

To get this to compile, naturally,
the builder will have to have a `.build()` method.
This should return [`ConfigBuildError::Invalid`].
(it can't return the uninhabited built type, obviously.)
The configuration resolution arrangements are set up to call this,
and will report the error.

For an example, see `crates/tor-guardmgr/src/bridge_disabled.rs`.

---
License: MIT OR Apache-2.0
