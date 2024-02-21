# tor-relay-selection

Logic to select Tor relays for specific purposes

## Overview

The `tor-relay-selection` crate provides higher-level functions
in order to select Tor relays for specific purposes,
or check whether they are suitable for those purposes.
It wraps lower-level functionality from `tor-netdir`.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

## Design

Our main types are `RelayUsage`,  `RelayExclusion`, `RelayRestriction`, and `RelaySelector`.

A `RelayUsage` answers the question "what is this relay for?"

A `RelayExclusion` excludes one or more relays
as having already been selected,
or as sharing families with already-selected relays.

A `RelayRestriction` imposes additional restrictions on a relay.

A `RelaySelector` is a collection of a usage, an exclusion, and any number of restrictions.

In a `RelaySelector`, usages and restrictions can be strict or non-strict.
If we fail to pick a relay, and there are any non-strict usages/restrictions,
then we remove those usages/restrictions to produce a _relaxed_ selector
and we try again.


License: MIT OR Apache-2.0
