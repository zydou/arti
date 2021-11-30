# tor-netdoc

Parse and represent directory objects used in Tor.

## Overview

Tor has several "directory objects" that it uses to convey
information about relays on the network. They are documented in
dir-spec.txt.

This crate has common code to parse and validate these documents.
Currently, it can handle the metaformat, along with certain parts
of the router descriptor type. We will eventually need to handle
more types.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

### Design notes

The crate is derived into three main parts.  In the (private) `parse`
module, we have the generic code that we use to parse different
kinds of network documents.  In the [`types`] module we have
implementations for parsing specific data structures that are used
inside directory documents.  Finally, the [`doc`] module defines
the parsers for the documents themselves.

## Features

`build_docs`: enable code to construct the objects representing different
network documents.

`routerdesc`: enable support for the "router descriptor" document type, which
is needed by bridge clients and relays.

`ns-consensus`: enable support for the "ns consensus" document type, which
some relays cache and serve.

## Caveat haxxor: limitations and infelicities

TODO: This crate requires that all of its inputs be valid UTF-8:
This is fine only if we assume that proposal 285 is implemented in
mainline Tor.

TODO: This crate has several pieces that could probably be split out
into other smaller cases, including handling for version numbers
and exit policies.

TODO: Many parts of this crate that should eventually be public
aren't.

TODO: this crate needs far more tests!

License: MIT OR Apache-2.0
