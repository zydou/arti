# tor-netdoc

Parse and represent directory objects used in Tor.

## Overview

Tor has several "network documents" that it uses to convey
information about relays on the network. They are documented in
the [Tor Directory Protocol Spec](https://spec.torproject.org/dir-spec/index.html).

This crate has common code to parse, validate and encode
the network document metaformat.
It also has specific implementations for various document types.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

### Structure

The parts of the crate that new code should usually interface with are:

 * `encode`: Support for encoding the metaformat.
 * `parse2`: Support for parsing the metaformat.
 * `types`: Type definitions for elements common across various documents.
 * `doc`: Implementations for specific concrete document types.

Additionally, there is an older internal `parse` module
based on different parsing principles.

### Traits and derives

Each of `encode` and `parse2` define:

 * traits for encoding and parsing;
 * derive macros allowing automatically generated encoders and parsers
   for document data structures which closely match the netdoc spec;
 * helper types and traits.

Network document elements categories, and the corresponding traits, are:

 * Whole network documents (possibly with signatures).
   `NetdocParseable`, `NetdocSigned` (for parsing), `NetdocEncodable`.

 * Data structures containing sets of ordinary fields
   appearing within ("flattened" into) network documents:
   `NetdocParseableFields`, `NetdocEncodableFields`.

 * The value for an individual Item.
   (The same value type may be used for multiple different Items with different keywords,
   depending the specific document format(s).)
   `ItemValueParseable`, `SignatureItemParseable`, `ItemValueEncodable`.

 * An Argument (or several Arguments) found on an Item line.
   `ItemArgumentParseable`, `ItemArgument` (for encoding), `NormalItemArgument`.

 * An Object (encoded as base-64 in PEM format).
   `ItemObjectParseable`, `ItemObjectEncodable`.

### Design notes

The crate is derived into three main parts.  In the (private) `parse`
module, we have the generic code that we use to parse different
kinds of network documents.  In the [`types`] module we have
implementations for parsing specific data structures that are used
inside directory documents.  Finally, the [`doc`] module defines
the parsers for the documents themselves.

## Features

`routerdesc`: enable support for the "router descriptor" document type, which
is needed by bridge clients and relays.

`plain-consensus`: enable support for the "plain (unflavoured) consensus" document type, which
some relays cache and serve.

`hs-client`: enable support for parsing hidden service descriptors.

`hs-service`: enable support for generating hidden service descriptors.

`encode`: enable support for encoding documents, in general.

There are also other features includijng experimental ones
which aren't documented here and shouldn't be relied on.

#### Deprecated features

`build_docs`: enable code to construct the objects representing different
network documents, with builder patterns.

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
