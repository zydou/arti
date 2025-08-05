# tor-bytes

Utilities to decode/encode things into bytes.

## Overview

The `tor-bytes` crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Other crates in Arti use it to build and handle all the byte-encoded
objects from the Tor protocol.  For textual directory items, see
the [`tor-netdoc`] crate.

This crate is generally useful for encoding and decoding
byte-oriented formats that are not regular enough to qualify for
serde, and not complex enough to need a full meta-language.  It is
probably not suitable for handling anything bigger than a few
kilobytes in size.

### Alternatives

The Reader/Writer traits in std::io are more appropriate for
operations that can fail because of some IO problem.  This crate
can't handle that: it is for handling things that are already in
memory.

TODO: Look into using the "bytes" crate more here.

TODO: The "untrusted" crate has similar goals to our [`Reader`],
but takes more steps to make sure it can never panic. Perhaps we
should see if we can learn any tricks from it.

TODO: Do we really want to keep `Reader` as a struct and
`Writer` as a trait?

## Contents and concepts

This crate is structured around four key types:

* [`Reader`]: A view of a byte slice, from which data can be decoded.
* [`Writer`]: Trait to represent a growable buffer of bytes.
  (`Vec<u8>` and [`bytes::BytesMut`] implement this.)
* [`Writeable`]: Trait for an object that can be encoded onto a [`Writer`]
* [`Readable`]: Trait for an object that can be decoded from a [`Reader`].

Every object you want to encode or decode should implement
[`Writeable`] or [`Readable`] respectively.

Once you implement these traits, you can use Reader and Writer to
handle your type, and other types that are built around it.

License: MIT OR Apache-2.0

[`tor-netdoc`]: https://docs.rs/tor-netdoc/
