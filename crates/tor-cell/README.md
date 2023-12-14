# tor-cell

Coding and decoding for the cell types that make up Tor's protocol

## Overview

Tor's primary network protocol is oriented around a set of
messages called "Cells".  They exist at two primary layers of the
protocol: the channel-cell layer, and the relay-cell layer.

[Channel cells](chancell::ChanCell) are sent between relays, or
between a client and a relay, over a TLS connection.  Each of them
encodes a single [Channel Message](chancell::ChanMsg).
Channel messages can affect the channel itself (such as those used
to negotiate and authenticate the channel), but more frequently are
used with respect to a given multi-hop circuit.

Channel message that refer to a circuit do so with a channel-local
identifier called a [Circuit ID](chancell::CircId).  These
messages include CREATE2 (used to extend a circuit to a first hop)
and DESTROY (used to tear down a circuit).  But the most
frequently used channel message is RELAY, which is used to send a
message to a given hop along a circuit.

Each RELAY cell is encrypted and decrypted (according to protocols
not implemented in this crate) until it reaches its target.  When
it does, it is decoded into a single [Relay
Message](relaycell::RelayMsg).  Some of these relay messages
are used to manipulate circuits (e.g., by extending the circuit to
a new hop); others are used to manipulate anonymous data-streams
(by creating them, ending them, or sending data); and still others
are used for protocol-specific purposes (like negotiating with an
onion service.)

For a list of _most_ of the cell types used in Tor, see
[tor-spec.txt](https://spec.torproject.org/tor-spec).  Other cell
types are defined in [rend-spec-v3.txt (for onion
services)](https://spec.torproject.org/tor-spec) and
[padding-spec.txt (for padding
negotiation)](https://spec.torproject.org/padding-spec).

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

License: MIT OR Apache-2.0
