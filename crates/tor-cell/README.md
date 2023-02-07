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

## Futureproofing note

There are two pending proposals to remove the one-to-one
correspondence between relay cells and relay messages.

[Proposal 319](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/proposals/319-wide-everything.md)
would add a "RELAY_FRAGMENT" command that would allow larger relay
messages to span multiple RELAY cells.

[Proposal 325](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/proposals/325-packed-relay-cells.md),
on the other hand, would allow multiple relay messages to be
packed into a single RELAY cell.

The distinction between RelayCell and RelayMsg is meant in part
to future-proof arti against these proposals if they are adopted.

License: MIT OR Apache-2.0
