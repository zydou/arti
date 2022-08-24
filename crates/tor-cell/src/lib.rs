#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! Coding and decoding for the cell types that make up Tor's protocol
//!
//! # Overview
//!
//! Tor's primary network protocol is oriented around a set of
//! messages called "Cells".  They exist at two primary layers of the
//! protocol: the channel-cell layer, and the relay-cell layer.
//!
//! [Channel cells](chancell::ChanCell) are sent between relays, or
//! between a client and a relay, over a TLS connection.  Each of them
//! encodes a single [Channel Message](chancell::msg::ChanMsg).
//! Channel messages can affect the channel itself (such as those used
//! to negotiate and authenticate the channel), but more frequently are
//! used with respect to a given multi-hop circuit.
//!
//! Channel message that refer to a circuit do so with a channel-local
//! identifier called a [Circuit ID](chancell::CircId).  These
//! messages include CREATE2 (used to extend a circuit to a first hop)
//! and DESTROY (used to tear down a circuit).  But the most
//! frequently used channel message is RELAY, which is used to send a
//! message to a given hop along a circuit.
//!
//! Each RELAY cell is encrypted and decrypted (according to protocols
//! not implemented in this crate) until it reaches its target.  When
//! it does, it is decoded into a single [Relay
//! Message](relaycell::msg::RelayMsg).  Some of these relay messages
//! are used to manipulate circuits (e.g., by extending the circuit to
//! a new hop); others are used to manipulate anonymous data-streams
//! (by creating them, ending them, or sending data); and still others
//! are used for protocol-specific purposes (like negotiating with an
//! onion service.)
//!
//! For a list of _most_ of the cell types used in Tor, see
//! [tor-spec.txt](https://spec.torproject.org/tor-spec).  Other cell
//! types are defined in [rend-spec-v3.txt (for onion
//! services)](https://spec.torproject.org/tor-spec) and
//! [padding-spec.txt (for padding
//! negotiation)](https://spec.torproject.org/padding-spec).
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! # Futureproofing note
//!
//! There are two pending proposals to remove the one-to-one
//! correspondence between relay cells and relay messages.
//!
//! [Proposal 319](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/proposals/319-wide-everything.md)
//! would add a "RELAY_FRAGMENT" command that would allow larger relay
//! messages to span multiple RELAY cells.
//!
//! [Proposal 325](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/proposals/325-packed-relay-cells.md),
//! on the other hand, would allow multiple relay messages to be
//! packed into a single RELAY cell.
//!
//! The distinction between RelayCell and RelayMsg is meant in part
//! to future-proof arti against these proposals if they are adopted.

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod chancell;
mod err;
pub mod relaycell;

pub use err::Error;

/// An error type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
