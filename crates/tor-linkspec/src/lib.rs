#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! `tor-linkspec`: Descriptions of Tor relays, as used to connect to them.
//!
//! # Overview
//!
//! The `tor-linkspec` crate provides traits and data structures that
//! describe how to connect to Tor relays.
//!
//! When describing the location of a Tor relay on the network, the
//! Tor protocol uses a set of "link specifiers", each of which
//! corresponds to a single aspect of the relay's location or
//! identity—such as its IP address and port, its Ed25519 identity
//! key, its (legacy) RSA identity fingerprint, or so on.  This
//! crate's [`LinkSpec`] type encodes these structures.
//!
//! When a client is building a circuit through the Tor network, it
//! needs to know certain information about the relays in that
//! circuit.  This crate's [`ChanTarget`] and [`CircTarget`] traits
//! represent objects that describe a relay on the network that a
//! client can use as the first hop, or as any hop, in a circuit.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.  Several
//! other crates in Arti depend on it.  You will probably not need
//! this crate yourself unless you are interacting with the Tor
//! protocol at a fairly low level.
//!
//! `tor-linkspec` is a separate crate so that it can be used by other
//! crates that expose link specifiers and by crates that consume
//! them.
//!
//! ## Future work
//!
//! TODO: Possibly we should rename this crate.  "Linkspec" is a
//! pretty esoteric term in the Tor protocols.
//!
//! TODO: Possibly the link specifiers and the `*Target` traits belong in different crates.

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

mod ids;
mod ls;
mod owned;
mod traits;
mod transport;

pub use ids::{set::RelayIdSet, RelayId, RelayIdError, RelayIdRef, RelayIdType, RelayIdTypeIter};
pub use ls::LinkSpec;
pub use owned::{OwnedChanTarget, OwnedCircTarget, RelayIds};
pub use traits::{
    ChanTarget, CircTarget, HasAddrs, HasChanMethods, HasRelayIds, HasRelayIdsLegacy,
};
pub use transport::{ChannelMethod, PtAddrError, PtTargetAddr, TransportId, TransportIdError};

#[cfg(feature = "pt-client")]
pub use transport::{PtTarget, PtTargetSettings, PtTransportName};
