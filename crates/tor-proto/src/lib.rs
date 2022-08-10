//! Implementations for the core Tor protocol
//!
//! # Overview
//!
//! The `tor-proto` crate lies at the core of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Most people shouldn't use this crate directly,
//! since its APIs are needlessly low-level for most purposes, and it is
//! easy to misuse them in an insecure or privacy-violating way.
//!
//! Most people should use the [`arti-client`] crate instead.  This crate is
//! of interest mainly for those that want to access the Tor protocols at
//! a low level.
//!
//! ## Core concepts
//!
//! At its essence, Tor makes connections called "channels" to other
//! Tor instances.  These channels are implemented using TLS.  Each of
//! these channels multiplexes a number of anonymized multihop
//! "circuits" that act as reliable transports for "relay messages"
//! that are sent between clients and the different relays on the
//! circuits.  Finally, each circuit multiplexes a number of "streams",
//! each corresponding roughly to an application-level request.
//!
//! This crate implements the logic, protocols, and cryptography that
//! implement these [`channel::Channel`]s, [`circuit::ClientCirc`]s, and
//! [`stream::DataStream`]s.  It uses rust async code and future-related
//! traits, and is intended to work with (nearly) any executor
//! implementation that complies with the futures API.  It should also
//! work with nearly any TLS implementation that exposes AsyncRead and
//! AsyncWrite traits.
//!
//! ## Not in this crate
//!
//! This crate does _not_ implement higher level protocols, like onion
//! services or the Tor directory protocol, that are based on the Tor
//! protocol here.  Nor does it decide _when_, _how_, or _where_ to
//! build channels and circuits: that's the role of higher-level crates.
//!
//! This crate also has no support for timeouts, so every network
//! operation here has the potential to block the current task
//! indefinitely.  Timeouts are another necessary piece that gets
//! added at a higher level.
//!
//! In order to create channels and circuits, you'll need to know
//! about some Tor relays, and expose their information via
//! [`tor_linkspec::ChanTarget`] and [`tor_linkspec::CircTarget`].
//! Currently, the [`tor-netdir`] crate is the easiest way to do so.
//!
//! For an example of this crate in action, see the [`arti-client`]
//! library, or the `arti` CLI.
//!
//! # Design notes
//!
//! This crate's APIs are structured to explicitly avoid any usage of
//! an asynchronous runtime: It doesn't launch tasks or include
//! timeouts.  Those are done at a higher level in Arti, via the
//! [`tor-rtcompat`] crate.
//!
//! To the extent possible, this crate avoids doing public-key
//! cryptography in the same functions it uses for network activity.
//! This makes it easier for higher-level code to parallelize or yield
//! around public-key operations.
//!
//! # Limitations
//!
//! This is all a work in progress, and will need severe refactoring
//! before it's done.
//!
//! This is a client-only implementation; there is no support the
//! operations that Relays need.
//!
//! There are too many missing features to list.
//!
//! There isn't enough documentation or examples.
//!
//! This crate was my first attempt to use async in rust, and is probably
//! pretty kludgy.
//!
//! I bet that there are deadlocks somewhere in this code.  I fixed
//! all the ones I could find or think of, but it would be great to
//! find a good way to eliminate every lock that we have.

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

pub mod channel;
pub mod circuit;
mod crypto;
pub mod stream;
mod util;

pub use util::err::{Error, ResolveError};
pub use util::skew::ClockSkew;

pub use channel::params::ChannelsParams;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Timestamp object that we update whenever we get incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
static LAST_INCOMING_TRAFFIC: util::ts::OptTimestamp = util::ts::OptTimestamp::new();

/// Called whenever we receive incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
#[inline]
pub(crate) fn note_incoming_traffic() {
    LAST_INCOMING_TRAFFIC.update();
}

/// Return the amount of time since we last received "incoming traffic".
///
/// This is a global counter, and is subject to interference from
/// other users of the `tor_proto`.  Its only permissible use is for
/// checking how recently we have been definitely able to receive
/// incoming traffic.
///
/// When enabled, this timestamp is updated whenever we receive a valid
/// cell, and whenever we complete a channel handshake.
///
/// Returns `None` if we never received "incoming traffic".
pub fn time_since_last_incoming_traffic() -> Option<std::time::Duration> {
    LAST_INCOMING_TRAFFIC.time_since_update().map(Into::into)
}
