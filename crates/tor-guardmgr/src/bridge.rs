//! Code to configure and manage a set of bridge relays.
//!
//! A bridge relay, or "bridge" is a tor relay not listed as part of Tor
//! directory, in order to prevent censors from blocking it.  Instead, clients
//! learn about bridges out-of-band, and contact them either directly or via a
//! pluggable transport.
//!
//! When a client is configured to use bridges, it uses them in place of its
//! regular set of guards in building the first hop of its circuits.
//
// TODO pt-client: Should this whole module be in another crate?

mod config;
mod descs;
mod relay;

pub use config::{BridgeConfig, BridgeParseError};
pub use descs::{BridgeDesc, BridgeDescError, BridgeDescEvent, BridgeDescList, BridgeDescProvider};
pub use relay::BridgeRelay;
