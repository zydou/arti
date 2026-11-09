//! Relay configuration options only for testing networks.
//!
//! We enforce this [`TestingConfig`] to be used ONLY if custom directory authorities are
//! explicitly set in the configuration file.
//!
//! These options MUST NOT be used in the real network. Furthermore, we shouldn't use
//! these to change the network behaviours or to change timings such as consensus
//! intervals.

use derive_deftly::Deftly;

use tor_config::derive::prelude::*;

/// Options for running a relay in a test network.
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
#[derive_deftly(TorConfig)]
pub(crate) struct TestingConfig {
    /// Should we allow outgoing channels to all addresses, including local and private
    /// addresses?
    #[deftly(tor_config(default))]
    pub(crate) allow_channels_to_all_addrs: bool,
}
