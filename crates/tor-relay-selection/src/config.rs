//! Define configuration structures used for relay selection.

use std::collections::HashSet;

/// Configuration object for building relay restrictions.
///
/// This object can affect the interpretation of various usages and restrictions.
#[allow(clippy::exhaustive_structs)]
pub struct RelaySelectionConfig<'a> {
    /// A set of ports that require Stable relays.
    pub long_lived_ports: &'a HashSet<u16>,

    /// Configuration for which addresses are considered "too close"
    /// to share a circuit.
    pub subnet_config: tor_netdir::SubnetConfig,
}

impl<'a> RelaySelectionConfig<'a> {
    /// Return true if `port` requires us to use relays with the Stable flag.
    pub(crate) fn port_requires_stable_flag(&self, port: u16) -> bool {
        self.long_lived_ports.contains(&port)
    }
}
