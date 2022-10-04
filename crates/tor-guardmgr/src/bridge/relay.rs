//! Implementation code to make a bridge something that we can connect to and use to relay traffic.

use std::sync::Arc;

use tor_linkspec::{HasRelayIds, RelayIdRef, RelayIdType};

use super::{Bridge, BridgeDesc};

/// The information about a Bridge that is necessary to connect to it and relay traffic.
#[derive(Clone, Debug)]

pub struct BridgeRelay {
    /// The local configurations for the bridge.
    ///
    /// This is _always_ necessary, since it without it we can't know whether
    /// any pluggable transports are needed.
    bridge_line: Arc<Bridge>,

    /// A descriptor for the bridge.
    ///
    /// If present, it MUST have every RelayId that the `bridge_line` does.
    desc: Option<BridgeDesc>,
}

impl BridgeRelay {
    /// Return true if this BridgeRelay has a known descriptor and can be used for relays.
    pub fn has_descriptor(&self) -> bool {
        self.desc.is_some()
    }
}

impl HasRelayIds for BridgeRelay {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.bridge_line
            .identity(key_type)
            .or_else(|| self.desc.as_ref().and_then(|d| d.identity(key_type)))
    }
}
