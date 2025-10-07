//! Implementation code to make a bridge something that we can connect to and use to relay traffic.

use itertools::Itertools as _;
use tor_linkspec::{
    ChanTarget, CircTarget, HasAddrs, HasChanMethod, HasRelayIds, RelayIdRef, RelayIdType,
};

use super::{BridgeConfig, BridgeDesc};

/// The information about a Bridge that is necessary to connect to it and send
/// it traffic.
#[derive(Clone, Debug)]
pub struct BridgeRelay<'a> {
    /// The local configurations for the bridge.
    ///
    /// This is _always_ necessary, since it without it we can't know whether
    /// any pluggable transports are needed.
    bridge_line: &'a BridgeConfig,

    /// A descriptor for the bridge.
    ///
    /// If present, it MUST have every RelayId that the `bridge_line` does.
    ///
    /// `BridgeDesc` is an `Arc<>` internally, so we aren't so worried about
    /// having this be owned.
    desc: Option<BridgeDesc>,

    /// All the known addresses for the bridge.
    ///
    /// This includes the contact addresses in `bridge_line`, plus any addresses
    /// listed in `desc`.
    ///
    /// TODO(nickm): I wish we didn't have to reallocate a for this, but the API
    /// requires that we can return a reference to a slice of this.
    ///
    /// TODO(nickm): perhaps, construct this lazily?
    addrs: Vec<std::net::SocketAddr>,
}

/// A BridgeRelay that is known to have its full information available, and
/// which is therefore usable for multi-hop circuits.
///
/// (All bridges can be used for single-hop circuits, but we need to know the
/// bridge's descriptor in order to construct proper multi-hop circuits
/// with forward secrecy through it.)
#[derive(Clone, Debug)]
pub struct BridgeRelayWithDesc<'a>(
    /// This will _always_ be a bridge relay with a non-None desc.
    &'a BridgeRelay<'a>,
);

impl<'a> BridgeRelay<'a> {
    /// Construct a new BridgeRelay from its parts.
    pub(crate) fn new(bridge_line: &'a BridgeConfig, desc: Option<BridgeDesc>) -> Self {
        let addrs = bridge_line
            .addrs()
            .chain(desc.iter().flat_map(|d| d.as_ref().or_ports()))
            .unique()
            .collect();

        Self {
            bridge_line,
            desc,
            addrs,
        }
    }

    /// Return true if this BridgeRelay has a known descriptor and can be used for relays.
    pub fn has_descriptor(&self) -> bool {
        self.desc.is_some()
    }

    /// If we have enough information about this relay to build a circuit through it,
    /// return a BridgeRelayWithDesc for it.
    pub fn as_relay_with_desc(&self) -> Option<BridgeRelayWithDesc<'_>> {
        self.desc.is_some().then_some(BridgeRelayWithDesc(self))
    }
}

impl<'a> HasRelayIds for BridgeRelay<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.bridge_line
            .identity(key_type)
            .or_else(|| self.desc.as_ref().and_then(|d| d.identity(key_type)))
    }
}

impl<'a> HasAddrs for BridgeRelay<'a> {
    /// Note: Remember (from the documentation at [`HasAddrs`]) that these are
    /// not necessarily addresses _at which the Bridge can be reached_. For
    /// those, use `chan_method`.  These addresses are used for establishing
    /// GeoIp and family info.
    fn addrs(&self) -> impl Iterator<Item = std::net::SocketAddr> {
        self.addrs.iter().copied()
    }
}

impl<'a> HasChanMethod for BridgeRelay<'a> {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        self.bridge_line.chan_method()
    }
}

impl<'a> ChanTarget for BridgeRelay<'a> {}

impl<'a> HasRelayIds for BridgeRelayWithDesc<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.0.identity(key_type)
    }
}
impl<'a> HasAddrs for BridgeRelayWithDesc<'a> {
    /// Note: Remember (from the documentation at [`HasAddrs`]) that these are
    /// not necessarily addresses _at which the Bridge can be reached_. For
    /// those, use `chan_method`.  These addresses are used for establishing
    /// GeoIp and family info.
    fn addrs(&self) -> impl Iterator<Item = std::net::SocketAddr> {
        self.0.addrs()
    }
}
impl<'a> HasChanMethod for BridgeRelayWithDesc<'a> {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        self.0.chan_method()
    }
}

impl<'a> ChanTarget for BridgeRelayWithDesc<'a> {}

impl<'a> BridgeRelayWithDesc<'a> {
    /// Return a reference to the BridgeDesc in this reference.
    fn desc(&self) -> &BridgeDesc {
        self.0
            .desc
            .as_ref()
            .expect("There was supposed to be a descriptor here")
    }
}

impl<'a> CircTarget for BridgeRelayWithDesc<'a> {
    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        self.desc().as_ref().ntor_onion_key()
    }

    fn protovers(&self) -> &tor_protover::Protocols {
        self.desc().as_ref().protocols()
    }
}
