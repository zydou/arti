//! Code for anything related to a peer as in the endpoint of a tor channel.
//!
//! Peer information is put into a [`crate::channel::Channel`] which contains the information that
//! has been used to connect to it.

use std::net::{IpAddr, SocketAddr};

use tor_linkspec::{BridgeAddr, ChannelMethod, HasRelayIds, RelayIdRef, RelayIdType, RelayIds};

#[cfg(feature = "pt-client")]
use tor_linkspec::{PtTarget, PtTargetAddr};

/// Represents the address of a connected peer used for a tor channel.
///
/// Clever observer here would see that this is basically a [`tor_linkspec::ChannelMethod`] which
/// has a Direct variant with a vector of address which is incoherent with the semantic of "where we
/// are connected to".
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PeerAddr {
    /// The socket address we are directly connected to.
    Direct(SocketAddr),
    /// The pluggable transport target used to connect.
    ///
    /// Note that this is not a specific address but the PT transport details. We keep those
    /// because if the [`PtTargetAddr`] happens to be None, we need to compare the transport name
    /// and settings to match a channel.
    #[cfg(feature = "pt-client")]
    Pt(PtTarget),
}

impl PeerAddr {
    /// Unspecified address used for placeholder in unit tests.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) const UNSPECIFIED: Self = Self::Direct(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        0,
    ));

    /// Return the IP address that should be used in the NETINFO cell.
    ///
    /// A None value implies we didn't use an IP address to connect (see [`PtTarget`]). The
    /// [`tor_cell::chancell::msg::Netinfo`] interface will treat a None as an IPv4 unspecified
    /// address (0.0.0.0).
    pub fn netinfo_addr(&self) -> Option<IpAddr> {
        self.socket_addr().map(|sa| sa.ip())
    }

    /// Return the socket address of this peer.
    ///
    /// None means that this is a PT and doesn't use an internet addres. One example is it uses a
    /// hostname.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerAddr::Direct(sa) => Some(*sa),
            #[cfg(feature = "pt-client")]
            PeerAddr::Pt(t) => match t.addr() {
                PtTargetAddr::IpPort(sa) => Some(*sa),
                _ => None,
            },
        }
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(sa: SocketAddr) -> Self {
        Self::Direct(sa)
    }
}

#[cfg(feature = "pt-client")]
impl From<PtTarget> for PeerAddr {
    fn from(t: PtTarget) -> Self {
        Self::Pt(t)
    }
}

/// Useful because [`BridgeAddr`] are used in some Error struct.
impl From<&PeerAddr> for Option<BridgeAddr> {
    fn from(t: &PeerAddr) -> Self {
        match t {
            PeerAddr::Direct(sa) => Some(BridgeAddr::new_addr_from_sockaddr(*sa)),
            #[cfg(feature = "pt-client")]
            PeerAddr::Pt(target) => target.addr().clone().into(),
        }
    }
}

/// Represents the actual information about the peer of a [`crate::channel::Channel`].
///
/// This type exists because [`tor_linkspec::OwnedChanTarget`] is overloaded and used for multiple
/// purposes.
///
/// An [`tor_linkspec::OwnedChanTarget`] represents an intended target, rather than what is
/// actually used. In addition, it stores peer addresses both in a vector inside the struct and
/// within the [`ChannelMethod`]. When connecting to the peer, our code returns an
/// [`tor_linkspec::OwnedChanTarget`] whose [`ChannelMethod`] has been filtered to contain only the
/// address that was actually used. However, the [`tor_linkspec::HasAddrs`] trait reads from the
/// address vector, which creates a disconnect between the intent and the actual usage.
///
/// This struct resolves that ambiguity by storing the concrete peer information that was actually
/// used. It provides clear, unambiguous guarantees about the peer associated with the channel.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Actual target address used for the channel connection.
    addr: PeerAddr,
    /// Identities that this relay provides.
    ids: RelayIds,
}

impl PeerInfo {
    /// Empty peer info used for placeholder in unit tests.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) const EMPTY: Self = Self {
        addr: PeerAddr::UNSPECIFIED,
        ids: RelayIds::empty(),
    };

    /// Constructor.
    pub(crate) fn new(addr: PeerAddr, ids: RelayIds) -> Self {
        Self { addr, ids }
    }

    /// Return a reference to the target address.
    fn addr(&self) -> &PeerAddr {
        &self.addr
    }

    /// Return a reference to the [`RelayIds`] of this channel target.
    fn ids(&self) -> &RelayIds {
        &self.ids
    }

    /// Return true iff the given [`ChannelMethod`] matches us.
    ///
    /// A [`ChannelMethod`] is semantically for the concept of a "target" as in a connection goal.
    /// And so, this method returns true or false if the target method matches the peer
    /// information. This is used to choose the best channel in the channel manager.
    ///
    /// A match is true if:
    ///     * Direct: Our address is contained in the method set of addresses.
    ///     * Pluggable: Our address is equal to the method's target.
    pub fn matches_chan_method(&self, method: &ChannelMethod) -> bool {
        match (method, self.addr()) {
            (ChannelMethod::Direct(addrs), PeerAddr::Direct(our_addr)) => addrs.contains(our_addr),
            #[cfg(feature = "pt-client")]
            (ChannelMethod::Pluggable(target), PeerAddr::Pt(our_target)) => our_target == target,
            _ => false,
        }
    }
}

impl HasRelayIds for PeerInfo {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.ids().identity(key_type)
    }
}
