//! Module exposing tunnel-related types shared by clients and relays.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::circuit::UniqId;
use derive_more::Display;

/// The unique identifier of a tunnel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("{}", _0)]
#[cfg_attr(feature = "relay", visibility::make(pub))]
#[allow(unreachable_pub)] // TODO(#1447): use in ChanMgr's ChannelProvider impl
pub(crate) struct TunnelId(u64);

impl TunnelId {
    /// Create a new TunnelId.
    ///
    /// # Panics
    ///
    /// Panics if we have exhausted the possible space of u64 IDs.
    pub(crate) fn next() -> TunnelId {
        /// The next unique tunnel ID.
        static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "Exhausted Tunnel ID space?!");
        TunnelId(id)
    }
}

/// The identifier of a circuit [`UniqId`] within a tunnel.
///
/// This type is only needed for logging purposes: a circuit's [`UniqId`] is
/// process-unique, but in the logs it's often useful to display the
/// owning tunnel's ID alongside the circuit identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("Circ {}.{}", tunnel_id, circ_id.display_chan_circ())]
pub(crate) struct TunnelScopedCircId {
    /// The identifier of the owning tunnel
    tunnel_id: TunnelId,
    /// The process-unique identifier of the circuit
    circ_id: UniqId,
}

impl TunnelScopedCircId {
    /// Create a new [`TunnelScopedCircId`] from the specified identifiers.
    pub(crate) fn new(tunnel_id: TunnelId, circ_id: UniqId) -> Self {
        Self { tunnel_id, circ_id }
    }

    /// Return the [`UniqId`].
    pub(crate) fn unique_id(&self) -> UniqId {
        self.circ_id
    }
}
