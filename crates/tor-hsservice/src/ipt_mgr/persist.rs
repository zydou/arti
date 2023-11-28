//! Persistent state for the IPT manager
//!
//! Records of our IPTs.
//! Does *not* include private keys - those are in the `KeyMgr`.

use super::*;

/// Record of intro point establisher state, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS-IPT-PERSIST remove
struct StateRecord {
    /// Relays
    ipt_relays: Vec<RelayRecord>,
}

/// Record of a selected intro point relay, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS-IPT-PERSIST remove
struct RelayRecord {
    /// Which relay?
    relay: RelayIds,
    /// The IPTs, including the current one and any still-wanted old ones
    ipts: Vec<IptRecord>,
}

/// Record of a single intro point, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS-IPT-PERSIST remove
struct IptRecord {
    /// Used to find the cryptographic keys, amongst other things
    lid: IptLocalId,
    // TODO HSS-IPT-PERSIST other fields need to be here!
}
