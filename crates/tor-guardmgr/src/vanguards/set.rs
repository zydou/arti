//! Vanguard sets

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use tor_linkspec::RelayIds;
use tor_netdir::{NetDir, Relay};

/// A vanguard relay.
//
// TODO HS-VANGUARDS: this is currently just a Relay newtype (if it doesn't grow any additional
// fields, we might want to consider removing it and using Relay instead).
#[derive(Clone)]
#[allow(unused)] // TODO HS-VANGUARDS
pub struct Vanguard<'a> {
    /// The relay.
    relay: Relay<'a>,
}

/// An identifier for a time-bound vanguard.
#[derive(Debug, Clone, Serialize, Deserialize)] //
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)] //
pub(crate) struct TimeBoundVanguard {
    /// The ID of this relay.
    id: RelayIds,
    /// When to stop using this relay as a vanguard.
    expiration: SystemTime,
}

/// A set of vanguards, for use in a particular [`Layer`](crate::vanguards::Layer).
#[derive(Debug, Default, Clone, Serialize, Deserialize)] //
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[allow(unused)] // TODO HS-VANGUARDS
pub(super) struct VanguardSet {
    /// The time-bound vanguards of a given [`Layer`](crate::vanguards::Layer).
    vanguards: Vec<TimeBoundVanguard>,
}

impl VanguardSet {
    /// Pick a relay from this set.
    pub(super) fn pick_relay(&self, _netdir: &NetDir) -> Option<Vanguard> {
        todo!()
    }
}
