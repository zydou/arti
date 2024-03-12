//! Define extension traits for [`tor_netdir`] types.

use crate::{LowLevelRelayPredicate, SelectionInfo};
use tor_netdir::Relay;

/// Private module to prevent other crates from seeing `Sealed`.
mod sealed {
    /// Sealing trait.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// Extension trait for [`Relay`], to check whether it matches selection
/// properties.
pub trait RelayExt: sealed::Sealed {
    /// Return true if this `Relay` is permitted by a given predicate.
    fn obeys_predicate<P: LowLevelRelayPredicate>(&self, pred: &P) -> bool;
}

impl<'a> sealed::Sealed for tor_netdir::Relay<'a> {}
impl<'a> RelayExt for Relay<'a> {
    fn obeys_predicate<P: LowLevelRelayPredicate>(&self, pred: &P) -> bool {
        pred.low_level_predicate_permits_relay(self)
    }
}

/// Extension trait for [`NetDir`], to implement semantic relay selection.
pub trait NetDirExt: sealed::Sealed {
    /// Try to select a random relay according to `selector`.
    fn select_relay<'a, 'b, R: rand::Rng>(
        &'a self,
        rng: &mut R,
        selector: &'b crate::RelaySelector<'_>,
    ) -> (Option<Relay<'a>>, SelectionInfo<'b>);

    /// Try to select `n_relays` distinct random relays according to `selector`.
    fn select_n_relays<'a, 'b, R: rand::Rng>(
        &'a self,
        rng: &mut R,
        n_relays: usize,
        selector: &'b crate::RelaySelector<'_>,
    ) -> (Vec<Relay<'a>>, SelectionInfo<'b>);
}
impl sealed::Sealed for tor_netdir::NetDir {}
impl NetDirExt for tor_netdir::NetDir {
    fn select_relay<'a, 'b, R: rand::Rng>(
        &'a self,
        rng: &mut R,
        selector: &'b crate::RelaySelector<'_>,
    ) -> (Option<Relay<'a>>, SelectionInfo<'b>) {
        selector.select_relay(rng, self)
    }

    fn select_n_relays<'a, 'b, R: rand::Rng>(
        &'a self,
        rng: &mut R,
        n_relays: usize,
        selector: &'b crate::RelaySelector<'_>,
    ) -> (Vec<Relay<'a>>, SelectionInfo<'b>) {
        selector.select_n_relays(rng, n_relays, self)
    }
}
