//! Functions and type for implementing the onion service directory ring.
//!
//! The onion service directory ring is an ordered ring of the all of relays in
//! the consensus with the HsDir flag. The HSDirs change their position in this
//! index every [`TimePeriod`], and every time that the shared random value in
//! the consensus changes.  (These events are typically synchronized, for
//! reasonable network configurations.)
//!  
//! Each onion service is also (semi-privately) associated with "N" positions on
//! the ring based on its blinded ID and the current time period. When upload or
//! downloading an onion service descriptor descriptor, we look at the ring at
//! each of these positions, and consider the "S" relays that fall at that
//! position or later. ("N" is a "number of replicas" parameter, and "S" is a
//! "Spread" parameter.)

#![allow(unused_variables, dead_code)] //TODO hs: remove

use tor_hscrypto::{pk::HsBlindId, time::TimePeriod};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdoc::doc::netstatus::SharedRandVal;

use crate::hsdir_params::HsRingParams;
use crate::RouterStatusIdx;

/// A sort key determining a position in the onion service directory ring.
///
/// This is either the sort key of a given relay at a given time period, or the
/// sort key for a probing position for a given onion service id at a given
/// time.
///
/// The specification calls this an "index" but `HsDirIndex` is a key-length
/// sized, apparently-random, value, which determines the ordering of relays on
/// the ring. It is not the position number (ie, not a dense index starting at
/// 0).
///
/// Note that this is _not_ an index into any array; it is instead an index into
/// a space of possible values in a (virtual!) ring of 2^256 elements.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct HsDirIndex([u8; 32]);

/// A hash ring as used in `NetDir`.
///
/// This type is immutable once constructed: entries cannot be added, changed,
/// or removed.  It can be interpreted only in the context of a given consensus
/// document.
#[derive(Clone, Debug)]
pub(crate) struct HsDirRing {
    /// The time period for which the ring is valid.
    period: TimePeriod,

    /// The shared random value that applies to the ring.
    shared_rand: SharedRandVal,

    /// The ring itself.
    ///
    /// The first element of each tuple is a 32-byte hash representing a
    /// position on the ring; the second is the index for the corresponding
    /// relay within self.consensus.relays().
    ///
    /// This vector is empty in a partial netdir; it is filled in when we
    /// convert to a complete netdir.
    ring: Vec<(HsDirIndex, RouterStatusIdx)>,
}

/// Compute the [`HsDirIndex`] for a given relay.
pub(crate) fn relay_index(
    id: Ed25519Identity,
    rand: SharedRandVal,
    period: TimePeriod,
) -> HsDirIndex {
    //  TODO hs implement this.
    //
    // hsdir_index(node) = H("node-idx" | node_identity |
    //      shared_random_value |
    //      INT_8(period_num) |
    //      INT_8(period_length) )
    //
    // Note that INT_8 means "u64" and H is sha3-256.

    todo!()
}

/// Compute the starting [`HsDirIndex`] for a given descriptor replica.
pub(crate) fn service_index(
    id: HsBlindId,
    replica: u8,
    rand: SharedRandVal,
    period: TimePeriod,
) -> HsDirIndex {
    // TODO hs implement this
    //
    // hs_index(replicanum) = H("store-at-idx" |
    //      blinded_public_key |
    //      INT_8(replicanum) |
    //      INT_8(period_length) |
    //      INT_8(period_num) )
    //
    // Note that INT_8 means "u64" and H is sha3-256

    todo!()
}

impl HsDirRing {
    /// Return a new empty HsDirRing from a given set of parameters.
    pub(crate) fn empty_from_params(params: &HsRingParams) -> Self {
        Self {
            period: params.time_period,
            shared_rand: params.shared_rand,
            ring: Vec::new(),
        }
    }

    /// Find the location or (notional) insertion point for `idx` within `ring`.
    fn find_pos(&self, idx: HsDirIndex) -> usize {
        // TODO hs implement this
        todo!()
    }

    /// Yield items from `ring` starting with `idx`, wrapping around once when we
    /// reach the end, and yielding no element more than once.
    pub(crate) fn ring_items_at(
        &self,
        idx: HsDirIndex,
    ) -> impl Iterator<Item = &(HsDirIndex, RouterStatusIdx)> {
        let idx = self.find_pos(idx);
        self.ring[idx..].iter().chain(&self.ring[..idx])
    }

    /// Return the time period for which this ring applies.
    pub(crate) fn time_period(&self) -> TimePeriod {
        self.period
    }
}
