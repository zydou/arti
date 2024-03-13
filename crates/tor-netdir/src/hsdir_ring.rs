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

use std::collections::HashMap;
use std::fmt::Debug;

use derive_more::{AsRef, From, Into};
use digest::Digest;
use typed_index_collections::TiVec;

use tor_basic_utils::impl_debug_hex;
use tor_hscrypto::{pk::HsBlindId, time::TimePeriod};
use tor_llcrypto::d::Sha3_256;
use tor_llcrypto::pk::ed25519::Ed25519Identity;

use crate::hsdir_params::HsDirParams;
use crate::{NetDir, RouterStatusIdx};

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
#[derive(Copy, Clone, Eq, Hash, PartialEq, Ord, PartialOrd, AsRef)]
pub(crate) struct HsDirIndex(#[as_ref] [u8; 32]);

impl_debug_hex! { HsDirIndex .0 }

/// Position in the hsdir hash ring
///
/// This an "index" in the sense that you can use it to index `HsDirRing.ring`,
/// but in the spec, in the context of the hsdir,
/// "index" is used to the sort key - here, [`HsDirIndex`].
#[derive(Debug, From, Into, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct HsDirPos(usize);

/// A hash ring as used in `NetDir`.
///
/// This type is immutable once constructed: entries cannot be added, changed,
/// or removed.  It can be interpreted only in the context of a given consensus
/// document.
#[derive(Clone, Debug)]
pub(crate) struct HsDirRing {
    /// The parameters (time period and shared random value)
    params: HsDirParams,

    /// The ring itself.
    ///
    /// The first element of each tuple is a 32-byte hash representing a
    /// position on the ring; the second is the index for the corresponding
    /// relay within self.consensus.relays().
    ///
    /// This vector is empty in a partial netdir; it is filled in when we
    /// convert to a complete netdir.
    ring: TiVec<HsDirPos, (HsDirIndex, RouterStatusIdx)>,
}

/// Compute the [`HsDirIndex`] for a given relay.
pub(crate) fn relay_hsdir_index(
    kp_relayid_ed: &Ed25519Identity,
    params: &HsDirParams,
) -> HsDirIndex {
    // rend-spec-v3 2.2.3 "hsdir_index(node)"
    //
    // hsdir_index(node) = H("node-idx" | node_identity |
    //      shared_random_value |
    //      INT_8(period_num) |
    //      INT_8(period_length) )
    //
    // Note that INT_8 means "u64" and H is sha3-256.

    let mut h = Sha3_256::default();
    h.update(b"node-idx");
    h.update(kp_relayid_ed.as_bytes());
    h.update(params.shared_rand.as_ref());
    h.update(params.time_period.interval_num().to_be_bytes());
    h.update(u64::from(params.time_period.length().as_minutes()).to_be_bytes());
    HsDirIndex(h.finalize().into())
}

/// Compute the starting [`HsDirIndex`] for a given descriptor replica.
pub(crate) fn service_hsdir_index(
    kp_hs_blind_id: &HsBlindId,
    replica: u8,
    params: &HsDirParams,
) -> HsDirIndex {
    // rend-spec-v3 2.2.3 "hs_index(replicanum)"
    //
    // hs_index(replicanum) = H("store-at-idx" |
    //      blinded_public_key |
    //      INT_8(replicanum) |
    //      INT_8(period_length) |
    //      INT_8(period_num) )
    //
    // Note that INT_8 means "u64" and H is sha3-256

    let mut h = Sha3_256::new();
    h.update(b"store-at-idx");
    h.update(kp_hs_blind_id.as_ref());
    h.update(u64::from(replica).to_be_bytes());
    h.update(u64::from(params.time_period.length().as_minutes()).to_be_bytes());
    h.update(params.time_period.interval_num().to_be_bytes());
    HsDirIndex(h.finalize().into())
}

impl HsDirRing {
    /// Return a new empty HsDirRing from a given set of parameters.
    pub(crate) fn empty_from_params(params: HsDirParams) -> Self {
        Self {
            params,
            ring: TiVec::new(),
        }
    }

    /// Compute the HsDirRing
    ///
    /// Reuses existing hash calculations from a previous netdir, if available.
    ///
    /// `this_netdir.hsdir_rings` is not used; the return values from this function
    /// will be stored there by
    /// [`PartialNetDir::compute_rings`](super::PartialNetDir::compute_rings).
    pub(crate) fn compute(
        new_params: HsDirParams,
        this_netdir: &NetDir,
        prev_netdir: Option<&NetDir>,
    ) -> Self {
        // TODO: The ring itself can be a bit expensive to compute, so maybe we should
        // make sure this happens in a separate task or something, and expose a
        // way to do that?
        // But: this is being done during netdir ingestion, which is already happening
        // on the dirmgr task.  So I think this is fine?  -Diziet

        // We would like to avoid re-computing the hsdir indexes, since they're a hash
        // each.  Instead, we look to see if our previous netdir contains a hash ring
        // using the same parameters.  If so, we make a hashmap from relay identities
        // to hsring_index positions _in the previous netdir_
        // to reuse.
        //
        // TODO: Actually, the relays in the consensus are ordered by their RSA identity.
        // So we could do a merge join on the previous and last relay lists, and avoid
        // building this separate hashmap.  (We'd have to *check* that the ed25519 ids
        // matched, but it would be OK to recompute the index values for relays that
        // have a different correspondence between ed25519 and RSA ids in subsequent
        // consensuses, since that's really not supposed to happen.
        //
        // However, that would involve tor-netdoc offering the ordering property as a
        // *guarantee*.  It's also quite subtle.  This algorithm is O(N.log(N)) which
        // is the same complexity as the (unavoidable) sort by hsdir_index.
        let reuse_index_values: HashMap<&Ed25519Identity, &HsDirIndex> = (|| {
            let prev_netdir = prev_netdir?;
            let prev_ring = prev_netdir
                .hsdir_rings
                .iter()
                .find(|prev_ring| prev_ring.params == new_params)?;

            let reuse_index_values = prev_ring
                .ring
                .iter()
                .filter_map(|(hsdir_index, rsidx)| {
                    Some((prev_netdir.md_by_rsidx(*rsidx)?.ed25519_id(), hsdir_index))
                })
                .collect();
            Some(reuse_index_values)
        })()
        .unwrap_or_default();

        let mut new_ring: TiVec<_, _> = this_netdir
            .all_hsdirs()
            .map(|(rsidx, relay)| {
                let ed_id = relay.md.ed25519_id();
                let hsdir_index = reuse_index_values
                    .get(ed_id)
                    .cloned()
                    .cloned()
                    .unwrap_or_else(|| relay_hsdir_index(ed_id, &new_params));
                (hsdir_index, rsidx)
            })
            .collect();

        // rsidx are all different, so no need to think about comparing them
        new_ring.sort_by_key(|(hsdir_index, _rsidx)| *hsdir_index);

        HsDirRing {
            ring: new_ring,
            params: new_params,
        }
    }

    /// Return the parameters used for this ring
    pub(crate) fn params(&self) -> &HsDirParams {
        &self.params
    }

    /// Find the location or (notional) insertion point for `hsdir_index` within `ring`.
    fn find_pos(&self, hsdir_index: HsDirIndex) -> HsDirPos {
        self.ring
            .binary_search_by_key(&hsdir_index, |(hsdir_index, _rs_idx)| *hsdir_index)
            .unwrap_or_else(|pos| pos)
    }

    /// Yield `spread` items from `ring` that satisfy the specified filter, starting with
    /// `hsdir_index`.
    ///
    /// Wraps around once when we reach the end.
    ///
    /// The specified filter function `f` is applied to each item, and determines whether the item
    /// should be yielded or not. This filtering functionality is used by [`NetDir::hs_dirs`] to
    /// prevent nodes that have already been selected for a lowered-numbered replica to be
    /// considered again when choosing `spread` nodes for a higher-numbered replicas.
    ///
    /// Yields no element more than once, even if the ring is smaller than `spread`.
    pub(crate) fn ring_items_at(
        &self,
        hsdir_index: HsDirIndex,
        spread: usize,
        f: impl FnMut(&&(HsDirIndex, RouterStatusIdx)) -> bool,
    ) -> impl Iterator<Item = &(HsDirIndex, RouterStatusIdx)> {
        let pos = self.find_pos(hsdir_index);
        self.ring[pos..]
            .iter()
            .chain(&self.ring[..pos])
            .filter(f)
            .take(spread)
    }

    /// Return the time period for which this ring applies.
    pub(crate) fn time_period(&self) -> TimePeriod {
        self.params.time_period
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use std::time::Duration;

    // mirrors C Tor src/test/test_hs_common.c:test_hs_indexes
    #[test]
    fn test_hs_indexes() {
        // C Tor test vector simply has
        //    uint64_t period_num = 42;
        let time_period = TimePeriod::new(
            Duration::from_secs(24 * 3600),
            // ~43 days from the Unix epoch
            humantime::parse_rfc3339("1970-02-13T01:00:00Z").unwrap(),
            Duration::from_secs(12 * 3600),
        )
        .unwrap();
        assert_eq!(time_period.interval_num(), 42);

        let shared_rand = [0x43; 32].into();

        let params = HsDirParams {
            time_period,
            shared_rand,
            srv_lifespan: time_period.range().unwrap(),
        };

        // service_index AKA hs_index
        {
            let kp_hs_blind_id = [0x42; 32].into();
            let replica = 1;
            let got = service_hsdir_index(&kp_hs_blind_id, replica, &params);
            assert_eq!(
                hex::encode(got.as_ref()),
                "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a",
            );
        }

        // relay_index AKA hsdir_index
        {
            let kp_relayid_ed = [0x42; 32].into();
            let got = relay_hsdir_index(&kp_relayid_ed, &params);
            assert_eq!(
                hex::encode(got.as_ref()),
                "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5",
            );
        }
    }
}
