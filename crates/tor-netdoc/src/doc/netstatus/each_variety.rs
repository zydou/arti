//! network status documents - items for all varieties, that vary
//!
//! **This file is reincluded multiple times**,
//! by the macros in [`crate::doc::ns_variety_definition_macros`],
//! once for votes, and once for each consensus flavour.
//! It is *not* a module `crate::doc::netstatus::rs::each_variety`.
//!
//! Each time this file is included by one of the macros mentioned above,
//! the `ns_***` macros (such as `ns_const_name!`) may expand to different values.
//!
//! See [`crate::doc::ns_variety_definition_macros`].

use super::*;

ns_use_this_variety! {
    pub use [crate::doc::netstatus::rs]::?::{RouterStatus};
}

/// The header of a networkstatus.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Header {
    /// What kind of consensus document is this?  Absent in votes and
    /// in ns-flavored consensuses.
    pub flavor: ConsensusFlavor,
    /// Over what time is this consensus valid?  (For votes, this is
    /// the time over which the voted-upon consensus should be valid.)
    pub lifetime: Lifetime,
    /// List of recommended Tor client versions.
    pub client_versions: Vec<String>,
    /// List of recommended Tor relay versions.
    pub relay_versions: Vec<String>,
    /// Lists of recommended and required subprotocols.
    pub proto_statuses: Arc<ProtoStatuses>,
    /// Declared parameters for tunable settings about how to the
    /// network should operator. Some of these adjust timeouts and
    /// whatnot; some features things on and off.
    pub params: NetParams<i32>,
    /// How long in seconds should voters wait for votes and
    /// signatures (respectively) to propagate?
    pub voting_delay: Option<(u32, u32)>,
    /// What "method" was used to produce this consensus?  (A
    /// consensus method is a version number used by authorities to
    /// upgrade the consensus algorithm.)
    pub consensus_method: u32,
    /// Global shared-random value for the previous shared-random period.
    pub shared_rand_prev: Option<SharedRandStatus>,
    /// Global shared-random value for the current shared-random period.
    pub shared_rand_cur: Option<SharedRandStatus>,
}
