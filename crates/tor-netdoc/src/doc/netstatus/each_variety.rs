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

/// The preamble of a network status document, except for the intro and `vote-status` items.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:preable>
///
/// **Does not include `network-status-version` and `vote-status`**.
/// In the old parser this is not represented directly;
/// instead, in `Consensus.flavor`, there's just the `ConsensusFlavor`.
/// `parse2` doesn't (currently) support subdocuments which contain the parent's intro item
/// (ie, `#[deftly(netdoc(flatten))]` is not supported on the first field.)
//
// TODO DIRAUTH the *contents* of this struct is still wrong for votes,
// and is missing some consensus fields that need to be manipulated by dirauths;
// there are individual TODO comments about each such defect.
#[cfg_attr(
    feature = "parse2",
    derive(Deftly),
    derive_deftly(NetdocParseableFields),
)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Preamble {
    /// Consensus methods supported by this voter.
    pub consensus_methods: ns_type!( NotPresent, NotPresent, ConsensusMethods ),

    /// What "method" was used to produce this consensus?  (A
    /// consensus method is a version number used by authorities to
    /// upgrade the consensus algorithm.)
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    pub consensus_method: ns_type!( u32, u32, NotPresent ),

    /// Publication time (of a vote)
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    pub published: ns_type!( NotPresent, NotPresent, Iso8601TimeSp ),

    /// Over what time is this consensus valid?  (For votes, this is
    /// the time over which the voted-upon consensus should be valid.)
    #[cfg_attr(feature = "parse2", deftly(netdoc(flatten)))]
    pub lifetime: Lifetime,

    /// How long in seconds should voters wait for votes and
    /// signatures (respectively) to propagate?
    pub voting_delay: Option<(u32, u32)>,

    /// List of recommended Tor client versions.
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    pub client_versions: Vec<String>,

    /// List of recommended Tor relay versions.
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    pub server_versions: Vec<String>,

    // TODO DIRAUTH missing field: known-flags (in consensuses too, not just votes)
    // TODO DIRAUTH missing field: flag-thresholds (in votes)

    /// Lists of recommended and required subprotocols.
    ///
    /// **`{recommended,required}-{client,relay}-protocols`**
    #[cfg_attr(feature = "parse2", deftly(netdoc(flatten)))]
    pub proto_statuses: Arc<ProtoStatuses>,

    /// Declared parameters for tunable settings about how to the
    /// network should operator. Some of these adjust timeouts and
    /// whatnot; some features things on and off.
    pub params: NetParams<i32>,

    /// Global shared-random value for the previous shared-random period.
    // TODO DIRAUTH in votes, is in the authority section
    pub shared_rand_previous_value: Option<SharedRandStatus>,

    /// Global shared-random value for the current shared-random period.
    // TODO DIRAUTH in votes, is in the authority section
    pub shared_rand_current_value: Option<SharedRandStatus>,

    // TODO DIRAUTH missing field: bandwidth-file-headers (in votes)
    // TODO DIRAUTH missing field: bandwidth-file-digest (in votes)
}
