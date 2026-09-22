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
    pub use [crate::doc::netstatus::rs]::?::{
        RouterStatus, RouterStatusConstructor,
        RouterStatusIntroItem, RouterStatusIntroItemConstructor,
    };
}

/// Network status document - consensus, or vote
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html>
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavors>
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Constructor, NetdocEncodable, NetdocParseableUnverified)]
#[deftly(netdoc(doctype_for_error = NETSTATUS_DOCTYPE_FOR_ERROR))]
#[allow(clippy::exhaustive_structs)]
pub struct NetworkStatus {
    /// The `network-status-version` intro item
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:network-status-version>
    ///
    /// In the "preamble" in the spec, but not in our `Preamble` type for Reasons.
    pub network_status_version: NetworkStatusVersionItem,

    /// `vote-status`
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:vote-status>
    ///
    /// In the "preamble" in the spec, but not in our `Preamble` type for Reasons.
    #[deftly(netdoc(single_arg))]
    pub vote_status: ns_type!(
        VoteStatusConsensus,
        VoteStatusConsensus,
        VoteStatusVote,
    ),

    /// The rest of the preamble
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:preable>
    #[deftly(constructor, netdoc(flatten))]
    pub preamble: Preamble,

    /// Authority section
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>
    #[deftly(constructor, netdoc(subdoc))]
    pub authority: ns_type!(
        ConsensusAuthoritySection,
        ConsensusAuthoritySection,
        VoteAuthoritySection,
    ),

    /// Router status entries
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:router-status>
    #[deftly(netdoc(subdoc))]
    pub routers: Vec<RouterStatus>,

    /// Footer
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:footer>
    #[deftly(netdoc(subdoc))]
    #[deftly(constructor)]
    pub footer: Footer,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// `network-status-version` intro item in a consensus
///
/// This is hard to parse because it's so irregular (even, ambiguous).
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:network-status-version>
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
///
/// <https://gitlab.torproject.org/tpo/core/torspec/-/work_items/359>
#[derive(Clone, Debug, Deftly, Default)]
#[derive_deftly(Constructor, ItemValueEncodable, ItemValueParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct NetworkStatusVersionItem {
    /// The version number, always `3`
    pub version: NetworkStatusVersion,

    /// The `flavor` argument
    ///
    ///  * In a plain consensus, this is an optional `ns`.
    ///  * In an md consensus, this is always `microdesc`.
    ///  * In a vote, there is no variety, but to avoid ambiguity, we reject.
    pub variety: VarietyKeyword,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
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
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Constructor, NetdocEncodableFields, NetdocParseableFields)]
#[allow(clippy::exhaustive_structs)]
pub struct Preamble {
    /// Consensus methods supported by this voter.
    #[deftly(constructor)]
    pub consensus_methods: ns_type!( NotPresent, NotPresent, ConsensusMethods ),

    /// What "method" was used to produce this consensus?  (A
    /// consensus method is a version number used by authorities to
    /// upgrade the consensus algorithm.)
    #[deftly(constructor)]
    // Not #[deftly(netdoc(single_arg))] because that would mean a consensuses
    // had an always-present singleton `consensus_method` item with no arguments.
    pub consensus_method: ns_type!( (u32,), (u32,), NotPresent ),

    /// Publication time (of a vote)
    #[deftly(constructor)]
    // Not #[deftly(netdoc(single_arg))] because that would mean a consensuses
    // had an always-present singleton `published` item with no arguments.
    pub published: ns_type!( NotPresent, NotPresent, (Iso8601TimeSp,) ),

    /// Over what time is this consensus valid?  (For votes, this is
    /// the time over which the voted-upon consensus should be valid.)
    #[deftly(constructor)]
    #[deftly(netdoc(flatten))]
    pub lifetime: Lifetime,

    /// How long in seconds should voters wait for votes and
    /// signatures (respectively) to propagate?
    pub voting_delay: Option<(u32, u32)>,

    /// List of recommended Tor client versions.
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:client-versions>
    #[deftly(netdoc(default))]
    pub client_versions: RecommendedTorVersions,

    /// List of recommended Tor relay versions.
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:server-versions>
    #[deftly(netdoc(default))]
    pub server_versions: RecommendedTorVersions,

    /// Router flags which could be determined
    #[deftly(constructor)]
    #[deftly(netdoc(with = "relay_flags::ParserEncoder::<relay_flags::NoImplicitRepr>"))]
    pub known_flags: DocRelayFlags,

    /// Lists of recommended and required subprotocols.
    ///
    /// **`{recommended,required}-{client,relay}-protocols`**
    #[deftly(constructor)]
    #[deftly(netdoc(flatten))]
    pub proto_statuses: Arc<ProtoStatuses>,

    /// Declared parameters for tunable settings about how to the
    /// network should operator. Some of these adjust timeouts and
    /// whatnot; some features things on and off.
    #[deftly(constructor)]
    pub params: NetParams<i32>,

    /// Global shared-random values
    #[deftly(netdoc(flatten))]
    pub shared_rand: ns_type!( SharedRandStatuses, SharedRandStatuses, NotPresent ),

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// The footer of a network status document.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:footer>>
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Constructor, NetdocEncodable, NetdocParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct Footer {
    /// Intro item
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:directory-footer>
    pub directory_footer: (),

    /// Fields that appear in consensuses (only)
    #[deftly(constructor, netdoc(flatten))]
    pub consensus: ns_type!(ConsensusFooterFields, ConsensusFooterFields, NotPresent),

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// Signatures on a network status document
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(NetdocEncodableFields, NetdocParseableSignatures)]
#[deftly(netdoc(signatures(hashes_accu = "DirectorySignaturesHashesAccu")))]
#[non_exhaustive]
pub struct NetworkStatusSignatures {
    /// `directory-signature`s
    pub directory_signature: ns_type!(Vec<Signature>, Vec<Signature>, Signature),
}

impl Preamble {
    /// Calculate the validity range (time interval) for this network status document
    pub fn validity_time_range(&self) -> std::ops::Range<SystemTime> {
        let lifetime = self.lifetime.clone();
        let delay = self.voting_delay.unwrap_or((0, 0));
        let dist_interval = time::Duration::from_secs(delay.1.into());
        let starting_time = lifetime.valid_after.saturating_sub(dist_interval);
        starting_time..*lifetime.valid_until
    }
}
