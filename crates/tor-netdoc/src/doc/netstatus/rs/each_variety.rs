//! router status entries - items for all varieties, that vary
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

// Explicit parsing arrangements for document digest field in `m` items.
//
// https://spec.torproject.org/dir-spec/consensus-formats.html#item:r
// https://spec.torproject.org/dir-spec/consensus-formats.html#item:m
// https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc
//
// The document digest moves about, and vote `m` items are even more exciting.
// This is for the benefit of the `with` annotations for RouterStatus.m.
//
// We need to make this an import that can be used with `deftly(netdoc(with = ))`.
// `with` expects a path, not a type, so we can't use ns_type!.
//
// (Normally when trying to parse an item whose single field implements ItemArgumentParseable
// but not ItemValueParseable, we would use #[deftly(netdoc(single_arg))]
// but here we can't do that because we can't have variety-dependent attributes.)
ns_choose! { (
    use NotPresentEachValue as doc_digest_item_m;
) (
    // doc_digest_item_m implemented in rs/md.rs
) (
    use RouterStatusMdDigestsVote as doc_digest_item_m;
) }

/// Type of the referenced document digest in form suitable for parsing and encoding
type DocDigestB64 = FixedB64<DOC_DIGEST_LEN>;

/// Intro item for a router status entry
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:r>
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
/// `r` item.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[non_exhaustive]
pub struct RouterStatusIntroItem {
    /// The nickname for this relay.
    ///
    /// Nicknames can be used for convenience purpose, but no more:
    /// there is no mechanism to enforce their uniqueness.
    pub nickname: Nickname,

    /// Fingerprint of the old-style RSA identity for this relay.
    pub identity: Base64Fingerprint,

    /// Digest of the document for this relay (except md consensuses)
    // TODO SPEC rename in the spec from `digest` to "doc_digest"
    // TODO SPEC in md consensuses the referenced document digest is in a separate `m` item
    pub doc_digest: ns_type!(DocDigestB64, NotPresent, DocDigestB64),

    /// Publication time.
    pub publication: ns_type!(
        IgnoredPublicationTimeSp,
        IgnoredPublicationTimeSp,
        Iso8601TimeSp
    ),

    /// IPv4 address
    pub ip: std::net::Ipv4Addr,

    /// Relay port
    pub or_port: u16,

    /// Directory port
    ///
    /// Always 0 when read by the old parser.
    pub dir_port: u16,
}

/// A single relay's status, in a network status document.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:router-status>
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
/// under "Changes to router status entries".
//
// In most netdocs we would use the item keywords as the field names.  But routerstatus
// entry keywords are chosen to be very short to minimise the consensus size, so we
// use longer names in the struct and specify the keyword separately.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
#[non_exhaustive]
pub struct RouterStatus {
    /// `r` --- Introduce a routerstatus entry
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:r>
    /// (and, the md version, which is different).
    pub r: RouterStatusIntroItem,

    /// `m` --- Microdescriptor or document digest
    ///
    /// In an md consensus, the hash of the document for this relay.
    /// In a vote, microdescriptor hashes for the various consensus methods.
    ///
    /// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
    /// `r` item.
    // We call this field `m` rather than `doc_digest` because it's not always the doc digest.
    // TODO SPEC in all but md consensuses the referenced document digest is in the `r` intro item
    //
    // TODO SPEC Adjust microdesc consensus `m` item position in the spec.
    // This item is here because this is where C Tor puts it.  
    #[deftly(netdoc(with = doc_digest_item_m))]
    pub m: ns_type!(NotPresent, DocDigestB64, Vec<RouterStatusMdDigestsVote>),

    /// `a` --- Further router address(es) (IPv6)
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:a>
    /// (and, the md version, which is different).
    #[deftly(netdoc(single_arg))]
    pub a: Vec<net::SocketAddr>,

    /// `s` --- Router status flags
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:s>
    #[deftly(netdoc(
        keyword = "s",
        with = {
            relay_flags::ParserEncoder::<ns_type!(
                relay_flags::ConsensusRepr,
                relay_flags::ConsensusRepr,
                relay_flags::NoImplicitRepr,
            )>
        },
    ))]
    pub flags: DocRelayFlags,

    /// `v` --- Relay's Tor software version
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:v>
    #[deftly(netdoc(keyword = "v"))]
    pub version: Option<SoftwareVersion>,

    /// `pr` --- Subprotocol capabilities supported
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:v>
    #[deftly(netdoc(keyword = "pr"))]
    pub protos: Protocols,

    /// `w` --- Bandwidth estimates
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:w>
    #[deftly(netdoc(flatten))]
    pub weight: RelayWeightsItem,

    /// `p` --- Exit ports summary
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:p>
    ///
    /// This field is not properly parsed in plain consensuses by the old parser.
    #[deftly(netdoc(keyword = "p"))]
    pub port_policy: ns_type!(Option<Intern<PortPolicy>>, NotPresent, Option<Intern<PortPolicy>>),

    /// `id` --- Relay’s (ed25519) identity
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:id>
    #[deftly(netdoc(keyword = "id"))] 
    pub ed25519_id: ns_type!(NotPresent, NotPresent, Ed25519IdentityLine),

    /// `stats` -- Statistics for this relay
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:stats>
    pub stats: ns_type!(NotPresent, NotPresent, NetParams<F64Finite>),
}

impl RouterStatus {
    /// Return the digest of the document identified by this
    /// routerstatus.
    ///
    /// The `doc_digest` method is provided on all varieties of routerstatus entry
    /// to help paper over the protocol anomaly, that the digest is in a different place
    /// in md routerstatus entries.
    pub fn doc_digest(&self) -> &DocDigest {
        ns_expr!(&self.r.doc_digest, &self.m, &self.r.doc_digest,)
    }
}

impl EncodeOrd for RouterStatus {
    fn encode_cmp(&self, other: &Self) -> Ordering {
        // Type inference seems to need a *lot* of help here!
        let k: for <'i> fn(&'i RouterStatus) -> &'i _  = |rs| &rs .r.identity;
        EncodeOrd::encode_cmp(k(self), k(other))
    }
}
