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

// Explicit parsing arrangements for document digest fields in `r` and `m` items.
//
// https://spec.torproject.org/dir-spec/consensus-formats.html#item:r
// https://spec.torproject.org/dir-spec/consensus-formats.html#item:m
// https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc
//
// The document digest moves about, and vote `m` items are even more exciting.
// This is for the benefit of the `with` annotations for theses two fields:
//
//  RouterStatus.r.doc_digest aka RouterStatusIntroItem.doc_digest
//  RouterStatus.m
//
// This would have been a bit easier if the various DocDigest types implemented parse2 traits,
// but they're just byte arrays and such impls would imply that byte arrays are always
// represented the same way in netdocs which is very far from being true.
// TODO consider introducing newtypes for routerdesc and microdesc hashes?
#[cfg(feature = "parse2")]
ns_choose! { (
    use doc_digest_parse2_real as doc_digest_parse2_r; // implemented here in rs/each_variety.rs
    use Ignored as doc_digest_parse2_m;
    use relay_flags::ConsensusRepr as VarietyRelayFlagsRepr;
) (
    use NotPresent as doc_digest_parse2_r;
    use doc_digest_parse2_real_item as doc_digest_parse2_m; // implemented in rs/md.rs
    use relay_flags::ConsensusRepr as VarietyRelayFlagsRepr;
) (
    use doc_digest_parse2_real as doc_digest_parse2_r; // implemented here in rs/each_variety.rs
    use RouterStatusMdDigestsVote as doc_digest_parse2_m;
    use relay_flags::VoteRepr as VarietyRelayFlagsRepr;
) }

/// Intro item for a router status entry
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:r>
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
/// `r` item.
#[cfg_attr(feature = "parse2", derive(Deftly), derive_deftly(ItemValueParseable))]
#[derive(Debug, Clone)]
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
    #[cfg_attr(feature = "parse2", deftly(netdoc(with = "doc_digest_parse2_r")))]
    pub doc_digest: ns_type!(DocDigest, NotPresent, DocDigest),
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
#[cfg_attr(feature = "parse2", derive(Deftly), derive_deftly(NetdocParseable))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouterStatus {
    /// `r` --- Introduce a routerstatus entry
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:r>
    /// (and, the the md version, which is different).
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
    #[cfg_attr(feature = "parse2", deftly(netdoc(with = "doc_digest_parse2_m")))]
    pub m: ns_type!(NotPresent, DocDigest, Vec<RouterStatusMdDigestsVote>),

    /// `a` --- Further router address(es) (IPv6)
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:a>
    /// (and, the the md version, which is different).
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    pub a: Vec<net::SocketAddr>,

    /// `s` --- Router status flags
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:s>
    #[cfg_attr(
        feature = "parse2",
        deftly(netdoc(keyword = "s")),
        deftly(netdoc(with = "relay_flags::Parser::<VarietyRelayFlagsRepr>"))
    )]
    pub flags: DocRelayFlags,

    /// `v` --- Relay's Tor software version
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:v>
    #[cfg_attr(feature = "parse2", deftly(netdoc(keyword = "v")))]
    pub version: Option<SoftwareVersion>,

    /// `pr` --- Subprotocol capabilities supported
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:v>
    #[cfg_attr(feature = "parse2", deftly(netdoc(keyword = "pr")))]
    pub protos: Protocols,

    /// `w` --- Bandwidth estimates
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:w>
    #[cfg_attr(feature = "parse2", deftly(netdoc(keyword = "w")))]
    pub weight: RelayWeight,
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

/// Netdoc format helper module for referenced doc digest field in `r` and `m`
///
/// This field is present in `r` items, except for md consensuses, where it's in `m`.
/// Hence the `_real`, which lets us swap it out for each variety.
#[cfg(feature = "parse2")]
pub(crate) mod doc_digest_parse2_real {
    use super::*;
    use crate::parse2::ArgumentError as AE;
    use crate::parse2::ArgumentStream;
    use std::result::Result;

    /// Parse a single argument
    pub(crate) fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<DocDigest, AE> {
        let data = args
            .next()
            .ok_or(AE::Missing)?
            .parse::<B64>()
            .map_err(|_| AE::Invalid)?;
        data.into_array().map_err(|_| AE::Invalid)
    }
}
