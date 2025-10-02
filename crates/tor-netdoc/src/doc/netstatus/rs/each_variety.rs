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

/// Intro item for a router status entry
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
    pub doc_digest: ns_type!( DocDigest, ArgumentNotPresent, DocDigest ),
    /// IPv4 address
    pub ip: std::net::Ipv4Addr,
    /// Relay port
    pub or_port: u16,
}

/// A single relay's status, in a network status document.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouterStatus {
    /// `r` item, introducing a routerstatus entry
    pub r: RouterStatusIntroItem,
    /// Digest of the document for this relay (md consensuses only)
    // We call this field `m` rather than `doc_digest` because it's not always the doc digest.
    // TODO SPEC in all but md consensuses the referenced document digest is in the `r` intro item
    pub m: ns_type!( Option<Ignored>, DocDigest, Option<Ignored> ),
    /// A list of address:port values where this relay can be reached.
    pub a: Vec<net::SocketAddr>,
    /// Flags applied by the authorities to this relay.
    pub flags: RelayFlags,
    /// Version of the software that this relay is running.
    pub version: Option<Version>,
    /// List of subprotocol versions supported by this relay.
    pub protos: Arc<Protocols>,
    /// Information about how to weight this relay when choosing a
    /// relay at random.
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
        ns_expr!(
            &self.r.doc_digest,
            &self.m,
            &self.r.doc_digest,
        )
    }
}
