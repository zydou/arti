//! Routerstatus-specific parts of networkstatus parsing.
//!
//! This is a private module; relevant pieces are re-exported by its
//! parent.

#[cfg(feature = "build_docs")]
pub(crate) mod build;
pub(crate) mod md;
#[cfg(feature = "plain-consensus")]
pub(crate) mod plain;
#[cfg(feature = "ns-vote")]
pub(crate) mod vote;

use super::{ConsensusFlavor, ConsensusMethods};
use crate::doc::netstatus::NetstatusKwd;
use crate::doc::netstatus::{IgnoredPublicationTimeSp, Protocols, RelayWeight};
use crate::parse::parser::Section;
use crate::types::misc::*;
use crate::types::relay_flags::{self, DocRelayFlags, RelayFlag, RelayFlags};
use crate::types::version::TorVersion;
use crate::{Error, NetdocErrorKind as EK, Result};
use itertools::chain;
use std::sync::Arc;
use std::{net, time};
use tor_basic_utils::intern::InternCache;
use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;

#[cfg(feature = "parse2")]
use {
    super::consensus_methods_comma_separated, //
    derive_deftly::Deftly,
};

/// A version as presented in a router status.
///
/// This can either be a parsed Tor version, or an unparsed string.
//
// TODO: This might want to merge, at some point, with routerdesc::RelayPlatform.
#[derive(Clone, Debug, Eq, PartialEq, Hash, derive_more::Display)]
#[non_exhaustive]
pub enum SoftwareVersion {
    /// A Tor version
    CTor(TorVersion),
    /// A string we couldn't parse.
    Other(Arc<str>),
}

/// A cache of unparsable version strings.
///
/// We use this because we expect there not to be very many distinct versions of
/// relay software in existence.
static OTHER_VERSION_CACHE: InternCache<str> = InternCache::new();

/// `m` item in votes
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:m>
///
/// This is different to the `m` line in in microdesc consensuses.
/// Plain consensuses don't have `m` lines at all.
///
/// ### Non-invariants
///
///  * There may be overlapping or even contradictory information.
///  * It might not be sorted.
///    Users of the structure who need to emit reproducible document encodings.
///    must sort it.
///  * These non-invariants apply both within one instance of this struct,
///    and across multiple instances of it within a `RouterStatus`.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[cfg(feature = "ns-vote")]
#[cfg_attr(feature = "parse2", derive(Deftly), derive_deftly(ItemValueParseable))]
#[non_exhaustive]
pub struct RouterStatusMdDigestsVote {
    /// The methods for which this document is applicable.
    #[cfg_attr(
        feature = "parse2",
        deftly(netdoc(with = "consensus_methods_comma_separated"))
    )]
    pub consensus_methods: ConsensusMethods,

    /// The various hashes of this document.
    pub digests: Vec<IdentifiedDigest>,
}

impl std::str::FromStr for SoftwareVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut elts = s.splitn(3, ' ');
        if elts.next() == Some("Tor") {
            if let Some(Ok(v)) = elts.next().map(str::parse) {
                return Ok(SoftwareVersion::CTor(v));
            }
        }

        Ok(SoftwareVersion::Other(OTHER_VERSION_CACHE.intern_ref(s)))
    }
}

/// Helper to decode a document digest in the format in which it
/// appears in a given kind of routerstatus.
trait FromRsString: Sized {
    /// Try to decode the given object.
    fn decode(s: &str) -> Result<Self>;
}
