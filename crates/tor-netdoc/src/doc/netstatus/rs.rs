//! Routerstatus-specific parts of networkstatus parsing.
//!
//! This is a private module; relevant pieces are re-exported by its
//! parent.

#[cfg(feature = "build_docs")]
pub(crate) mod build;
pub(crate) mod md;
pub(crate) mod plain;
pub(crate) mod vote;

use super::{ConsensusFlavor, ConsensusMethods, consensus_methods_comma_separated};
use crate::doc::netstatus::{
    IgnoredPublicationTimeSp, NetParams, NetstatusKwd, Protocols, RelayWeight, RelayWeightsItem,
    VoteRelayWeightsItem,
};
use crate::encode::{EncodeOrd, ItemEncoder};
use crate::parse::parser::Section;
use crate::parse2::ItemArgumentParseable;
use crate::types::misc::*;
use crate::types::policy::PortPolicy;
use crate::types::relay_flags::{self, DocRelayFlags, RelayFlag, RelayFlags};
use crate::types::version::TorVersion;
use crate::{Error, NetdocErrorKind as EK, Result};
use derive_deftly::Deftly;
use itertools::chain;
use std::cmp::Ordering;
use std::result::Result as StdResult;
use std::{net, time};
use tor_basic_utils::intern::{Intern, InternCache};
use tor_error::{Bug, internal};
use tor_llcrypto::pk::rsa::RsaIdentity;

/// A version as presented in a router status.
///
/// This can either be a parsed Tor version, or an unparsed string.
//
// TODO: This might want to merge, at some point, with routerdesc::RelayPlatform.
#[derive(Clone, Debug, Eq, PartialEq, Hash, derive_more::Display)]
#[non_exhaustive]
pub enum SoftwareVersion {
    /// A Tor version
    #[display("Tor {_0}")]
    CTor(TorVersion),

    /// A string we couldn't parse.
    ///
    /// This may be a C tor version that we couldn't parse,
    /// or some other software.
    Other(Intern<str>),
}

/// A cache of unparsable version strings.
///
/// We use this because we expect there not to be very many distinct versions of
/// relay software in existence.
// TODO DIRAUTH: Improve the caching here.
static OTHER_VERSION_CACHE: InternCache<str> = InternCache::new();

/// `m` item in votes
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:m>
///
/// This is different to the `m` line in microdesc consensuses.
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
#[derive(Debug, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Deftly)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[non_exhaustive]
pub struct RouterStatusMdDigestsVote {
    /// The methods for which this document is applicable.
    #[deftly(netdoc(with = consensus_methods_comma_separated))]
    pub consensus_methods: ConsensusMethods,

    /// The various hashes of this document.
    pub digests: Vec<IdentifiedDigest>,
}

impl std::str::FromStr for SoftwareVersion {
    // This needs to stay infallible: if any version is unparsable,
    // then we may reject a consensus needlessly,
    // since authorities copy versions from what relays say.
    type Err = void::Void;

    fn from_str(s: &str) -> StdResult<Self, void::Void> {
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

/// Implementation for parsing [`tor_protover::Protocols`] via its
/// [`from_str_c_compatible`](tor_protover::Protocols::from_str_c_compatible)
/// method.
///
/// We use this (for now) for parsing routerstatuses _and nothing else_.
/// It's okay to be strict about router descriptors and required/recommended versions,
/// but if we are strict about these lines in a routerstatus, we run the risk of rejecting
/// stuff that the C tor authorities thought was okay.
mod protovers_flexible {
    use tor_error::Bug;
    use tor_protover::Protocols;

    use crate::{
        encode::{ItemEncoder, ItemValueEncodable as _},
        parse2::{ErrorProblem, UnparsedItem},
    };

    /// Parse a [`Protocols`] using [`Protocols::from_str_c_compatible`].
    #[expect(clippy::needless_pass_by_value)]
    pub(super) fn from_unparsed(item: UnparsedItem<'_>) -> Result<Protocols, ErrorProblem> {
        item.check_no_object()?;
        Protocols::from_str_c_compatible(item.args_copy().into_remaining())
            .map_err(item.invalid_argument_handler("protocols"))
    }

    /// Encode a [`Protocols`] in the usual manner.
    ///
    /// (We have to define this because there is no "parse_with", only a "with" that overrides
    /// parsing _and_ encoding.)
    pub(super) fn write_item_value_onto(
        protocols: &Protocols,
        out: ItemEncoder,
    ) -> Result<(), Bug> {
        protocols.write_item_value_onto(out)
    }
}
