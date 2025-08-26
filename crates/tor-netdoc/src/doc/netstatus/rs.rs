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

use super::ConsensusFlavor;
use crate::doc;
use crate::doc::netstatus::NetstatusKwd;
use crate::doc::netstatus::{Protocols, RelayFlags, RelayWeight};
use crate::parse::parser::Section;
use crate::types::misc::*;
use crate::types::version::TorVersion;
use crate::util::intern::InternCache;
use crate::{Error, NetdocErrorKind as EK, Result};
use std::sync::Arc;
use std::{net, time};
use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;

/// A version as presented in a router status.
///
/// This can either be a parsed Tor version, or an unparsed string.
//
// TODO: This might want to merge, at some point, with routerdesc::RelayPlatform.
#[derive(Clone, Debug, Eq, PartialEq, Hash, derive_more::Display)]
#[non_exhaustive]
pub enum Version {
    /// A Tor version
    Tor(TorVersion),
    /// A string we couldn't parse.
    Other(Arc<str>),
}

/// A cache of unparsable version strings.
///
/// We use this because we expect there not to be very many distinct versions of
/// relay software in existence.
static OTHER_VERSION_CACHE: InternCache<str> = InternCache::new();

impl std::str::FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut elts = s.splitn(3, ' ');
        if elts.next() == Some("Tor") {
            if let Some(Ok(v)) = elts.next().map(str::parse) {
                return Ok(Version::Tor(v));
            }
        }

        Ok(Version::Other(OTHER_VERSION_CACHE.intern_ref(s)))
    }
}

/// Helper to decode a document digest in the format in which it
/// appears in a given kind of routerstatus.
trait FromRsString: Sized {
    /// Try to decode the given object.
    fn decode(s: &str) -> Result<Self>;
}
