//! `dir-source` items, including the mutant `-legacy` version
//!
//! A `dir-source` line is normally an authority entry.
//! But it might also be a "superseded authority key entry".
//! That has a "nickname" ending in `-legacy` and appears only in consensuses.
//! (Note that `-legacy` is not legal syntax for a nickname.)
//!
//! <https://spec.torproject.org/dir-spec/consensus-formats.html#item:dir-source>
//!
//! This module will also handle the decoding of consensus authority sections,
//! which are fiddly because they can contain a mixture of things.
//!
//! <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>

use super::*;

/// Description of an authority's identity and address.
///
/// (Corresponds to a dir-source line.)
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:dir-source>
#[derive(Debug, Clone, Deftly)]
#[cfg_attr(feature = "parse2", derive_deftly(ItemValueParseable))]
#[cfg_attr(feature = "encode", derive_deftly(ItemValueEncodable))]
#[cfg_attr(not(any(feature = "parse2", feature = "encode")), derive_deftly_adhoc)]
#[derive_deftly(Constructor)]
#[allow(clippy::exhaustive_structs)]
pub struct DirSource {
    /// human-readable nickname for this authority.
    #[deftly(constructor)]
    pub nickname: Nickname,

    /// Fingerprint for the _authority_ identity key of this
    /// authority.
    ///
    /// This is the same key as the one that signs the authority's
    /// certificates.
    #[deftly(constructor)]
    pub identity: Fingerprint,

    /// IP address for the authority
    #[deftly(constructor)]
    pub hostname: InternetHost,

    /// IP address for the authority
    #[deftly(constructor(default = { net::Ipv6Addr::UNSPECIFIED.into() }))]
    pub ip: net::IpAddr,

    /// HTTP directory port for this authority
    pub dir_port: u16,

    /// OR port for this authority.
    pub or_port: u16,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}
