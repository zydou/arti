//! Implementation for the style of router descriptors used in
//! old-style "ns" consensus documents.

use super::{FromRsString, GenericRouterStatus};
use crate::doc::netstatus::{
    ConsensusFlavor, NetstatusKwd, ParseRouterStatus, RelayFlags, RelayWeight, RouterStatus,
};
use crate::doc::routerdesc::RdDigest;
use crate::types::misc::*;
use crate::{parse::parser::Section, util::private::Sealed};
use crate::{Error, Result};
use std::net;

use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

/// A single relay's status, as represented in a "ns" consensus.
///
/// Only available if `tor-netdoc` is built with the `ns_consensus` feature.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    non_exhaustive
)]
#[cfg_attr(docsrs, doc(cfg(feature = "ns_consensus")))]
#[derive(Debug, Clone)]
pub struct NsConsensusRouterStatus {
    /// Underlying generic routerstatus object.
    ///
    /// This is private because we don't want to leak that these two
    /// types have the same implementation "under the hood".
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    rs: GenericRouterStatus<RdDigest>,
}

impl From<GenericRouterStatus<RdDigest>> for NsConsensusRouterStatus {
    fn from(rs: GenericRouterStatus<RdDigest>) -> Self {
        NsConsensusRouterStatus { rs }
    }
}

super::implement_accessors! {NsConsensusRouterStatus}

impl NsConsensusRouterStatus {
    /// Return the expected router descriptor digest for this routerstatus
    pub fn rd_digest(&self) -> &RdDigest {
        &self.rs.doc_digest
    }
}

impl Sealed for NsConsensusRouterStatus {}

impl RouterStatus for NsConsensusRouterStatus {
    type DocumentDigest = RdDigest;

    /// Return the expected microdescriptor digest for this routerstatus
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rs.identity
    }

    fn doc_digest(&self) -> &RdDigest {
        self.rd_digest()
    }
}

impl ParseRouterStatus for NsConsensusRouterStatus {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Ns
    }

    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<NsConsensusRouterStatus> {
        let rs = GenericRouterStatus::from_section(sec, ConsensusFlavor::Ns)?;
        Ok(NsConsensusRouterStatus { rs })
    }
}

impl FromRsString for RdDigest {
    fn decode(s: &str) -> Result<RdDigest> {
        s.parse::<B64>()?
            .check_len(20..=20)?
            .as_bytes()
            .try_into()
            .map_err(|_| Error::from(internal!("correct length on digest, but unable to convert")))
    }
}
