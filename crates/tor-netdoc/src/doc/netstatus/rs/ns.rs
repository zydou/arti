//! Implementation for the style of router descriptors used in
//! old-style "ns" consensus documents.

ns_do_species_ns! {}

use super::{FromRsString, GenericRouterStatus};
use crate::doc::netstatus::{
    ConsensusFlavor, NetstatusKwd, ParseRouterStatus, RelayFlags, RelayWeight, RouterStatus,
};
use crate::doc::routerdesc::{RdDigest as DocDigest, DOC_DIGEST_LEN};
use crate::types::misc::*;
use crate::{Error, Result};
use crate::{parse::parser::Section, util::private::Sealed};
use std::net;

use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

/// The flavor
const FLAVOR: ConsensusFlavor = ConsensusFlavor::Ns;

/// A single relay's status, as represented in a consensus.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    non_exhaustive
)]
#[derive(Debug, Clone)]
pub struct ConsensusRouterStatus {
    /// Underlying generic routerstatus object.
    ///
    /// This is private because we don't want to leak that these two
    /// types have the same implementation "under the hood".
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    rs: GenericRouterStatus<DocDigest>,
}

impl From<GenericRouterStatus<DocDigest>> for ConsensusRouterStatus {
    fn from(rs: GenericRouterStatus<DocDigest>) -> Self {
        ConsensusRouterStatus { rs }
    }
}

super::implement_accessors! {ConsensusRouterStatus}

impl ConsensusRouterStatus {
    /// Return the expected router descriptor digest for this routerstatus
    pub fn rd_digest(&self) -> &DocDigest {
        self.doc_digest()
    }
}

impl Sealed for ConsensusRouterStatus {}

impl RouterStatus for ConsensusRouterStatus {
    type DocumentDigest = DocDigest;

    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rs.identity
    }

    fn doc_digest(&self) -> &DocDigest {
        &self.rs.doc_digest
    }
}

impl ParseRouterStatus for ConsensusRouterStatus {
    fn flavor() -> ConsensusFlavor {
        FLAVOR
    }

    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<ConsensusRouterStatus> {
        let rs = GenericRouterStatus::from_section(sec, FLAVOR)?;
        Ok(ConsensusRouterStatus { rs })
    }
}

impl FromRsString for DocDigest {
    fn decode(s: &str) -> Result<DocDigest> {
        s.parse::<B64>()?
            .check_len(DOC_DIGEST_LEN..=DOC_DIGEST_LEN)?
            .as_bytes()
            .try_into()
            .map_err(|_| Error::from(internal!("correct length on digest, but unable to convert")))
    }
}
