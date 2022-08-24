//! Implementation for the style of router descriptors used in
//! microdesc consensus documents.

use super::{FromRsString, GenericRouterStatus};
use crate::doc::microdesc::MdDigest;
use crate::doc::netstatus::{
    ConsensusFlavor, NetstatusKwd, ParseRouterStatus, RelayFlags, RelayWeight, RouterStatus,
};
use crate::types::misc::*;
use crate::{parse::parser::Section, util::private::Sealed};
use crate::{Error, Result};
use std::net;

use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

/// A single relay's status, as represented in a microdesc consensus.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    non_exhaustive
)]
#[derive(Debug, Clone)]
pub struct MdConsensusRouterStatus {
    /// Underlying generic routerstatus object.
    ///
    /// This is private because we don't want to leak that these two
    /// types have the same implementation "under the hood".
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    rs: GenericRouterStatus<MdDigest>,
}

impl From<GenericRouterStatus<MdDigest>> for MdConsensusRouterStatus {
    fn from(rs: GenericRouterStatus<MdDigest>) -> Self {
        MdConsensusRouterStatus { rs }
    }
}

super::implement_accessors! {MdConsensusRouterStatus}

impl MdConsensusRouterStatus {
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn md_digest(&self) -> &MdDigest {
        &self.rs.doc_digest
    }
}

impl Sealed for MdConsensusRouterStatus {}

impl RouterStatus for MdConsensusRouterStatus {
    type DocumentDigest = MdDigest;

    /// Return the expected microdescriptor digest for this routerstatus
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rs.identity
    }

    fn doc_digest(&self) -> &MdDigest {
        self.md_digest()
    }
}

impl ParseRouterStatus for MdConsensusRouterStatus {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Microdesc
    }

    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<MdConsensusRouterStatus> {
        let rs = GenericRouterStatus::from_section(sec, true)?;
        Ok(MdConsensusRouterStatus { rs })
    }
}

impl FromRsString for MdDigest {
    fn decode(s: &str) -> Result<MdDigest> {
        s.parse::<B64>()?
            .check_len(32..=32)?
            .as_bytes()
            .try_into()
            .map_err(|_| Error::from(internal!("correct length on digest, but unable to convert")))
    }
}
