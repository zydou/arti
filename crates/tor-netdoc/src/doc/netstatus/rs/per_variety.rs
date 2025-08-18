//! router status entries - types that vary by document variety
//!
//! **This file is reincluded multiple times**,
//! by the macros in [`crate::doc::ns_per_variety_macros`],
//! once for votes, and once for each consensus flavour.
//! It is *not* a module `crate::doc::netstatus::rs::per_variety`.
//!
//! Each time this file is included by one of the macros mentioned above,
//! the `ns_***` macros (such as `ns_const_name!`) may expand to different values.
//!
//! See [`crate::doc::ns_per_variety_macros`].

use super::*;

use super::{FromRsString, GenericRouterStatus};
use crate::doc::netstatus::{
    ConsensusFlavor, NetstatusKwd, ParseRouterStatus, RelayFlags, RelayWeight, RouterStatus,
};
use crate::{Error, Result};
use crate::{parse::parser::Section, util::private::Sealed};
use std::net;

use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

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

// TODO: These methods should probably become, in whole or in part,
// methods on the RouterStatus trait.
impl ConsensusRouterStatus {
    /// Return an iterator of ORPort addresses for this routerstatus
    pub fn orport_addrs(&self) -> impl Iterator<Item = &net::SocketAddr> {
        self.addrs().iter()
    }
    /// Return the declared weight of this routerstatus in the directory.
    pub fn weight(&self) -> &RelayWeight {
        &self.rs.weight
    }
    /// Return the ORPort addresses of this routerstatus
    pub fn addrs(&self) -> &[net::SocketAddr] {
        &self.rs.addrs[..]
    }
    /// Return the protovers that this routerstatus says it implements.
    pub fn protovers(&self) -> &Protocols {
        &self.rs.protos
    }
    /// Return the nickname of this routerstatus.
    pub fn nickname(&self) -> &str {
        self.rs.nickname.as_str()
    }
    /// Return the relay flags of this routerstatus.
    pub fn flags(&self) -> &RelayFlags {
        &self.rs.flags
    }
    /// Return the version of this routerstatus.
    pub fn version(&self) -> Option<&crate::doc::netstatus::rs::Version> {
        self.rs.version.as_ref()
    }
    /// Return true if the ed25519 identity on this relay reflects a
    /// true consensus among the authorities.
    pub fn ed25519_id_is_usable(&self) -> bool {
        !self.rs.flags.contains(RelayFlags::NO_ED_CONSENSUS)
    }
    /// Return true if this routerstatus is listed with the BadExit flag.
    pub fn is_flagged_bad_exit(&self) -> bool {
        self.rs.flags.contains(RelayFlags::BAD_EXIT)
    }
    /// Return true if this routerstatus is listed with the v2dir flag.
    pub fn is_flagged_v2dir(&self) -> bool {
        self.rs.flags.contains(RelayFlags::V2DIR)
    }
    /// Return true if this routerstatus is listed with the Exit flag.
    pub fn is_flagged_exit(&self) -> bool {
        self.rs.flags.contains(RelayFlags::EXIT)
    }
    /// Return true if this routerstatus is listed with the Guard flag.
    pub fn is_flagged_guard(&self) -> bool {
        self.rs.flags.contains(RelayFlags::GUARD)
    }
    /// Return true if this routerstatus is listed with the HSDir flag.
    pub fn is_flagged_hsdir(&self) -> bool {
        self.rs.flags.contains(RelayFlags::HSDIR)
    }
    /// Return true if this routerstatus is listed with the Stable flag.
    pub fn is_flagged_stable(&self) -> bool {
        self.rs.flags.contains(RelayFlags::STABLE)
    }
    /// Return true if this routerstatus is listed with the Fast flag.
    pub fn is_flagged_fast(&self) -> bool {
        self.rs.flags.contains(RelayFlags::FAST)
    }
    /// Return true if this routerstatus is listed with the MiddleOnly flag.
    pub fn is_flagged_middle_only(&self) -> bool {
        self.rs.flags.contains(RelayFlags::MIDDLE_ONLY)
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
