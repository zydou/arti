//! router status entries - types that vary by document variety
//!
//! **This file is reincluded multiple times**,
//! by the macros in [`crate::doc::ns_variety_definition_macros`],
//! once for votes, and once for each consensus flavour.
//! It is *not* a module `crate::doc::netstatus::rs::per_variety`.
//!
//! Each time this file is included by one of the macros mentioned above,
//! the `ns_***` macros (such as `ns_const_name!`) may expand to different values.
//!
//! See [`crate::doc::ns_variety_definition_macros`].

use super::*;

use super::{FromRsString};
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
    rs: GenericRouterStatus,
}

impl From<GenericRouterStatus> for ConsensusRouterStatus {
    fn from(rs: GenericRouterStatus) -> Self {
        ConsensusRouterStatus { rs }
    }
}

/// Shared implementation of MdConsensusRouterStatus and NsConsensusRouterStatus.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    visibility::make(pub),
    non_exhaustive
)]
#[derive(Debug, Clone)]
// XXXX get rid of this type entirely!
struct GenericRouterStatus {
    /// The nickname for this relay.
    ///
    /// Nicknames can be used for convenience purpose, but no more:
    /// there is no mechanism to enforce their uniqueness.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) nickname: Nickname,
    /// Fingerprint of the old-style RSA identity for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) identity: RsaIdentity,
    /// A list of address:port values where this relay can be reached.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) addrs: Vec<net::SocketAddr>,
    /// Digest of the document for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) doc_digest: DocDigest,
    /// Flags applied by the authorities to this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) flags: RelayFlags,
    /// Version of the software that this relay is running.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) version: Option<Version>,
    /// List of subprotocol versions supported by this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) protos: Arc<Protocols>,
    /// Information about how to weight this relay when choosing a
    /// relay at random.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) weight: RelayWeight,
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

impl GenericRouterStatus {
    /// Parse a generic routerstatus from a section.
    ///
    /// Requires that the section obeys the right SectionRules,
    /// matching `consensus_flavor`.
    fn from_section(
        sec: &Section<'_, NetstatusKwd>,
        consensus_flavor: ConsensusFlavor,
    ) -> Result<GenericRouterStatus> {
        use NetstatusKwd::*;
        // R line
        let r_item = sec.required(RS_R)?;
        let nickname = r_item.required_arg(0)?.parse()?;
        let ident = r_item.required_arg(1)?.parse::<B64>()?;
        let identity = RsaIdentity::from_bytes(ident.as_bytes()).ok_or_else(|| {
            EK::BadArgument
                .at_pos(r_item.pos())
                .with_msg("Wrong identity length")
        })?;
        // Fields to skip in the "r" line.
        let n_skip = match consensus_flavor {
            ConsensusFlavor::Microdesc => 0,
            ConsensusFlavor::Plain => 1,
        };
        // We check that the published time is well-formed, but we never use it
        // for anything in a consensus document.
        let _ignore_published: time::SystemTime = {
            // TODO: It's annoying to have to do this allocation, since we
            // already have a slice that contains both of these arguments.
            // Instead, we could get a slice of arguments: we'd have to add
            // a feature for that.
            let mut p = r_item.required_arg(2 + n_skip)?.to_string();
            p.push(' ');
            p.push_str(r_item.required_arg(3 + n_skip)?);
            p.parse::<Iso8601TimeSp>()?.into()
        };
        let ipv4addr = r_item.required_arg(4 + n_skip)?.parse::<net::Ipv4Addr>()?;
        let or_port = r_item.required_arg(5 + n_skip)?.parse::<u16>()?;
        let _ = r_item.required_arg(6 + n_skip)?.parse::<u16>()?;

        // main address and A lines.
        let a_items = sec.slice(RS_A);
        let mut addrs = Vec::with_capacity(1 + a_items.len());
        addrs.push(net::SocketAddr::V4(net::SocketAddrV4::new(
            ipv4addr, or_port,
        )));
        for a_item in a_items {
            addrs.push(a_item.required_arg(0)?.parse::<net::SocketAddr>()?);
        }

        // S line
        let flags = RelayFlags::from_item(sec.required(RS_S)?)?;

        // V line
        let version = sec.maybe(RS_V).args_as_str().map(str::parse).transpose()?;

        // PR line
        let protos = {
            let tok = sec.required(RS_PR)?;
            doc::PROTOVERS_CACHE.intern(
                tok.args_as_str()
                    .parse::<Protocols>()
                    .map_err(|e| EK::BadArgument.at_pos(tok.pos()).with_source(e))?,
            )
        };

        // W line
        let weight = sec
            .get(RS_W)
            .map(RelayWeight::from_item)
            .transpose()?
            .unwrap_or_default();

        // No p line
        // no ID line

        // Try to find the document digest.  This is in different
        // places depending on the kind of consensus we're in.
        let doc_digest: DocDigest = match consensus_flavor {
            ConsensusFlavor::Microdesc => {
                // M line
                let m_item = sec.required(RS_M)?;
                DocDigest::decode(m_item.required_arg(0)?)?
            }
            ConsensusFlavor::Plain => DocDigest::decode(r_item.required_arg(2)?)?,
        };

        Ok(GenericRouterStatus {
            nickname,
            identity,
            addrs,
            doc_digest,
            flags,
            version,
            protos,
            weight,
        })
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
