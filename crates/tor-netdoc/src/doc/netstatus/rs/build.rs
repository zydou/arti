//! Provide builder functionality for routerstatuses.

use super::{GenericRouterStatus, MdConsensusRouterStatus};
use crate::doc::microdesc::MdDigest;
use crate::doc::netstatus::{ConsensusBuilder, RelayFlags, RelayWeight};
use crate::{Error, Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;

#[cfg(feature = "ns_consensus")]
use super::NsConsensusRouterStatus;
#[cfg(feature = "ns_consensus")]
use crate::doc::routerdesc::RdDigest;

/// A Builder object for creating a RouterStatus and adding it to a
/// consensus.
#[derive(Debug, Clone)]
pub struct RouterStatusBuilder<D> {
    /// See [`GenericRouterStatus::nickname`].
    nickname: Option<String>,
    /// See [`GenericRouterStatus::identity`].
    identity: Option<RsaIdentity>,
    /// See [`GenericRouterStatus::addrs`].
    addrs: Vec<SocketAddr>,
    /// See [`GenericRouterStatus::dir_port`].
    dir_port: u16, // never used, I think? XXXX
    /// See [`GenericRouterStatus::doc_digest`].
    doc_digest: Option<D>,
    /// See [`GenericRouterStatus::flags`].
    flags: RelayFlags,
    /// See [`GenericRouterStatus::version`].
    version: Option<String>,
    /// See [`GenericRouterStatus::protos`].
    protos: Option<Protocols>,
    /// See [`GenericRouterStatus::weight`].
    weight: Option<RelayWeight>,
}

impl<D: Clone> RouterStatusBuilder<D> {
    /// Construct a new RouterStatusBuilder.
    pub(crate) fn new() -> Self {
        RouterStatusBuilder {
            nickname: None,
            identity: None,
            addrs: Vec::new(),
            dir_port: 0,
            doc_digest: None,
            flags: RelayFlags::empty(),
            version: None,
            protos: None,
            weight: None,
        }
    }

    /// Set the nickname for this routerstatus.
    ///
    /// This value defaults to "Unnamed".
    pub fn nickname(&mut self, nickname: String) -> &mut Self {
        self.nickname = Some(nickname);
        self
    }

    /// Set the RSA identity for this routerstatus.
    ///
    /// (The Ed25519 identity is in the microdescriptor).
    ///
    /// This value is required.
    pub fn identity(&mut self, identity: RsaIdentity) -> &mut Self {
        self.identity = Some(identity);
        self
    }
    /// Add an OrPort at `addr` to this routerstatus.
    ///
    /// At least one value here is required.
    pub fn add_or_port(&mut self, addr: SocketAddr) -> &mut Self {
        self.addrs.push(addr);
        self
    }
    /// Set a directory port for this routerstatus.
    ///
    /// Nothing in Arti uses this value; it defaults to 0.
    pub fn dir_port(&mut self, dir_port: u16) -> &mut Self {
        self.dir_port = dir_port;
        self
    }
    /// Set the document digest for this routerstatus.
    ///
    /// This value is required.
    pub fn doc_digest(&mut self, doc_digest: D) -> &mut Self {
        self.doc_digest = Some(doc_digest);
        self
    }
    /// Replace the current flags in this routerstatus with `flags`.
    pub fn set_flags(&mut self, flags: RelayFlags) -> &mut Self {
        self.flags = flags;
        self
    }
    /// Make all the flags in `flags` become set on this routerstatus,
    /// in addition to the flags already set.
    pub fn add_flags(&mut self, flags: RelayFlags) -> &mut Self {
        self.flags |= flags;
        self
    }
    /// Set the version of the relay described in this routerstatus.
    ///
    /// This value is optional.
    pub fn version(&mut self, version: String) -> &mut Self {
        self.version = Some(version);
        self
    }
    /// Set the list of subprotocols supported by the relay described
    /// by this routerstatus.
    ///
    /// This value is required.
    pub fn protos(&mut self, protos: Protocols) -> &mut Self {
        self.protos = Some(protos);
        self
    }
    /// Set the weight of this routerstatus for random selection.
    ///
    /// This value is optional; it defaults to 0.
    pub fn weight(&mut self, weight: RelayWeight) -> &mut Self {
        self.weight = Some(weight);
        self
    }
    /// Try to build a GenericRouterStatus from this builder.
    fn finish(&self) -> Result<GenericRouterStatus<D>> {
        let nickname = self.nickname.clone().unwrap_or_else(|| "Unnamed".into());
        let identity = self
            .identity
            .ok_or(Error::CannotBuild("Missing RSA identity"))?;
        if self.addrs.is_empty() {
            return Err(Error::CannotBuild("No addresses"));
        }
        let or_port = self.addrs[0].port();
        let doc_digest = self
            .doc_digest
            .as_ref()
            .ok_or(Error::CannotBuild("Missing document digest"))?
            .clone();
        let protos = self
            .protos
            .as_ref()
            .ok_or(Error::CannotBuild("Missing protocols"))?
            .clone();
        let weight = self.weight.unwrap_or(RelayWeight::Unmeasured(0));

        Ok(GenericRouterStatus {
            nickname,
            identity,
            addrs: self.addrs.clone(),
            or_port,
            dir_port: self.dir_port,
            doc_digest,
            version: self.version.clone(),
            protos,
            flags: self.flags,
            weight,
        })
    }
}

#[cfg(feature = "ns_consensus")]
impl RouterStatusBuilder<RdDigest> {
    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build_into(
        &self,
        builder: &mut ConsensusBuilder<NsConsensusRouterStatus>,
    ) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }
    /// Return a router status built by this object.
    pub fn build(&self) -> Result<NsConsensusRouterStatus> {
        Ok(self.finish()?.into())
    }
}

impl RouterStatusBuilder<MdDigest> {
    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.x
    pub fn build_into(
        &self,
        builder: &mut ConsensusBuilder<MdConsensusRouterStatus>,
    ) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }

    /// Return a router status built by this object.
    pub fn build(&self) -> Result<MdConsensusRouterStatus> {
        Ok(self.finish()?.into())
    }
}
