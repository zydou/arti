//! router status entry builders - items that vary by consensus flavor
//!
//! **This file is reincluded multiple times**,
//! by the macros in [`crate::doc::ns_variety_definition_macros`],
//! once for votes, and once for each consensus flavour.
//! It is *not* a module `crate::doc::netstatus::rs::each_flavor`.
//!
//! Each time this file is included by one of the macros mentioned above,
//! the `ns_***` macros (such as `ns_const_name!`) may expand to different values.
//!
//! See [`crate::doc::ns_variety_definition_macros`].

use super::*;

ns_use_this_variety! {
    use [crate::doc::netstatus::rs]::?::{DocDigest, RouterStatus, RouterStatusIntroItem};
}

/// A Builder object for creating a RouterStatus and adding it to a
/// consensus.
#[cfg_attr(docsrs, doc(cfg(feature = "build_docs")))]
#[derive(Debug, Clone)]
pub struct RouterStatusBuilder {
    /// See [`RouterStatus::nickname`].
    nickname: Option<String>,
    /// See [`RouterStatusIntroItem::identity`].
    identity: Option<RsaIdentity>,
    /// See [`RouterStatus::addrs`].
    addrs: Vec<SocketAddr>,
    /// See [`RouterStatus::doc_digest`].
    doc_digest: Option<DocDigest>,
    /// See [`RouterStatus::flags`].
    flags: RelayFlags,
    /// See [`RouterStatus::version`].
    version: Option<String>,
    /// See [`RouterStatus::protos`].
    protos: Option<Protocols>,
    /// See [`RouterStatus::weight`].
    weight: Option<RelayWeight>,
}

impl RouterStatusBuilder {
    /// Construct a new RouterStatusBuilder.
    pub(crate) fn new() -> Self {
        RouterStatusBuilder {
            nickname: None,
            identity: None,
            addrs: Vec::new(),
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
    /// Set the document digest for this routerstatus.
    ///
    /// This value is required.
    pub fn doc_digest(&mut self, doc_digest: DocDigest) -> &mut Self {
        self.doc_digest = Some(doc_digest);
        self
    }
    /// Replace the current flags in this routerstatus with `flags`.
    pub fn set_flags(&mut self, flags: impl Into<RelayFlags>) -> &mut Self {
        self.flags = flags.into();
        self
    }
    /// Make all the flags in `flags` become set on this routerstatus,
    /// in addition to the flags already set.
    pub fn add_flags(&mut self, flags: impl Into<RelayFlags>) -> &mut Self {
        self.flags |= flags.into();
        self
    }
    /// Make all the flags in `flags` become cleared on this routerstatus.
    #[cfg(feature = "testing")]
    pub fn clear_flags(&mut self, flags: impl Into<RelayFlags>) -> &mut Self {
        self.flags &= !flags.into();
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
    // TODO this function is identical to `build`; decide which one to keep
    pub(super) fn finish(&self) -> Result<RouterStatus> {
        let nickname = self.nickname.as_deref().unwrap_or("Unnamed").parse()?;
        let identity = self
            .identity
            .ok_or(Error::CannotBuild("Missing RSA identity"))?;
        if self.addrs.is_empty() {
            return Err(Error::CannotBuild("No addresses"));
        }
        let doc_digest = *self
            .doc_digest
            .as_ref()
            .ok_or(Error::CannotBuild("Missing document digest"))?;
        let protos = self
            .protos
            .as_ref()
            .ok_or(Error::CannotBuild("Missing protocols"))?
            .clone();
        let weight = self.weight.unwrap_or(RelayWeight::Unmeasured(0));
        let version = self.version.as_deref().map(str::parse).transpose()?;

        let mut ip = None;
        let a = self
            .addrs
            .iter()
            .filter_map(|a| match a {
                SocketAddr::V4(a) if ip.is_none() => {
                    ip = Some(a);
                    None
                }
                other => Some(*other),
            })
            .collect::<Vec<_>>();
        let ip = ip.ok_or_else(|| Error::CannotBuild("No IPv4 address"))?;

        ns_choose! { (
            let r_doc_digest = doc_digest;
            let m_doc_digest = NotPresent;
        ) (
            let r_doc_digest = NotPresent;
            let m_doc_digest = doc_digest;
        ) (
            compile_error!("no builder for votes");
        ) };

        Ok(RouterStatus {
            r: RouterStatusIntroItem {
                nickname,
                identity: Base64Fingerprint(identity),
                doc_digest: r_doc_digest,
                publication: IgnoredPublicationTimeSp,
                ip: *ip.ip(),
                or_port: ip.port(),
            },
            m: m_doc_digest,
            a,
            version,
            protos,
            flags: DocRelayFlags {
                known: self.flags,
                unknown: Unknown::new_discard(),
            },
            weight,
        })
    }

    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.x
    pub fn build_into(&self, builder: &mut ConsensusBuilder) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }

    /// Return a router status built by this object.
    // TODO this function is identical to `build`; decide which one to keep
    pub fn build(&self) -> Result<RouterStatus> {
        self.finish()
    }
}
