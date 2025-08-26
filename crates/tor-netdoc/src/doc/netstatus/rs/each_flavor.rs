//! router status entries - items that vary by consensus flavor
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

// TODO: These methods should probably become, in whole or in part,
// methods on the RouterStatus trait.
impl RouterStatus {
    /// Return an iterator of ORPort addresses for this routerstatus
    pub fn orport_addrs(&self) -> impl Iterator<Item = &net::SocketAddr> {
        self.addrs().iter()
    }
    /// Return the declared weight of this routerstatus in the directory.
    pub fn weight(&self) -> &RelayWeight {
        &self.weight
    }
    /// Return the ORPort addresses of this routerstatus
    pub fn addrs(&self) -> &[net::SocketAddr] {
        &self.addrs[..]
    }
    /// Return the protovers that this routerstatus says it implements.
    pub fn protovers(&self) -> &Protocols {
        &self.protos
    }
    /// Return the nickname of this routerstatus.
    pub fn nickname(&self) -> &str {
        self.nickname.as_str()
    }
    /// Return the relay flags of this routerstatus.
    pub fn flags(&self) -> &RelayFlags {
        &self.flags
    }
    /// Return the version of this routerstatus.
    pub fn version(&self) -> Option<&crate::doc::netstatus::rs::Version> {
        self.version.as_ref()
    }
    /// Return true if the ed25519 identity on this relay reflects a
    /// true consensus among the authorities.
    pub fn ed25519_id_is_usable(&self) -> bool {
        !self.flags.contains(RelayFlags::NO_ED_CONSENSUS)
    }
    /// Return true if this routerstatus is listed with the BadExit flag.
    pub fn is_flagged_bad_exit(&self) -> bool {
        self.flags.contains(RelayFlags::BAD_EXIT)
    }
    /// Return true if this routerstatus is listed with the v2dir flag.
    pub fn is_flagged_v2dir(&self) -> bool {
        self.flags.contains(RelayFlags::V2DIR)
    }
    /// Return true if this routerstatus is listed with the Exit flag.
    pub fn is_flagged_exit(&self) -> bool {
        self.flags.contains(RelayFlags::EXIT)
    }
    /// Return true if this routerstatus is listed with the Guard flag.
    pub fn is_flagged_guard(&self) -> bool {
        self.flags.contains(RelayFlags::GUARD)
    }
    /// Return true if this routerstatus is listed with the HSDir flag.
    pub fn is_flagged_hsdir(&self) -> bool {
        self.flags.contains(RelayFlags::HSDIR)
    }
    /// Return true if this routerstatus is listed with the Stable flag.
    pub fn is_flagged_stable(&self) -> bool {
        self.flags.contains(RelayFlags::STABLE)
    }
    /// Return true if this routerstatus is listed with the Fast flag.
    pub fn is_flagged_fast(&self) -> bool {
        self.flags.contains(RelayFlags::FAST)
    }
    /// Return true if this routerstatus is listed with the MiddleOnly flag.
    pub fn is_flagged_middle_only(&self) -> bool {
        self.flags.contains(RelayFlags::MIDDLE_ONLY)
    }
}

impl RouterStatus {
    /// Return RSA identity for the relay described by this RouterStatus
    pub fn rsa_identity(&self) -> &RsaIdentity {
        &self.identity
    }

    /// Return the digest of the document identified by this
    /// routerstatus.
    pub fn doc_digest(&self) -> &DocDigest {
        &self.doc_digest
    }

    /// Return the networkstatus consensus flavor in which this
    /// routerstatus appears.
    pub(crate) fn flavor() -> ConsensusFlavor {
        FLAVOR
    }

    /// Parse a generic routerstatus from a section.
    ///
    /// Requires that the section obeys the right SectionRules,
    /// matching `consensus_flavor`.
    pub(crate) fn from_section(
        sec: &Section<'_, NetstatusKwd>,
    ) -> Result<RouterStatus> {
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
        let n_skip = match FLAVOR {
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
        let doc_digest: DocDigest = match FLAVOR {
            ConsensusFlavor::Microdesc => {
                // M line
                let m_item = sec.required(RS_M)?;
                DocDigest::decode(m_item.required_arg(0)?)?
            }
            ConsensusFlavor::Plain => DocDigest::decode(r_item.required_arg(2)?)?,
        };

        Ok(RouterStatus {
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
