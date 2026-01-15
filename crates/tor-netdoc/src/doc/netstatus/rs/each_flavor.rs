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

impl RouterStatus {
    /// Return an iterator of ORPort addresses for this routerstatus
    pub fn addrs(&self) -> impl Iterator<Item = net::SocketAddr> {
        chain!(
            [std::net::SocketAddrV4::new(self.r.ip, self.r.or_port).into()],
            self.a.iter().copied(),
        )
    }
    /// Return the declared weight of this routerstatus in the directory.
    pub fn weight(&self) -> &RelayWeight {
        &self.weight
    }
    /// Return the protovers that this routerstatus says it implements.
    pub fn protovers(&self) -> &Protocols {
        &self.protos
    }
    /// Return the nickname of this routerstatus.
    pub fn nickname(&self) -> &str {
        self.r.nickname.as_str()
    }
    /// Return the relay flags of this routerstatus.
    pub fn flags(&self) -> &RelayFlags {
        &self.flags.known
    }
    /// Return the version of this routerstatus.
    pub fn version(&self) -> Option<&crate::doc::netstatus::rs::SoftwareVersion> {
        self.version.as_ref()
    }
    /// Return true if the ed25519 identity on this relay reflects a
    /// true consensus among the authorities.
    pub fn ed25519_id_is_usable(&self) -> bool {
        !self.flags.contains(RelayFlag::NoEdConsensus)
    }
    /// Return true if this routerstatus is listed with the BadExit flag.
    pub fn is_flagged_bad_exit(&self) -> bool {
        self.flags.contains(RelayFlag::BadExit)
    }
    /// Return true if this routerstatus is listed with the v2dir flag.
    pub fn is_flagged_v2dir(&self) -> bool {
        self.flags.contains(RelayFlag::V2Dir)
    }
    /// Return true if this routerstatus is listed with the Exit flag.
    pub fn is_flagged_exit(&self) -> bool {
        self.flags.contains(RelayFlag::Exit)
    }
    /// Return true if this routerstatus is listed with the Guard flag.
    pub fn is_flagged_guard(&self) -> bool {
        self.flags.contains(RelayFlag::Guard)
    }
    /// Return true if this routerstatus is listed with the HSDir flag.
    pub fn is_flagged_hsdir(&self) -> bool {
        self.flags.contains(RelayFlag::HSDir)
    }
    /// Return true if this routerstatus is listed with the Stable flag.
    pub fn is_flagged_stable(&self) -> bool {
        self.flags.contains(RelayFlag::Stable)
    }
    /// Return true if this routerstatus is listed with the Fast flag.
    pub fn is_flagged_fast(&self) -> bool {
        self.flags.contains(RelayFlag::Fast)
    }
    /// Return true if this routerstatus is listed with the MiddleOnly flag.
    pub fn is_flagged_middle_only(&self) -> bool {
        self.flags.contains(RelayFlag::MiddleOnly)
    }
}

impl RouterStatus {
    /// Return RSA identity for the relay described by this RouterStatus
    pub fn rsa_identity(&self) -> &RsaIdentity {
        &self.r.identity
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
    pub(crate) fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<RouterStatus> {
        use NetstatusKwd::*;
        // R line
        let r_item = sec.required(RS_R)?;
        let nickname = r_item.required_arg(0)?.parse()?;
        let ident = r_item.required_arg(1)?;
        let identity = ident.parse::<Base64Fingerprint>()?;
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
        let ip = r_item.required_arg(4 + n_skip)?.parse::<net::Ipv4Addr>()?;
        let or_port = r_item.required_arg(5 + n_skip)?.parse::<u16>()?;
        let _ = r_item.required_arg(6 + n_skip)?.parse::<u16>()?;

        // main address and A lines.
        let a_items = sec.slice(RS_A);
        let a = a_items
            .iter()
            .map(|a_item| Ok(a_item.required_arg(0)?.parse::<net::SocketAddr>()?))
            .collect::<Result<Vec<_>>>()?;

        // S line
        //
        // Wrong for votes, but this code doesn't run for votes.
        let flags = DocRelayFlags::from_item_consensus(sec.required(RS_S)?)?;

        // V line
        let version = sec.maybe(RS_V).args_as_str().map(str::parse).transpose()?;

        // PR line
        let protos = {
            let tok = sec.required(RS_PR)?;
            tok.args_as_str()
                .parse::<Protocols>()
                .map_err(|e| EK::BadArgument.at_pos(tok.pos()).with_source(e))?
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

        ns_choose! { (
            let r_doc_digest = doc_digest;
            let m_doc_digest = NotPresent;
        ) (
            let r_doc_digest = NotPresent;
            let m_doc_digest = doc_digest;
        ) (
            let r_doc_digest = doc_digest;
            let m_doc_digest = NotPresent;
        ) };

        Ok(RouterStatus {
            r: RouterStatusIntroItem {
                nickname,
                identity,
                or_port,
                doc_digest: r_doc_digest,
                publication: IgnoredPublicationTimeSp,
                ip,
            },
            m: m_doc_digest,
            a,
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
