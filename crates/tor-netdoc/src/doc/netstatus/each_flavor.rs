//! consensus documents - items that vary by consensus flavor
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
    use [crate::doc::netstatus::rs]::?::{RouterStatus};
}
#[cfg(feature = "build_docs")]
ns_use_this_variety! {
    pub(crate) use [crate::doc::netstatus::build]::?::{ConsensusBuilder};
    pub use [crate::doc::netstatus::rs::build]::?::{RouterStatusBuilder};
}

/// A single consensus netstatus, as produced by the old parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Consensus {
    /// What kind of consensus document is this?  Absent in votes and
    /// in ns-flavored consensuses.
    pub flavor: ConsensusFlavor,
    /// The preamble, except for the intro item.
    pub preamble: Preamble,
    /// List of voters whose votes contributed to this consensus.
    pub voters: Vec<ConsensusVoterInfo>,
    /// A list of routerstatus entries for the relays on the network,
    /// with one entry per relay.
    ///
    /// These are currently ordered by the router's RSA identity, but this is not
    /// to be relied on, since we may want to even abolish RSA at some point!
    pub relays: Vec<RouterStatus>,
    /// Footer for the consensus object.
    pub footer: Footer,
}

impl Consensus {
    /// Return the Lifetime for this consensus.
    pub fn lifetime(&self) -> &Lifetime {
        &self.preamble.lifetime
    }

    /// Return a slice of all the routerstatus entries in this consensus.
    pub fn relays(&self) -> &[RouterStatus] {
        &self.relays[..]
    }

    /// Return a mapping from keywords to integers representing how
    /// to weight different kinds of relays in different path positions.
    pub fn bandwidth_weights(&self) -> &NetParams<i32> {
        &self.footer.weights
    }

    /// Return the map of network parameters that this consensus advertises.
    pub fn params(&self) -> &NetParams<i32> {
        &self.preamble.params
    }

    /// Return the latest shared random value, if the consensus
    /// contains one.
    pub fn shared_rand_cur(&self) -> Option<&SharedRandStatus> {
        self.preamble.shared_rand_current_value.as_ref()
    }

    /// Return the previous shared random value, if the consensus
    /// contains one.
    pub fn shared_rand_prev(&self) -> Option<&SharedRandStatus> {
        self.preamble.shared_rand_previous_value.as_ref()
    }

    /// Return a [`ProtoStatus`] that lists the network's current requirements and
    /// recommendations for the list of protocols that every relay must implement.  
    pub fn relay_protocol_status(&self) -> &ProtoStatus {
        &self.preamble.proto_statuses.relay
    }

    /// Return a [`ProtoStatus`] that lists the network's current requirements and
    /// recommendations for the list of protocols that every client must implement.
    pub fn client_protocol_status(&self) -> &ProtoStatus {
        &self.preamble.proto_statuses.client
    }

    /// Return a set of all known [`ProtoStatus`] values.
    pub fn protocol_statuses(&self) -> &Arc<ProtoStatuses> {
        &self.preamble.proto_statuses
    }
}

impl Consensus {
    /// Return a new ConsensusBuilder for building test consensus objects.
    ///
    /// This function is only available when the `build_docs` feature has
    /// been enabled.
    #[cfg(feature = "build_docs")]
    pub fn builder() -> ConsensusBuilder {
        ConsensusBuilder::new(RouterStatus::flavor())
    }

    /// Try to parse a single networkstatus document from a string.
    pub fn parse(s: &str) -> Result<(&str, &str, UncheckedConsensus)> {
        let mut reader = NetDocReader::new(s)?;
        Self::parse_from_reader(&mut reader).map_err(|e| e.within(s))
    }
    /// Extract a voter-info section from the reader; return
    /// Ok(None) when we are out of voter-info sections.
    fn take_voterinfo(
        r: &mut NetDocReader<'_, NetstatusKwd>,
    ) -> Result<Option<ConsensusVoterInfo>> {
        use NetstatusKwd::*;

        match r.peek() {
            None => return Ok(None),
            Some(e) if e.is_ok_with_kwd_in(&[RS_R, DIRECTORY_FOOTER]) => return Ok(None),
            _ => (),
        };

        let mut first_dir_source = true;
        // TODO: Extract this pattern into a "pause at second"???
        // Pause at the first 'r', or the second 'dir-source'.
        let mut p = r.pause_at(|i| match i {
            Err(_) => false,
            Ok(item) => {
                item.kwd() == RS_R
                    || if item.kwd() == DIR_SOURCE {
                        let was_first = first_dir_source;
                        first_dir_source = false;
                        !was_first
                    } else {
                        false
                    }
            }
        });

        let voter_sec = NS_VOTERINFO_RULES_CONSENSUS.parse(&mut p)?;
        let voter = ConsensusVoterInfo::from_section(&voter_sec)?;

        Ok(Some(voter))
    }

    /// Extract the footer (but not signatures) from the reader.
    fn take_footer(r: &mut NetDocReader<'_, NetstatusKwd>) -> Result<Footer> {
        use NetstatusKwd::*;
        let mut p = r.pause_at(|i| i.is_ok_with_kwd_in(&[DIRECTORY_SIGNATURE]));
        let footer_sec = NS_FOOTER_RULES.parse(&mut p)?;
        let footer = Footer::from_section(&footer_sec)?;
        Ok(footer)
    }

    /// Extract a routerstatus from the reader.  Return Ok(None) if we're
    /// out of routerstatus entries.
    fn take_routerstatus(r: &mut NetDocReader<'_, NetstatusKwd>) -> Result<Option<(Pos, RouterStatus)>> {
        use NetstatusKwd::*;
        match r.peek() {
            None => return Ok(None),
            Some(e) if e.is_ok_with_kwd_in(&[DIRECTORY_FOOTER]) => return Ok(None),
            _ => (),
        };

        let pos = r.pos();

        let mut first_r = true;
        let mut p = r.pause_at(|i| match i {
            Err(_) => false,
            Ok(item) => {
                item.kwd() == DIRECTORY_FOOTER
                    || if item.kwd() == RS_R {
                        let was_first = first_r;
                        first_r = false;
                        !was_first
                    } else {
                        false
                    }
            }
        });

        let rules = match RouterStatus::flavor() {
            ConsensusFlavor::Microdesc => &NS_ROUTERSTATUS_RULES_MDCON,
            ConsensusFlavor::Plain => &NS_ROUTERSTATUS_RULES_PLAIN,
        };

        let rs_sec = rules.parse(&mut p)?;
        let rs = RouterStatus::from_section(&rs_sec)?;
        Ok(Some((pos, rs)))
    }

    /// Extract an entire UncheckedConsensus from a reader.
    ///
    /// Returns the signed portion of the string, the remainder of the
    /// string, and an UncheckedConsensus.
    fn parse_from_reader<'a>(
        r: &mut NetDocReader<'a, NetstatusKwd>,
    ) -> Result<(&'a str, &'a str, UncheckedConsensus)> {
        use NetstatusKwd::*;
        let ((flavor, preamble), start_pos) = {
            let mut h = r.pause_at(|i| i.is_ok_with_kwd_in(&[DIR_SOURCE]));
            let preamble_sec = NS_HEADER_RULES_CONSENSUS.parse(&mut h)?;
            // Unwrapping should be safe because above `.parse` would have
            // returned an Error
            #[allow(clippy::unwrap_used)]
            let pos = preamble_sec.first_item().unwrap().offset_in(r.str()).unwrap();
            (Preamble::from_section(&preamble_sec)?, pos)
        };
        if RouterStatus::flavor() != flavor {
            return Err(EK::BadDocumentType.with_msg(format!(
                "Expected {:?}, got {:?}",
                RouterStatus::flavor(),
                flavor
            )));
        }

        let mut voters = Vec::new();

        while let Some(voter) = Self::take_voterinfo(r)? {
            voters.push(voter);
        }

        let mut relays: Vec<RouterStatus> = Vec::new();
        while let Some((pos, routerstatus)) = Self::take_routerstatus(r)? {
            if let Some(prev) = relays.last() {
                if prev.rsa_identity() >= routerstatus.rsa_identity() {
                    return Err(EK::WrongSortOrder.at_pos(pos));
                }
            }
            relays.push(routerstatus);
        }
        relays.shrink_to_fit();

        let footer = Self::take_footer(r)?;

        let consensus = Consensus {
            flavor,
            preamble,
            voters,
            relays,
            footer,
        };

        // Find the signatures.
        let mut first_sig: Option<Item<'_, NetstatusKwd>> = None;
        let mut signatures = Vec::new();
        for item in &mut *r {
            let item = item?;
            if item.kwd() != DIRECTORY_SIGNATURE {
                return Err(EK::UnexpectedToken
                    .with_msg(item.kwd().to_str())
                    .at_pos(item.pos()));
            }

            let sig = Signature::from_item(&item)?;
            if first_sig.is_none() {
                first_sig = Some(item);
            }
            signatures.push(sig);
        }

        let end_pos = match first_sig {
            None => return Err(EK::MissingToken.with_msg("directory-signature")),
            // Unwrap should be safe because `first_sig` was parsed from `r`
            #[allow(clippy::unwrap_used)]
            Some(sig) => sig.offset_in(r.str()).unwrap() + "directory-signature ".len(),
        };

        // Find the appropriate digest.
        let signed_str = &r.str()[start_pos..end_pos];
        let remainder = &r.str()[end_pos..];
        let (sha256, sha1) = match RouterStatus::flavor() {
            ConsensusFlavor::Plain => (
                None,
                Some(ll::d::Sha1::digest(signed_str.as_bytes()).into()),
            ),
            ConsensusFlavor::Microdesc => (
                Some(ll::d::Sha256::digest(signed_str.as_bytes()).into()),
                None,
            ),
        };
        let siggroup = SignatureGroup {
            sha256,
            sha1,
            signatures,
        };

        let unval = UnvalidatedConsensus {
            consensus,
            siggroup,
            n_authorities: None,
        };
        let lifetime = unval.consensus.preamble.lifetime.clone();
        let delay = unval.consensus.preamble.voting_delay.unwrap_or((0, 0));
        let dist_interval = time::Duration::from_secs(delay.1.into());
        let starting_time = *lifetime.valid_after - dist_interval;
        let timebound = TimerangeBound::new(unval, starting_time..*lifetime.valid_until);
        Ok((signed_str, remainder, timebound))
    }
}

impl Preamble {
    /// Extract the CommonPreamble members from a single preamble section.
    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<(ConsensusFlavor, Preamble)> {
        use NetstatusKwd::*;

        {
            // this unwrap is safe because if there is not at least one
            // token in the section, the section is unparsable.
            #[allow(clippy::unwrap_used)]
            let first = sec.first_item().unwrap();
            if first.kwd() != NETWORK_STATUS_VERSION {
                return Err(EK::UnexpectedToken
                    .with_msg(first.kwd().to_str())
                    .at_pos(first.pos()));
            }
        }

        let ver_item = sec.required(NETWORK_STATUS_VERSION)?;

        let version: u32 = ver_item.parse_arg(0)?;
        if version != 3 {
            return Err(EK::BadDocumentVersion.with_msg(version.to_string()));
        }
        let flavor = ConsensusFlavor::from_opt_name(ver_item.arg(1))?;

        let valid_after = sec
            .required(VALID_AFTER)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?
            .into();
        let fresh_until = sec
            .required(FRESH_UNTIL)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?
            .into();
        let valid_until = sec
            .required(VALID_UNTIL)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?
            .into();
        let lifetime = Lifetime::new(valid_after, fresh_until, valid_until)?;

        let client_versions = sec
            .maybe(CLIENT_VERSIONS)
            .args_as_str()
            .unwrap_or("")
            .split(',')
            .map(str::to_string)
            .collect();
        let server_versions = sec
            .maybe(SERVER_VERSIONS)
            .args_as_str()
            .unwrap_or("")
            .split(',')
            .map(str::to_string)
            .collect();

        let proto_statuses = {
            let client = ProtoStatus::from_section(
                sec,
                RECOMMENDED_CLIENT_PROTOCOLS,
                REQUIRED_CLIENT_PROTOCOLS,
            )?;
            let relay = ProtoStatus::from_section(
                sec,
                RECOMMENDED_RELAY_PROTOCOLS,
                REQUIRED_RELAY_PROTOCOLS,
            )?;
            Arc::new(ProtoStatuses { client, relay })
        };

        let params = sec.maybe(PARAMS).args_as_str().unwrap_or("").parse()?;

        let status: &str = sec.required(VOTE_STATUS)?.arg(0).unwrap_or("");
        if status != "consensus" {
            return Err(EK::BadDocumentType.err());
        }

        // We're ignoring KNOWN_FLAGS in the consensus.

        let consensus_method: u32 = sec.required(CONSENSUS_METHOD)?.parse_arg(0)?;

        let shared_rand_previous_value = sec
            .get(SHARED_RAND_PREVIOUS_VALUE)
            .map(SharedRandStatus::from_item)
            .transpose()?;

        let shared_rand_current_value = sec
            .get(SHARED_RAND_CURRENT_VALUE)
            .map(SharedRandStatus::from_item)
            .transpose()?;

        let voting_delay = if let Some(tok) = sec.get(VOTING_DELAY) {
            let n1 = tok.parse_arg(0)?;
            let n2 = tok.parse_arg(1)?;
            Some((n1, n2))
        } else {
            None
        };

        let preamble = Preamble {
            lifetime,
            client_versions,
            server_versions,
            proto_statuses,
            params,
            voting_delay,
            consensus_method,
            published: NotPresent,
            consensus_methods: NotPresent,
            shared_rand_previous_value,
            shared_rand_current_value,
        };

        Ok((flavor, preamble))
    }
}

/// A Microdesc consensus whose signatures have not yet been checked.
///
/// To validate this object, call set_n_authorities() on it, then call
/// check_signature() on that result with the set of certs that you
/// have.  Make sure only to provide authority certificates representing
/// real authorities!
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnvalidatedConsensus {
    /// The consensus object. We don't want to expose this until it's
    /// validated.
    pub consensus: Consensus,
    /// The signatures that need to be validated before we can call
    /// this consensus valid.
    pub siggroup: SignatureGroup,
    /// The total number of authorities that we believe in.  We need
    /// this information in order to validate the signatures, since it
    /// determines how many signatures we need to find valid in `siggroup`.
    pub n_authorities: Option<usize>,
}

impl UnvalidatedConsensus {
    /// Tell the unvalidated consensus how many authorities we believe in.
    ///
    /// Without knowing this number, we can't validate the signature.
    #[must_use]
    pub fn set_n_authorities(self, n_authorities: usize) -> Self {
        UnvalidatedConsensus {
            n_authorities: Some(n_authorities),
            ..self
        }
    }

    /// Return an iterator of all the certificate IDs that we might use
    /// to validate this consensus.
    pub fn signing_cert_ids(&self) -> impl Iterator<Item = AuthCertKeyIds> {
        match self.key_is_correct(&[]) {
            Ok(()) => Vec::new(),
            Err(missing) => missing,
        }
        .into_iter()
    }

    /// Return the lifetime of this unvalidated consensus
    pub fn peek_lifetime(&self) -> &Lifetime {
        self.consensus.lifetime()
    }

    /// Return true if a client who believes in exactly the provided
    /// set of authority IDs might might consider this consensus to be
    /// well-signed.
    ///
    /// (This is the case if the consensus claims to be signed by more than
    /// half of the authorities in the list.)
    pub fn authorities_are_correct(&self, authorities: &[&RsaIdentity]) -> bool {
        self.siggroup.could_validate(authorities)
    }

    /// Return the number of relays in this unvalidated consensus.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn n_relays(&self) -> usize {
        self.consensus.relays.len()
    }

    /// Modify the list of relays in this unvalidated consensus.
    ///
    /// A use case for this is long-lasting custom directories. To ensure Arti can still quickly
    /// build circuits when the directory gets old, a tiny churn file can be regularly obtained,
    /// listing no longer available Tor nodes, which can then be removed from the consensus.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn modify_relays<F>(&mut self, func: F)
    where
        F: FnOnce(&mut Vec<RouterStatus>),
    {
        func(&mut self.consensus.relays);
    }
}

impl ExternallySigned<Consensus> for UnvalidatedConsensus {
    type Key = [AuthCert];
    type KeyHint = Vec<AuthCertKeyIds>;
    type Error = Error;

    fn key_is_correct(&self, k: &Self::Key) -> result::Result<(), Self::KeyHint> {
        let (n_ok, missing) = self.siggroup.list_missing(k);
        match self.n_authorities {
            Some(n) if n_ok > (n / 2) => Ok(()),
            _ => Err(missing.iter().map(|cert| cert.key_ids).collect()),
        }
    }
    fn is_well_signed(&self, k: &Self::Key) -> result::Result<(), Self::Error> {
        match self.n_authorities {
            None => Err(Error::from(internal!(
                "Didn't set authorities on consensus"
            ))),
            Some(authority) => {
                if self.siggroup.validate(authority, k) {
                    Ok(())
                } else {
                    Err(EK::BadSignature.err())
                }
            }
        }
    }
    fn dangerously_assume_wellsigned(self) -> Consensus {
        self.consensus
    }
}

/// A Consensus object that has been parsed, but not checked for
/// signatures and timeliness.
pub type UncheckedConsensus = TimerangeBound<UnvalidatedConsensus>;

