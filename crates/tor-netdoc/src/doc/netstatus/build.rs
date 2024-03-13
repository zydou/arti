//! Facilities to construct Consensus objects.
//!
//! (These are only for testing right now, since we don't yet
//! support signing or encoding.)

use super::rs::build::RouterStatusBuilder;
use super::{
    CommonHeader, Consensus, ConsensusFlavor, ConsensusHeader, ConsensusVoterInfo, DirSource,
    Footer, Lifetime, NetParams, ProtoStatus, RouterStatus, SharedRandStatus, SharedRandVal,
};

use crate::{BuildError as Error, BuildResult as Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::IpAddr;
use std::time::SystemTime;

/// A builder object used to construct a consensus.
///
/// Create one of these with the [`Consensus::builder`] method.
///
/// This facility is only enabled when the crate is built with
/// the `build_docs` feature.
#[cfg_attr(docsrs, doc(cfg(feature = "build_docs")))]
pub struct ConsensusBuilder<RS> {
    /// See [`CommonHeader::flavor`]
    flavor: ConsensusFlavor,
    /// See [`CommonHeader::lifetime`]
    lifetime: Option<Lifetime>,
    /// See [`CommonHeader::client_versions`]
    client_versions: Vec<String>,
    /// See [`CommonHeader::relay_versions`]
    relay_versions: Vec<String>,
    /// See [`CommonHeader::client_protos`]
    client_protos: ProtoStatus,
    /// See [`CommonHeader::relay_protos`]
    relay_protos: ProtoStatus,
    /// See [`CommonHeader::params`]
    params: NetParams<i32>,
    /// See [`CommonHeader::voting_delay`]
    voting_delay: Option<(u32, u32)>,
    /// See [`ConsensusHeader::consensus_method`]
    consensus_method: Option<u32>,
    /// See [`ConsensusHeader::shared_rand_prev`]
    shared_rand_prev: Option<SharedRandStatus>,
    /// See [`ConsensusHeader::shared_rand_cur`]
    shared_rand_cur: Option<SharedRandStatus>,
    /// See [`Consensus::voters`]
    voters: Vec<ConsensusVoterInfo>,
    /// See [`Consensus::relays`]
    relays: Vec<RS>,
    /// See [`Footer::weights`]
    weights: NetParams<i32>,
}

impl<RS> ConsensusBuilder<RS> {
    /// Construct a new ConsensusBuilder object.
    pub(crate) fn new(flavor: ConsensusFlavor) -> ConsensusBuilder<RS> {
        ConsensusBuilder {
            flavor,
            lifetime: None,
            client_versions: Vec::new(),
            relay_versions: Vec::new(),
            client_protos: ProtoStatus::default(),
            relay_protos: ProtoStatus::default(),
            params: NetParams::new(),
            voting_delay: None,
            consensus_method: None,
            shared_rand_prev: None,
            shared_rand_cur: None,
            voters: Vec::new(),
            relays: Vec::new(),
            weights: NetParams::new(),
        }
    }

    /// Set the lifetime of this consensus.
    ///
    /// This value is required.
    pub fn lifetime(&mut self, lifetime: Lifetime) -> &mut Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Add a single recommended Tor client version to this consensus.
    ///
    /// These values are optional for testing.
    pub fn add_client_version(&mut self, ver: String) -> &mut Self {
        self.client_versions.push(ver);
        self
    }
    /// Add a single recommended Tor relay version to this consensus.
    ///
    /// These values are optional for testing.
    pub fn add_relay_version(&mut self, ver: String) -> &mut Self {
        self.relay_versions.push(ver);
        self
    }
    /// Set the required client protocol versions for this consensus.
    ///
    /// This value defaults to "no protocol versions required."
    pub fn required_client_protos(&mut self, protos: Protocols) -> &mut Self {
        self.client_protos.required = protos;
        self
    }
    /// Set the recommended client protocol versions for this consensus.
    ///
    /// This value defaults to "no protocol versions recommended."
    pub fn recommended_client_protos(&mut self, protos: Protocols) -> &mut Self {
        self.client_protos.recommended = protos;
        self
    }
    /// Set the required relay protocol versions for this consensus.
    ///
    /// This value defaults to "no protocol versions required."
    pub fn required_relay_protos(&mut self, protos: Protocols) -> &mut Self {
        self.relay_protos.required = protos;
        self
    }
    /// Set the recommended client protocol versions for this consensus.
    ///
    /// This value defaults to "no protocol versions recommended."
    pub fn recommended_relay_protos(&mut self, protos: Protocols) -> &mut Self {
        self.relay_protos.recommended = protos;
        self
    }
    /// Set the value for a given consensus parameter by name.
    pub fn param<S>(&mut self, param: S, val: i32) -> &mut Self
    where
        S: Into<String>,
    {
        self.params.set(param.into(), val);
        self
    }
    /// Set the voting delays (in seconds) for this consensus.
    pub fn voting_delay(&mut self, vote_delay: u32, signature_delay: u32) -> &mut Self {
        self.voting_delay = Some((vote_delay, signature_delay));
        self
    }
    /// Set the declared consensus method for this consensus.
    ///
    /// This value is required.
    pub fn consensus_method(&mut self, consensus_method: u32) -> &mut Self {
        self.consensus_method = Some(consensus_method);
        self
    }
    /// Set the previous day's shared-random value for this consensus.
    ///
    /// This value is optional.
    pub fn shared_rand_prev(
        &mut self,
        n_reveals: u8,
        value: SharedRandVal,
        timestamp: Option<SystemTime>,
    ) -> &mut Self {
        self.shared_rand_prev = Some(SharedRandStatus {
            n_reveals,
            value,
            timestamp,
        });
        self
    }
    /// Set the current day's shared-random value for this consensus.
    ///
    /// This value is optional.
    pub fn shared_rand_cur(
        &mut self,
        n_reveals: u8,
        value: SharedRandVal,
        timestamp: Option<SystemTime>,
    ) -> &mut Self {
        self.shared_rand_cur = Some(SharedRandStatus {
            n_reveals,
            value,
            timestamp,
        });
        self
    }
    /// Set a named weight parameter for this consensus.
    pub fn weight<S>(&mut self, param: S, val: i32) -> &mut Self
    where
        S: Into<String>,
    {
        self.weights.set(param.into(), val);
        self
    }
    /// Replace all weight parameters for this consensus.
    pub fn weights(&mut self, weights: NetParams<i32>) -> &mut Self {
        self.weights = weights;
        self
    }
    /// Create a VoterInfoBuilder to add a voter to this builder.
    ///
    /// In theory these are required, but nothing asks for them.
    pub fn voter(&self) -> VoterInfoBuilder {
        VoterInfoBuilder::new()
    }

    /// Insert a single routerstatus into this builder.
    pub(crate) fn add_rs(&mut self, rs: RS) -> &mut Self {
        self.relays.push(rs);
        self
    }
}

impl<RS: RouterStatus + Clone> ConsensusBuilder<RS> {
    /// Create a RouterStatusBuilder to add a RouterStatus to this builder.
    ///
    /// You can make a consensus with no RouterStatus entries, but it
    /// won't actually be good for anything.
    pub fn rs(&self) -> RouterStatusBuilder<RS::DocumentDigest> {
        RouterStatusBuilder::new()
    }

    /// Try to create a consensus object from this builder.
    ///
    /// This object might not have all of the data that a valid
    /// consensus would have. Therefore, it should only be used for
    /// testing.
    pub fn testing_consensus(&self) -> Result<Consensus<RS>> {
        let lifetime = self
            .lifetime
            .as_ref()
            .ok_or(Error::CannotBuild("Missing lifetime."))?
            .clone();

        let hdr = CommonHeader {
            flavor: self.flavor,
            lifetime,
            client_versions: self.client_versions.clone(),
            relay_versions: self.relay_versions.clone(),
            client_protos: self.client_protos.clone(),
            relay_protos: self.relay_protos.clone(),
            params: self.params.clone(),
            voting_delay: self.voting_delay,
        };

        let consensus_method = self
            .consensus_method
            .ok_or(Error::CannotBuild("Missing consensus method."))?;

        let header = ConsensusHeader {
            hdr,
            consensus_method,
            shared_rand_prev: self.shared_rand_prev.clone(),
            shared_rand_cur: self.shared_rand_cur.clone(),
        };

        let footer = Footer {
            weights: self.weights.clone(),
        };

        let mut relays = self.relays.clone();
        relays.sort_by_key(|r| *r.rsa_identity());
        // TODO: check for duplicates?

        Ok(Consensus {
            header,
            voters: self.voters.clone(),
            relays,
            footer,
        })
    }
}

/// Builder object for constructing a [`ConsensusVoterInfo`]
pub struct VoterInfoBuilder {
    /// See [`DirSource::nickname`]
    nickname: Option<String>,
    /// See [`DirSource::identity`]
    identity: Option<RsaIdentity>,
    /// See [`DirSource::ip`]
    ip: Option<IpAddr>,
    /// See [`ConsensusVoterInfo::contact`]
    contact: Option<String>,
    /// See [`ConsensusVoterInfo::vote_digest`]
    vote_digest: Vec<u8>,
    /// See [`DirSource::or_port`]
    or_port: u16,
    /// See [`DirSource::dir_port`]
    dir_port: u16,
}

impl VoterInfoBuilder {
    /// Construct a new VoterInfoBuilder.
    pub(crate) fn new() -> Self {
        VoterInfoBuilder {
            nickname: None,
            identity: None,
            ip: None,
            contact: None,
            vote_digest: Vec::new(),
            or_port: 0,
            dir_port: 0,
        }
    }

    /// Set a nickname.
    ///
    /// This value is required.
    pub fn nickname(&mut self, nickname: String) -> &mut Self {
        self.nickname = Some(nickname);
        self
    }

    /// Set an RSA identity.
    ///
    /// This value is required.
    pub fn identity(&mut self, identity: RsaIdentity) -> &mut Self {
        self.identity = Some(identity);
        self
    }

    /// Set a IP-valued address.
    ///
    /// This value is required.
    pub fn ip(&mut self, ip: IpAddr) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    /// Set a contact line for this voter.
    ///
    /// This value is optional.
    pub fn contact(&mut self, contact: String) -> &mut Self {
        self.contact = Some(contact);
        self
    }

    /// Set the declared vote digest for this voter within a consensus.
    ///
    /// This value is required.
    pub fn vote_digest(&mut self, vote_digest: Vec<u8>) -> &mut Self {
        self.vote_digest = vote_digest;
        self
    }

    /// Set the declared OrPort for this voter.
    pub fn or_port(&mut self, or_port: u16) -> &mut Self {
        self.or_port = or_port;
        self
    }

    /// Set the declared DirPort for this voter.
    pub fn dir_port(&mut self, dir_port: u16) -> &mut Self {
        self.dir_port = dir_port;
        self
    }

    /// Add the voter that we've been building into the in-progress
    /// consensus of `builder`.
    pub fn build<RS>(&self, builder: &mut ConsensusBuilder<RS>) -> Result<()> {
        let nickname = self
            .nickname
            .as_ref()
            .ok_or(Error::CannotBuild("Missing nickname"))?
            .clone();
        let identity = self
            .identity
            .ok_or(Error::CannotBuild("Missing identity"))?;
        let ip = self.ip.ok_or(Error::CannotBuild("Missing IP"))?;
        let contact = self
            .contact
            .as_ref()
            .ok_or(Error::CannotBuild("Missing contact"))?
            .clone();
        if self.vote_digest.is_empty() {
            return Err(Error::CannotBuild("Missing vote digest"));
        }
        let dir_source = DirSource {
            nickname,
            identity,
            ip,
            dir_port: self.dir_port,
            or_port: self.or_port,
        };

        let info = ConsensusVoterInfo {
            dir_source,
            contact,
            vote_digest: self.vote_digest.clone(),
        };
        builder.voters.push(info);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::doc::netstatus::RelayFlags;

    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};

    #[test]
    fn consensus() {
        let now = SystemTime::now();
        let one_hour = Duration::new(3600, 0);

        let mut builder = crate::doc::netstatus::MdConsensus::builder();
        builder
            .lifetime(Lifetime::new(now, now + one_hour, now + 2 * one_hour).unwrap())
            .add_client_version("0.4.5.8".into())
            .add_relay_version("0.4.5.9".into())
            .required_client_protos("DirCache=2 LinkAuth=3".parse().unwrap())
            .required_relay_protos("DirCache=1".parse().unwrap())
            .recommended_client_protos("DirCache=6".parse().unwrap())
            .recommended_relay_protos("DirCache=5".parse().unwrap())
            .param("wombat", 7)
            .param("knish", 1212)
            .voting_delay(7, 8)
            .consensus_method(32)
            .shared_rand_prev(1, SharedRandVal([b'x'; 32]), None)
            .shared_rand_cur(1, SharedRandVal([b'y'; 32]), None)
            .weight("Wxy", 303)
            .weight("Wow", 999);

        builder
            .voter()
            .nickname("Fuzzy".into())
            .identity([15; 20].into())
            .ip("10.0.0.200".parse().unwrap())
            .contact("admin@fuzzy.example.com".into())
            .vote_digest((*b"1234").into())
            .or_port(9001)
            .dir_port(9101)
            .build(&mut builder)
            .unwrap();

        builder
            .rs()
            .nickname("Fred".into())
            .identity([155; 20].into())
            .add_or_port(SocketAddr::from(([10, 0, 0, 60], 9100)))
            .add_or_port("[f00f::1]:9200".parse().unwrap())
            .doc_digest([99; 32])
            .set_flags(RelayFlags::FAST)
            .add_flags(RelayFlags::STABLE | RelayFlags::V2DIR)
            .version("Arti 0.0.0".into())
            .protos("DirCache=7".parse().unwrap())
            .build_into(&mut builder)
            .unwrap();

        let _cons = builder.testing_consensus().unwrap();

        // TODO: Check actual members of `cons` above.
    }
}
