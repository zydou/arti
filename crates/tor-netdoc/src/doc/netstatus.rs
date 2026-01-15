//! Parsing implementation for networkstatus documents.
//!
//! In Tor, a networkstatus documents describes a complete view of the
//! relays in the network: how many there are, how to contact them,
//! and so forth.
//!
//! A networkstatus document can either be a "votes" -- an authority's
//! view of the network, used as input to the voting process -- or a
//! "consensus" -- a combined view of the network based on multiple
//! authorities' votes, and signed by multiple authorities.
//!
//! A consensus document can itself come in two different flavors: a
//! plain (unflavoured) consensus has references to router descriptors, and
//! a "microdesc"-flavored consensus ("md") has references to
//! microdescriptors.
//!
//! To keep an up-to-date view of the network, clients download
//! microdescriptor-flavored consensuses periodically, and then
//! download whatever microdescriptors the consensus lists that the
//! client doesn't already have.
//!
//! For full information about the network status format, see
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! # Limitations
//!
//! NOTE: The consensus format has changes time, using a
//! "consensus-method" mechanism.  This module is does not yet handle all
//! all historical consensus-methods.
//!
//! NOTE: This module _does_ parse some fields that are not in current
//! use, like relay nicknames, and the "published" times on
//! microdescriptors. We should probably decide whether we actually
//! want to do this.
//!
//! TODO: This module doesn't implement vote parsing at all yet.
//!
//! TODO: This module doesn't implement plain consensuses.
//!
//! TODO: More testing is needed!
//!
//! TODO: There should be accessor functions for most of the fields here.
//! As with the other tor-netdoc types, I'm deferring those till I know what
//! they should be.

mod rs;

pub mod md;
#[cfg(feature = "plain-consensus")]
pub mod plain;
#[cfg(feature = "ns-vote")]
pub mod vote;

#[cfg(feature = "build_docs")]
mod build;

#[cfg(feature = "parse2")]
use {
    crate::parse2::{self, ArgumentStream}, //
};

#[cfg(feature = "parse2")]
pub use {
    parse2_impls::ProtoStatusesNetdocParseAccumulator, //
};

use crate::doc::authcert::{AuthCert, AuthCertKeyIds};
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules, SectionRulesBuilder};
use crate::parse::tokenize::{Item, ItemResult, NetDocReader};
use crate::types::misc::*;
use crate::util::PeekableIterator;
use crate::{Error, KeywordEncodable, NetdocErrorKind as EK, NormalItemArgument, Pos, Result};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display};
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Arc;
use std::{net, result, time};
use tor_error::{HasKind, internal};
use tor_protover::Protocols;

use derive_deftly::{Deftly, define_derive_deftly};
use digest::Digest;
use std::sync::LazyLock;
use tor_checkable::{ExternallySigned, timed::TimerangeBound};
use tor_llcrypto as ll;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::{Deserialize, Deserializer};

#[cfg(feature = "build_docs")]
pub use build::MdConsensusBuilder;
#[cfg(all(feature = "build_docs", feature = "plain-consensus"))]
pub use build::PlainConsensusBuilder;
#[cfg(feature = "build_docs")]
ns_export_each_flavor! {
    ty: RouterStatusBuilder;
}

ns_export_each_variety! {
    ty: RouterStatus, Preamble;
}

#[deprecated]
#[cfg(feature = "ns_consensus")]
pub use PlainConsensus as NsConsensus;
#[deprecated]
#[cfg(feature = "ns_consensus")]
pub use PlainRouterStatus as NsRouterStatus;
#[deprecated]
#[cfg(feature = "ns_consensus")]
pub use UncheckedPlainConsensus as UncheckedNsConsensus;
#[deprecated]
#[cfg(feature = "ns_consensus")]
pub use UnvalidatedPlainConsensus as UnvalidatedNsConsensus;

#[cfg(feature = "ns-vote")]
pub use rs::{RouterStatusMdDigestsVote, SoftwareVersion};

/// `publiscation` field in routerstatus entry intro item other than in votes
///
/// Two arguments which are both ignored.
/// This used to be an ISO8601 timestamp in anomalous two-argument format.
///
/// Nowadays, according to the spec, it can be a dummy value.
/// So it can be a unit type.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:r>,
/// except in votes which use [`Iso8601TimeSp`] instead.
///
/// **Not the same as** the `published` item:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct IgnoredPublicationTimeSp;

/// The lifetime of a networkstatus document.
///
/// In a consensus, this type describes when the consensus may safely
/// be used.  In a vote, this type describes the proposed lifetime for a
/// consensus.
///
/// Aggregate of three netdoc preamble fields.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Lifetime)]
#[cfg_attr(feature = "parse2", derive_deftly(NetdocParseableFields))]
pub struct Lifetime {
    /// `valid-after` --- Time at which the document becomes valid
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// (You might see a consensus a little while before this time,
    /// since voting tries to finish up before the.)
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    valid_after: Iso8601TimeSp,
    /// `fresh-until` --- Time after which there is expected to be a better version
    /// of this consensus
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// You can use the consensus after this time, but there is (or is
    /// supposed to be) a better one by this point.
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    fresh_until: Iso8601TimeSp,
    /// `valid-until` --- Time after which this consensus is expired.
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// You should try to get a better consensus after this time,
    /// though it's okay to keep using this one if no more recent one
    /// can be found.
    #[cfg_attr(feature = "parse2", deftly(netdoc(single_arg)))]
    valid_until: Iso8601TimeSp,
}

define_derive_deftly! {
    /// Bespoke derive for `Lifetime`, for `new` and accessors
    Lifetime:

    impl Lifetime {
        /// Construct a new Lifetime.
        pub fn new(
            $( $fname: time::SystemTime, )
        ) -> Result<Self> {
            // Make this now because otherwise literal `valid_after` here in the body
            // has the wrong span - the compiler refuses to look at the argument.
            // But we can refer to the field names.
            let self_ = Lifetime {
                $( $fname: $fname.into(), )
            };
            if self_.valid_after < self_.fresh_until && self_.fresh_until < self_.valid_until {
                Ok(self_)
            } else {
                Err(EK::InvalidLifetime.err())
            }
        }
      $(
        ${fattrs doc}
        pub fn $fname(&self) -> time::SystemTime {
            *self.$fname
        }
      )
        /// Return true if this consensus is officially valid at the provided time.
        pub fn valid_at(&self, when: time::SystemTime) -> bool {
            *self.valid_after <= when && when <= *self.valid_until
        }

        /// Return the voting period implied by this lifetime.
        ///
        /// (The "voting period" is the amount of time in between when a consensus first
        /// becomes valid, and when the next consensus is expected to become valid)
        pub fn voting_period(&self) -> time::Duration {
            let valid_after = self.valid_after();
            let fresh_until = self.fresh_until();
            fresh_until
                .duration_since(valid_after)
                .expect("Mis-formed lifetime")
        }
    }
}
use derive_deftly_template_Lifetime;

/// A single consensus method
///
/// These are integers, but we don't do arithmetic on them.
///
/// As defined here:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:consensus-methods>
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavor:microdesc>
///
/// As used in a `consensus-method` item:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:consensus-method>
#[derive(Debug, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Copy)] //
#[derive(derive_more::From, derive_more::Into, derive_more::Display, derive_more::FromStr)]
pub struct ConsensusMethod(u32);
impl NormalItemArgument for ConsensusMethod {}

/// A set of consensus methods
///
/// Implements `ItemValueParseable` as required for `consensus-methods`,
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:consensus-methods>
///
/// There is also [`consensus_methods_comma_separated`] for `m` lines in votes.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "parse2", derive(Deftly), derive_deftly(ItemValueParseable))]
#[non_exhaustive]
pub struct ConsensusMethods {
    /// Consensus methods.
    pub methods: BTreeSet<ConsensusMethod>,
}

/// Module for use with parse2's `with`, to parse one argument of comma-separated consensus methods
///
/// As found in an `m` item in a vote:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:m>
#[cfg(feature = "parse2")]
pub mod consensus_methods_comma_separated {
    use super::*;
    use parse2::ArgumentError as AE;
    use std::result::Result;

    /// Parse
    pub fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<ConsensusMethods, AE> {
        let mut methods = BTreeSet::new();
        for ent in args.next().ok_or(AE::Missing)?.split(',') {
            let ent = ent.parse().map_err(|_| AE::Invalid)?;
            if !methods.insert(ent) {
                return Err(AE::Invalid);
            }
        }
        Ok(ConsensusMethods { methods })
    }
}

/// A set of named network parameters.
///
/// These are used to describe current settings for the Tor network,
/// current weighting parameters for path selection, and so on.  They're
/// encoded with a space-separated K=V format.
///
/// A `NetParams<i32>` is part of the validated directory manager configuration,
/// where it is built (in the builder-pattern sense) from a transparent HashMap.
///
/// As found in `params` in a network status:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:params>
///
/// The same syntax is also used, and this type used for parsing, in various other places,
/// for example routerstatus entry `w` items (bandwith weights):
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:w>
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct NetParams<T> {
    /// Map from keys to values.
    params: HashMap<String, T>,
}

impl<T> NetParams<T> {
    /// Create a new empty list of NetParams.
    #[allow(unused)]
    pub fn new() -> Self {
        NetParams {
            params: HashMap::new(),
        }
    }
    /// Retrieve a given network parameter, if it is present.
    pub fn get<A: AsRef<str>>(&self, v: A) -> Option<&T> {
        self.params.get(v.as_ref())
    }
    /// Return an iterator over all key value pairs in an arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &T)> {
        self.params.iter()
    }
    /// Set or replace the value of a network parameter.
    pub fn set(&mut self, k: String, v: T) {
        self.params.insert(k, v);
    }
}

impl<K: Into<String>, T> FromIterator<(K, T)> for NetParams<T> {
    fn from_iter<I: IntoIterator<Item = (K, T)>>(i: I) -> Self {
        NetParams {
            params: i.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }
}

impl<T> std::iter::Extend<(String, T)> for NetParams<T> {
    fn extend<I: IntoIterator<Item = (String, T)>>(&mut self, iter: I) {
        self.params.extend(iter);
    }
}

impl<'de, T> Deserialize<'de> for NetParams<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let params = HashMap::deserialize(deserializer)?;
        Ok(NetParams { params })
    }
}

/// A list of subprotocol versions that implementors should/must provide.
///
/// This struct represents a pair of (optional) items:
/// `recommended-FOO-protocols` and `required-FOO-protocols`.
///
/// Each consensus has two of these: one for relays, and one for clients.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:required-relay-protocols>
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProtoStatus {
    /// Set of protocols that are recommended; if we're missing a protocol
    /// in this list we should warn the user.
    ///
    /// `recommended-client-protocols` or `recommended-relay-protocols`
    recommended: Protocols,
    /// Set of protocols that are required; if we're missing a protocol
    /// in this list we should refuse to start.
    ///
    /// `required-client-protocols` or `required-relay-protocols`
    required: Protocols,
}

impl ProtoStatus {
    /// Check whether the list of supported protocols
    /// is sufficient to satisfy this list of recommendations and requirements.
    ///
    /// If any required protocol is missing, returns [`ProtocolSupportError::MissingRequired`].
    ///
    /// Otherwise, if no required protocol is missing, but some recommended protocol is missing,
    /// returns [`ProtocolSupportError::MissingRecommended`].
    ///
    /// Otherwise, if no recommended or required protocol is missing, returns `Ok(())`.
    pub fn check_protocols(
        &self,
        supported_protocols: &Protocols,
    ) -> StdResult<(), ProtocolSupportError> {
        // Required protocols take precedence, so we check them first.
        let missing_required = self.required.difference(supported_protocols);
        if !missing_required.is_empty() {
            return Err(ProtocolSupportError::MissingRequired(missing_required));
        }
        let missing_recommended = self.recommended.difference(supported_protocols);
        if !missing_recommended.is_empty() {
            return Err(ProtocolSupportError::MissingRecommended(
                missing_recommended,
            ));
        }

        Ok(())
    }
}

/// A subprotocol that is recommended or required in the consensus was not present.
#[derive(Clone, Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum ProtocolSupportError {
    /// At least one required protocol was not in our list of supported protocols.
    #[error("Required protocols are not implemented: {0}")]
    MissingRequired(Protocols),

    /// At least one recommended protocol was not in our list of supported protocols.
    ///
    /// Also implies that no _required_ protocols were missing.
    #[error("Recommended protocols are not implemented: {0}")]
    MissingRecommended(Protocols),
}

impl ProtocolSupportError {
    /// Return true if the suggested behavior for this error is a shutdown.
    pub fn should_shutdown(&self) -> bool {
        matches!(self, Self::MissingRequired(_))
    }
}

impl HasKind for ProtocolSupportError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::SoftwareDeprecated
    }
}

/// A set of recommended and required protocols when running
/// in various scenarios.
///
/// Represents the collection of four items: `{recommended,required}-{client,relay}-protocols`.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:required-relay-protocols>
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProtoStatuses {
    /// Lists of recommended and required subprotocol versions for clients
    client: ProtoStatus,
    /// Lists of recommended and required subprotocol versions for relays
    relay: ProtoStatus,
}

impl ProtoStatuses {
    /// Return the list of recommended and required protocols for running as a client.
    pub fn client(&self) -> &ProtoStatus {
        &self.client
    }

    /// Return the list of recommended and required protocols for running as a relay.
    pub fn relay(&self) -> &ProtoStatus {
        &self.relay
    }
}

/// A recognized 'flavor' of consensus document.
///
/// The enum is exhaustive because the addition/removal of a consensus flavor
/// should indeed be a breaking change, as it would inevitable require
/// interfacing code to think about the handling of it.
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#flavors>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[allow(clippy::exhaustive_enums)]
pub enum ConsensusFlavor {
    /// A "microdesc"-flavored consensus.  This is the one that
    /// clients and relays use today.
    Microdesc,
    /// A "networkstatus"-flavored consensus.  It's used for
    /// historical and network-health purposes.  Instead of listing
    /// microdescriptor digests, it lists digests of full relay
    /// descriptors.
    Plain,
}

impl ConsensusFlavor {
    /// Return the name of this consensus flavor.
    pub fn name(&self) -> &'static str {
        match self {
            ConsensusFlavor::Plain => "ns", // spec bug, now baked in
            ConsensusFlavor::Microdesc => "microdesc",
        }
    }
    /// Try to find the flavor whose name is `name`.
    ///
    /// For historical reasons, an unnamed flavor indicates an "Plain"
    /// document.
    pub fn from_opt_name(name: Option<&str>) -> Result<Self> {
        match name {
            Some("microdesc") => Ok(ConsensusFlavor::Microdesc),
            Some("ns") | None => Ok(ConsensusFlavor::Plain),
            Some(other) => {
                Err(EK::BadDocumentType.with_msg(format!("unrecognized flavor {:?}", other)))
            }
        }
    }
}

/// The signature of a single directory authority on a networkstatus document.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Signature {
    /// The name of the digest algorithm used to make the signature.
    ///
    /// Currently sha1 and sh256 are recognized.  Here we only support
    /// sha256.
    pub digestname: String,
    /// Fingerprints of the keys for the authority that made
    /// this signature.
    pub key_ids: AuthCertKeyIds,
    /// The signature itself.
    pub signature: Vec<u8>,
}

/// A collection of signatures that can be checked on a networkstatus document
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureGroup {
    /// The sha256 of the document itself
    pub sha256: Option<[u8; 32]>,
    /// The sha1 of the document itself
    pub sha1: Option<[u8; 20]>,
    /// The signatures listed on the document.
    pub signatures: Vec<Signature>,
}

/// A shared random value produced by the directory authorities.
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::AsRef,
)]
// (This doesn't need to use CtByteArray; we don't really need to compare these.)
pub struct SharedRandVal([u8; 32]);

/// A shared-random value produced by the directory authorities,
/// along with meta-information about that value.
#[derive(Debug, Clone, Deftly)]
#[non_exhaustive]
#[cfg_attr(feature = "parse2", derive_deftly(ItemValueParseable))]
#[cfg_attr(feature = "encode", derive_deftly(ItemValueEncodable))]
pub struct SharedRandStatus {
    /// How many authorities revealed shares that contributed to this value.
    pub n_reveals: u8,
    /// The current random value.
    ///
    /// The properties of the secure shared-random system guarantee
    /// that this value isn't predictable before it first becomes
    /// live, and that a hostile party could not have forced it to
    /// have any more than a small number of possible random values.
    pub value: SharedRandVal,

    /// The time when this SharedRandVal becomes (or became) the latest.
    ///
    /// (This is added per proposal 342, assuming that gets accepted.)
    pub timestamp: Option<Iso8601TimeNoSp>,
}

/// Description of an authority's identity and address.
///
/// (Corresponds to a dir-source line.)
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirSource {
    /// human-readable nickname for this authority.
    pub nickname: String,
    /// Fingerprint for the _authority_ identity key of this
    /// authority.
    ///
    /// This is the same key as the one that signs the authority's
    /// certificates.
    pub identity: RsaIdentity,
    /// IP address for the authority
    pub ip: net::IpAddr,
    /// HTTP directory port for this authority
    pub dir_port: u16,
    /// OR port for this authority.
    pub or_port: u16,
}

/// Recognized weight fields on a single relay in a consensus
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum RelayWeight {
    /// An unmeasured weight for a relay.
    Unmeasured(u32),
    /// An measured weight for a relay.
    Measured(u32),
}

impl RelayWeight {
    /// Return true if this weight is the result of a successful measurement
    pub fn is_measured(&self) -> bool {
        matches!(self, RelayWeight::Measured(_))
    }
    /// Return true if this weight is nonzero
    pub fn is_nonzero(&self) -> bool {
        !matches!(self, RelayWeight::Unmeasured(0) | RelayWeight::Measured(0))
    }
}

/// All information about a single authority, as represented in a consensus
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConsensusVoterInfo {
    /// Contents of the dirsource line about an authority
    pub dir_source: DirSource,
    /// Human-readable contact information about the authority
    pub contact: String,
    /// Digest of the vote that the authority cast to contribute to
    /// this consensus.
    pub vote_digest: Vec<u8>,
}

/// The signed footer of a consensus netstatus.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Footer {
    /// Weights to be applied to certain classes of relays when choosing
    /// for different roles.
    ///
    /// For example, we want to avoid choosing exits for non-exit
    /// roles when overall the proportion of exits is small.
    pub weights: NetParams<i32>,
}

/// A consensus document that lists relays along with their
/// microdescriptor documents.
pub type MdConsensus = md::Consensus;

/// An MdConsensus that has been parsed and checked for timeliness,
/// but not for signatures.
pub type UnvalidatedMdConsensus = md::UnvalidatedConsensus;

/// An MdConsensus that has been parsed but not checked for signatures
/// and timeliness.
pub type UncheckedMdConsensus = md::UncheckedConsensus;

#[cfg(feature = "plain-consensus")]
/// A consensus document that lists relays along with their
/// router descriptor documents.
pub type PlainConsensus = plain::Consensus;

#[cfg(feature = "plain-consensus")]
/// An PlainConsensus that has been parsed and checked for timeliness,
/// but not for signatures.
pub type UnvalidatedPlainConsensus = plain::UnvalidatedConsensus;

#[cfg(feature = "plain-consensus")]
/// An PlainConsensus that has been parsed but not checked for signatures
/// and timeliness.
pub type UncheckedPlainConsensus = plain::UncheckedConsensus;

decl_keyword! {
    /// Keywords that can be used in votes and consensuses.
    // TODO: This is public because otherwise we can't use it in the
    // ParseRouterStatus crate.  But I'd rather find a way to make it
    // private.
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub NetstatusKwd {
        // Header
        "network-status-version" => NETWORK_STATUS_VERSION,
        "vote-status" => VOTE_STATUS,
        "consensus-methods" => CONSENSUS_METHODS,
        "consensus-method" => CONSENSUS_METHOD,
        "published" => PUBLISHED,
        "valid-after" => VALID_AFTER,
        "fresh-until" => FRESH_UNTIL,
        "valid-until" => VALID_UNTIL,
        "voting-delay" => VOTING_DELAY,
        "client-versions" => CLIENT_VERSIONS,
        "server-versions" => SERVER_VERSIONS,
        "known-flags" => KNOWN_FLAGS,
        "flag-thresholds" => FLAG_THRESHOLDS,
        "recommended-client-protocols" => RECOMMENDED_CLIENT_PROTOCOLS,
        "required-client-protocols" => REQUIRED_CLIENT_PROTOCOLS,
        "recommended-relay-protocols" => RECOMMENDED_RELAY_PROTOCOLS,
        "required-relay-protocols" => REQUIRED_RELAY_PROTOCOLS,
        "params" => PARAMS,
        "bandwidth-file-headers" => BANDWIDTH_FILE_HEADERS,
        "bandwidth-file-digest" => BANDWIDTH_FILE_DIGEST,
        // "package" is now ignored.

        // header in consensus, voter section in vote?
        "shared-rand-previous-value" => SHARED_RAND_PREVIOUS_VALUE,
        "shared-rand-current-value" => SHARED_RAND_CURRENT_VALUE,

        // Voter section (both)
        "dir-source" => DIR_SOURCE,
        "contact" => CONTACT,

        // voter section (vote, but not consensus)
        "legacy-dir-key" => LEGACY_DIR_KEY,
        "shared-rand-participate" => SHARED_RAND_PARTICIPATE,
        "shared-rand-commit" => SHARED_RAND_COMMIT,

        // voter section (consensus, but not vote)
        "vote-digest" => VOTE_DIGEST,

        // voter cert beginning (but only the beginning)
        "dir-key-certificate-version" => DIR_KEY_CERTIFICATE_VERSION,

        // routerstatus
        "r" => RS_R,
        "a" => RS_A,
        "s" => RS_S,
        "v" => RS_V,
        "pr" => RS_PR,
        "w" => RS_W,
        "p" => RS_P,
        "m" => RS_M,
        "id" => RS_ID,

        // footer
        "directory-footer" => DIRECTORY_FOOTER,
        "bandwidth-weights" => BANDWIDTH_WEIGHTS,
        "directory-signature" => DIRECTORY_SIGNATURE,
    }
}

/// Shared parts of rules for all kinds of netstatus headers
static NS_HEADER_RULES_COMMON_: LazyLock<SectionRulesBuilder<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = SectionRules::builder();
    rules.add(NETWORK_STATUS_VERSION.rule().required().args(1..=2));
    rules.add(VOTE_STATUS.rule().required().args(1..));
    rules.add(VALID_AFTER.rule().required());
    rules.add(FRESH_UNTIL.rule().required());
    rules.add(VALID_UNTIL.rule().required());
    rules.add(VOTING_DELAY.rule().args(2..));
    rules.add(CLIENT_VERSIONS.rule());
    rules.add(SERVER_VERSIONS.rule());
    rules.add(KNOWN_FLAGS.rule().required());
    rules.add(RECOMMENDED_CLIENT_PROTOCOLS.rule().args(1..));
    rules.add(RECOMMENDED_RELAY_PROTOCOLS.rule().args(1..));
    rules.add(REQUIRED_CLIENT_PROTOCOLS.rule().args(1..));
    rules.add(REQUIRED_RELAY_PROTOCOLS.rule().args(1..));
    rules.add(PARAMS.rule());
    rules
});
/// Rules for parsing the header of a consensus.
static NS_HEADER_RULES_CONSENSUS: LazyLock<SectionRules<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = NS_HEADER_RULES_COMMON_.clone();
    rules.add(CONSENSUS_METHOD.rule().args(1..=1));
    rules.add(SHARED_RAND_PREVIOUS_VALUE.rule().args(2..));
    rules.add(SHARED_RAND_CURRENT_VALUE.rule().args(2..));
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules.build()
});
/*
/// Rules for parsing the header of a vote.
static NS_HEADER_RULES_VOTE: SectionRules<NetstatusKwd> = {
    use NetstatusKwd::*;
    let mut rules = NS_HEADER_RULES_COMMON_.clone();
    rules.add(CONSENSUS_METHODS.rule().args(1..));
    rules.add(FLAG_THRESHOLDS.rule());
    rules.add(BANDWIDTH_FILE_HEADERS.rule());
    rules.add(BANDWIDTH_FILE_DIGEST.rule().args(1..));
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules
};
/// Rules for parsing a single voter's information in a vote.
static NS_VOTERINFO_RULES_VOTE: SectionRules<NetstatusKwd> = {
    use NetstatusKwd::*;
    let mut rules = SectionRules::new();
    rules.add(DIR_SOURCE.rule().required().args(6..));
    rules.add(CONTACT.rule().required());
    rules.add(LEGACY_DIR_KEY.rule().args(1..));
    rules.add(SHARED_RAND_PARTICIPATE.rule().no_args());
    rules.add(SHARED_RAND_COMMIT.rule().may_repeat().args(4..));
    rules.add(SHARED_RAND_PREVIOUS_VALUE.rule().args(2..));
    rules.add(SHARED_RAND_CURRENT_VALUE.rule().args(2..));
    // then comes an entire cert: When we implement vote parsing,
    // we should use the authcert code for handling that.
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules
};
 */
/// Rules for parsing a single voter's information in a consensus
static NS_VOTERINFO_RULES_CONSENSUS: LazyLock<SectionRules<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = SectionRules::builder();
    rules.add(DIR_SOURCE.rule().required().args(6..));
    rules.add(CONTACT.rule().required());
    rules.add(VOTE_DIGEST.rule().required());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules.build()
});
/// Shared rules for parsing a single routerstatus
static NS_ROUTERSTATUS_RULES_COMMON_: LazyLock<SectionRulesBuilder<NetstatusKwd>> =
    LazyLock::new(|| {
        use NetstatusKwd::*;
        let mut rules = SectionRules::builder();
        rules.add(RS_A.rule().may_repeat().args(1..));
        rules.add(RS_S.rule().required());
        rules.add(RS_V.rule());
        rules.add(RS_PR.rule().required());
        rules.add(RS_W.rule());
        rules.add(RS_P.rule().args(2..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    });

/// Rules for parsing a single routerstatus in an NS consensus
static NS_ROUTERSTATUS_RULES_PLAIN: LazyLock<SectionRules<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
    rules.add(RS_R.rule().required().args(8..));
    rules.build()
});

/*
/// Rules for parsing a single routerstatus in a vote
static NS_ROUTERSTATUS_RULES_VOTE: SectionRules<NetstatusKwd> = {
    use NetstatusKwd::*;
        let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
        rules.add(RS_R.rule().required().args(8..));
        rules.add(RS_M.rule().may_repeat().args(2..));
        rules.add(RS_ID.rule().may_repeat().args(2..)); // may-repeat?
        rules
    };
*/
/// Rules for parsing a single routerstatus in a microdesc consensus
static NS_ROUTERSTATUS_RULES_MDCON: LazyLock<SectionRules<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = NS_ROUTERSTATUS_RULES_COMMON_.clone();
    rules.add(RS_R.rule().required().args(6..));
    rules.add(RS_M.rule().required().args(1..));
    rules.build()
});
/// Rules for parsing consensus fields from a footer.
static NS_FOOTER_RULES: LazyLock<SectionRules<NetstatusKwd>> = LazyLock::new(|| {
    use NetstatusKwd::*;
    let mut rules = SectionRules::builder();
    rules.add(DIRECTORY_FOOTER.rule().required().no_args());
    // consensus only
    rules.add(BANDWIDTH_WEIGHTS.rule());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules.build()
});

impl ProtoStatus {
    /// Construct a ProtoStatus from two chosen keywords in a section.
    fn from_section(
        sec: &Section<'_, NetstatusKwd>,
        recommend_token: NetstatusKwd,
        required_token: NetstatusKwd,
    ) -> Result<ProtoStatus> {
        /// Helper: extract a Protocols entry from an item's arguments.
        fn parse(t: Option<&Item<'_, NetstatusKwd>>) -> Result<Protocols> {
            if let Some(item) = t {
                item.args_as_str()
                    .parse::<Protocols>()
                    .map_err(|e| EK::BadArgument.at_pos(item.pos()).with_source(e))
            } else {
                Ok(Protocols::new())
            }
        }

        let recommended = parse(sec.get(recommend_token))?;
        let required = parse(sec.get(required_token))?;
        Ok(ProtoStatus {
            recommended,
            required,
        })
    }

    /// Return the protocols that are listed as "required" in this `ProtoStatus`.
    ///
    /// Implementations may assume that relays on the network implement all the
    /// protocols in the relays' required-protocols list.  Implementations should
    /// refuse to start if they do not implement all the protocols on their own
    /// (client or relay) required-protocols list.
    pub fn required_protocols(&self) -> &Protocols {
        &self.required
    }

    /// Return the protocols that are listed as "recommended" in this `ProtoStatus`.
    ///
    /// Implementations should warn if they do not implement all the protocols
    /// on their own (client or relay) recommended-protocols list.
    pub fn recommended_protocols(&self) -> &Protocols {
        &self.recommended
    }
}

impl<T> std::str::FromStr for NetParams<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error,
{
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        /// Helper: parse a single K=V pair.
        fn parse_pair<U>(p: &str) -> Result<(String, U)>
        where
            U: std::str::FromStr,
            U::Err: std::error::Error,
        {
            let parts: Vec<_> = p.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(EK::BadArgument
                    .at_pos(Pos::at(p))
                    .with_msg("Missing = in key=value list"));
            }
            let num = parts[1].parse::<U>().map_err(|e| {
                EK::BadArgument
                    .at_pos(Pos::at(parts[1]))
                    .with_msg(e.to_string())
            })?;
            Ok((parts[0].to_string(), num))
        }

        let params = s
            .split(' ')
            .filter(|p| !p.is_empty())
            .map(parse_pair)
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(NetParams { params })
    }
}

impl FromStr for SharedRandVal {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let val: B64 = s.parse()?;
        let val = SharedRandVal(val.into_array()?);
        Ok(val)
    }
}
impl Display for SharedRandVal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&B64::from(Vec::from(self.0)), f)
    }
}
impl NormalItemArgument for SharedRandVal {}

impl SharedRandStatus {
    /// Parse a current or previous shared rand value from a given
    /// SharedRandPreviousValue or SharedRandCurrentValue.
    fn from_item(item: &Item<'_, NetstatusKwd>) -> Result<Self> {
        match item.kwd() {
            NetstatusKwd::SHARED_RAND_PREVIOUS_VALUE | NetstatusKwd::SHARED_RAND_CURRENT_VALUE => {}
            _ => {
                return Err(Error::from(internal!(
                    "wrong keyword {:?} on shared-random value",
                    item.kwd()
                ))
                .at_pos(item.pos()));
            }
        }
        let n_reveals: u8 = item.parse_arg(0)?;
        let value: SharedRandVal = item.parse_arg(1)?;
        // Added in proposal 342
        let timestamp = item.parse_optional_arg::<Iso8601TimeNoSp>(2)?;
        Ok(SharedRandStatus {
            n_reveals,
            value,
            timestamp,
        })
    }

    /// Return the actual shared random value.
    pub fn value(&self) -> &SharedRandVal {
        &self.value
    }

    /// Return the timestamp (if any) associated with this `SharedRandValue`.
    pub fn timestamp(&self) -> Option<std::time::SystemTime> {
        self.timestamp.map(|t| t.0)
    }
}

impl DirSource {
    /// Parse a "dir-source" item
    fn from_item(item: &Item<'_, NetstatusKwd>) -> Result<Self> {
        if item.kwd() != NetstatusKwd::DIR_SOURCE {
            return Err(
                Error::from(internal!("Bad keyword {:?} on dir-source", item.kwd()))
                    .at_pos(item.pos()),
            );
        }
        let nickname = item.required_arg(0)?.to_string();
        let identity = item.parse_arg::<Fingerprint>(1)?.into();
        let ip = item.parse_arg(3)?;
        let dir_port = item.parse_arg(4)?;
        let or_port = item.parse_arg(5)?;

        Ok(DirSource {
            nickname,
            identity,
            ip,
            dir_port,
            or_port,
        })
    }
}

impl ConsensusVoterInfo {
    /// Parse a single ConsensusVoterInfo from a voter info section.
    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<ConsensusVoterInfo> {
        use NetstatusKwd::*;
        // this unwrap should be safe because if there is not at least one
        // token in the section, the section is unparsable.
        #[allow(clippy::unwrap_used)]
        let first = sec.first_item().unwrap();
        if first.kwd() != DIR_SOURCE {
            return Err(Error::from(internal!(
                "Wrong keyword {:?} at start of voter info",
                first.kwd()
            ))
            .at_pos(first.pos()));
        }
        let dir_source = DirSource::from_item(sec.required(DIR_SOURCE)?)?;

        let contact = sec.required(CONTACT)?.args_as_str().to_string();

        let vote_digest = sec.required(VOTE_DIGEST)?.parse_arg::<B16>(0)?.into();

        Ok(ConsensusVoterInfo {
            dir_source,
            contact,
            vote_digest,
        })
    }
}

impl Default for RelayWeight {
    fn default() -> RelayWeight {
        RelayWeight::Unmeasured(0)
    }
}

impl RelayWeight {
    /// Parse a routerweight from a "w" line.
    fn from_item(item: &Item<'_, NetstatusKwd>) -> Result<RelayWeight> {
        if item.kwd() != NetstatusKwd::RS_W {
            return Err(
                Error::from(internal!("Wrong keyword {:?} on W line", item.kwd()))
                    .at_pos(item.pos()),
            );
        }

        let params = item.args_as_str().parse()?;

        Self::from_net_params(&params).map_err(|e| e.at_pos(item.pos()))
    }

    /// Parse a routerweight from partially-parsed `w` line in the form of a `NetParams`
    ///
    /// This function is the common part shared between `parse2` and `parse`.
    fn from_net_params(params: &NetParams<u32>) -> Result<RelayWeight> {
        let bw = params.params.get("Bandwidth");
        let unmeas = params.params.get("Unmeasured");

        let bw = match bw {
            None => return Ok(RelayWeight::Unmeasured(0)),
            Some(b) => *b,
        };

        match unmeas {
            None | Some(0) => Ok(RelayWeight::Measured(bw)),
            Some(1) => Ok(RelayWeight::Unmeasured(bw)),
            _ => Err(EK::BadArgument.with_msg("unmeasured value")),
        }
    }
}

/// `parse2` impls for types in this module
///
/// Separate module to save on repeated `cfg` and for a separate namespace.
#[cfg(feature = "parse2")]
mod parse2_impls {
    use super::*;
    use parse2::ArgumentError as AE;
    use parse2::ErrorProblem as EP;
    use parse2::{ArgumentStream, ItemArgumentParseable, ItemValueParseable};
    use parse2::{KeywordRef, NetdocParseableFields, UnparsedItem};
    use paste::paste;
    use std::result::Result;

    /// Implements `NetdocParseableFields` for `ProtoStatuses`
    ///
    /// We have this macro so that it's impossible to write things like
    /// ```text
    ///      ProtoStatuses {
    ///          client: ProtoStatus {
    ///              recommended: something something recommended_relay_versions something,
    /// ```
    ///
    /// (The structure of `ProtoStatuses` means the normal parse2 derive won't work for it.
    /// Note the bug above: the recommended *relay* version info is put in the *client* field.
    /// Preventing this bug must involve: avoiding writing twice the field name elements,
    /// such as `relay` and `client`, during this kind of construction/conversion.)
    macro_rules! impl_proto_statuses { { $( $rr:ident $cr:ident; )* } => { paste! {
        #[derive(Deftly)]
        #[derive_deftly(NetdocParseableFields)]
        // Only ProtoStatusesParseNetdocParseAccumulator is exposed.
        #[allow(unreachable_pub)]
        pub struct ProtoStatusesParseHelper {
            $(
                #[deftly(netdoc(default))]
                [<$rr _ $cr _protocols>]: Protocols,
            )*
        }

        /// Partially parsed `ProtoStatuses`
        pub use ProtoStatusesParseHelperNetdocParseAccumulator
            as ProtoStatusesNetdocParseAccumulator;

        impl NetdocParseableFields for ProtoStatuses {
            type Accumulator = ProtoStatusesNetdocParseAccumulator;
            fn is_item_keyword(kw: KeywordRef<'_>) -> bool {
                ProtoStatusesParseHelper::is_item_keyword(kw)
            }
            fn accumulate_item(
                acc: &mut Self::Accumulator,
                item: UnparsedItem<'_>,
            ) -> Result<(), EP> {
                ProtoStatusesParseHelper::accumulate_item(acc, item)
            }
            fn finish(acc: Self::Accumulator) -> Result<Self, EP> {
                let parse = ProtoStatusesParseHelper::finish(acc)?;
                let mut out = ProtoStatuses::default();
                $(
                    out.$cr.$rr = parse.[< $rr _ $cr _protocols >];
                )*
                Ok(out)
            }
        }
    } } }

    impl_proto_statuses! {
        required client;
        required relay;
        recommended client;
        recommended relay;
    }

    impl ItemValueParseable for NetParams<i32> {
        fn from_unparsed(item: parse2::UnparsedItem<'_>) -> Result<Self, EP> {
            item.check_no_object()?;
            item.args_copy()
                .into_remaining()
                .parse()
                .map_err(item.invalid_argument_handler("parameters"))
        }
    }

    impl ItemValueParseable for RelayWeight {
        fn from_unparsed(item: parse2::UnparsedItem<'_>) -> Result<Self, EP> {
            item.check_no_object()?;
            (|| {
                let params = item.args_copy().into_remaining().parse()?;
                Self::from_net_params(&params)
            })()
            .map_err(item.invalid_argument_handler("weights"))
        }
    }

    impl ItemValueParseable for rs::SoftwareVersion {
        fn from_unparsed(mut item: parse2::UnparsedItem<'_>) -> Result<Self, EP> {
            item.check_no_object()?;
            item.args_mut()
                .into_remaining()
                .parse()
                .map_err(item.invalid_argument_handler("version"))
        }
    }

    impl ItemArgumentParseable for IgnoredPublicationTimeSp {
        fn from_args(a: &mut ArgumentStream) -> Result<IgnoredPublicationTimeSp, AE> {
            let mut next_arg = || a.next().ok_or(AE::Missing);
            let _: &str = next_arg()?;
            let _: &str = next_arg()?;
            Ok(IgnoredPublicationTimeSp)
        }
    }
}

impl Footer {
    /// Parse a directory footer from a footer section.
    fn from_section(sec: &Section<'_, NetstatusKwd>) -> Result<Footer> {
        use NetstatusKwd::*;
        sec.required(DIRECTORY_FOOTER)?;

        let weights = sec
            .maybe(BANDWIDTH_WEIGHTS)
            .args_as_str()
            .unwrap_or("")
            .parse()?;

        Ok(Footer { weights })
    }
}

/// Result of checking a single authority signature.
enum SigCheckResult {
    /// The signature checks out.  Great!
    Valid,
    /// The signature is invalid; no additional information could make it
    /// valid.
    Invalid,
    /// We can't check the signature because we don't have a
    /// certificate with the right signing key.
    MissingCert,
}

impl Signature {
    /// Parse a Signature from a directory-signature section
    fn from_item(item: &Item<'_, NetstatusKwd>) -> Result<Signature> {
        if item.kwd() != NetstatusKwd::DIRECTORY_SIGNATURE {
            return Err(Error::from(internal!(
                "Wrong keyword {:?} for directory signature",
                item.kwd()
            ))
            .at_pos(item.pos()));
        }

        let (alg, id_fp, sk_fp) = if item.n_args() > 2 {
            (
                item.required_arg(0)?,
                item.required_arg(1)?,
                item.required_arg(2)?,
            )
        } else {
            ("sha1", item.required_arg(0)?, item.required_arg(1)?)
        };

        let digestname = alg.to_string();
        let id_fingerprint = id_fp.parse::<Fingerprint>()?.into();
        let sk_fingerprint = sk_fp.parse::<Fingerprint>()?.into();
        let key_ids = AuthCertKeyIds {
            id_fingerprint,
            sk_fingerprint,
        };
        let signature = item.obj("SIGNATURE")?;

        Ok(Signature {
            digestname,
            key_ids,
            signature,
        })
    }

    /// Return true if this signature has the identity key and signing key
    /// that match a given cert.
    fn matches_cert(&self, cert: &AuthCert) -> bool {
        cert.key_ids() == self.key_ids
    }

    /// If possible, find the right certificate for checking this signature
    /// from among a slice of certificates.
    fn find_cert<'a>(&self, certs: &'a [AuthCert]) -> Option<&'a AuthCert> {
        certs.iter().find(|&c| self.matches_cert(c))
    }

    /// Try to check whether this signature is a valid signature of a
    /// provided digest, given a slice of certificates that might contain
    /// its signing key.
    fn check_signature(&self, signed_digest: &[u8], certs: &[AuthCert]) -> SigCheckResult {
        match self.find_cert(certs) {
            None => SigCheckResult::MissingCert,
            Some(cert) => {
                let key = cert.signing_key();
                match key.verify(signed_digest, &self.signature[..]) {
                    Ok(()) => SigCheckResult::Valid,
                    Err(_) => SigCheckResult::Invalid,
                }
            }
        }
    }
}

impl SignatureGroup {
    // TODO: these functions are pretty similar and could probably stand to be
    // refactored a lot.

    /// Helper: Return a pair of the number of possible authorities'
    /// signatures in this object for which we _could_ find certs, and
    /// a list of the signatures we couldn't find certificates for.
    fn list_missing(&self, certs: &[AuthCert]) -> (usize, Vec<&Signature>) {
        let mut ok: HashSet<RsaIdentity> = HashSet::new();
        let mut missing = Vec::new();
        for sig in &self.signatures {
            let id_fingerprint = &sig.key_ids.id_fingerprint;
            if ok.contains(id_fingerprint) {
                continue;
            }
            if sig.find_cert(certs).is_some() {
                ok.insert(*id_fingerprint);
                continue;
            }

            missing.push(sig);
        }
        (ok.len(), missing)
    }

    /// Given a list of authority identity key fingerprints, return true if
    /// this signature group is _potentially_ well-signed according to those
    /// authorities.
    fn could_validate(&self, authorities: &[&RsaIdentity]) -> bool {
        let mut signed_by: HashSet<RsaIdentity> = HashSet::new();
        for sig in &self.signatures {
            let id_fp = &sig.key_ids.id_fingerprint;
            if signed_by.contains(id_fp) {
                // Already found this in the list.
                continue;
            }
            if authorities.contains(&id_fp) {
                signed_by.insert(*id_fp);
            }
        }

        signed_by.len() > (authorities.len() / 2)
    }

    /// Return true if the signature group defines a valid signature.
    ///
    /// A signature is valid if it signed by more than half of the
    /// authorities.  This API requires that `n_authorities` is the number of
    /// authorities we believe in, and that every cert in `certs` belongs
    /// to a real authority.
    fn validate(&self, n_authorities: usize, certs: &[AuthCert]) -> bool {
        // A set of the authorities (by identity) who have have signed
        // this document.  We use a set here in case `certs` has more
        // than one certificate for a single authority.
        let mut ok: HashSet<RsaIdentity> = HashSet::new();

        for sig in &self.signatures {
            let id_fingerprint = &sig.key_ids.id_fingerprint;
            if ok.contains(id_fingerprint) {
                // We already checked at least one signature using this
                // authority's identity fingerprint.
                continue;
            }

            let d: Option<&[u8]> = match sig.digestname.as_ref() {
                "sha256" => self.sha256.as_ref().map(|a| &a[..]),
                "sha1" => self.sha1.as_ref().map(|a| &a[..]),
                _ => None, // We don't know how to find this digest.
            };
            if d.is_none() {
                // We don't support this kind of digest for this kind
                // of document.
                continue;
            }

            // Unwrap should be safe because of above `d.is_none()` check
            #[allow(clippy::unwrap_used)]
            match sig.check_signature(d.as_ref().unwrap(), certs) {
                SigCheckResult::Valid => {
                    ok.insert(*id_fingerprint);
                }
                _ => continue,
            }
        }

        ok.len() > (n_authorities / 2)
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use hex_literal::hex;
    #[cfg(all(feature = "ns-vote", feature = "parse2"))]
    use {
        crate::parse2::{NetdocSigned as _, ParseInput, parse_netdoc},
        std::fs,
    };

    const CERTS: &str = include_str!("../../testdata/authcerts2.txt");
    const CONSENSUS: &str = include_str!("../../testdata/mdconsensus1.txt");

    #[cfg(feature = "plain-consensus")]
    const PLAIN_CERTS: &str = include_str!("../../testdata2/cached-certs");
    #[cfg(feature = "plain-consensus")]
    const PLAIN_CONSENSUS: &str = include_str!("../../testdata2/cached-consensus");

    fn read_bad(fname: &str) -> String {
        use std::fs;
        use std::path::PathBuf;
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("testdata");
        path.push("bad-mdconsensus");
        path.push(fname);

        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn parse_and_validate_md() -> Result<()> {
        use std::net::SocketAddr;
        use tor_checkable::{SelfSigned, Timebound};
        let mut certs = Vec::new();
        for cert in AuthCert::parse_multiple(CERTS)? {
            let cert = cert?.check_signature()?.dangerously_assume_timely();
            certs.push(cert);
        }
        let auth_ids: Vec<_> = certs.iter().map(|c| c.id_fingerprint()).collect();

        assert_eq!(certs.len(), 3);

        let (_, _, consensus) = MdConsensus::parse(CONSENSUS)?;
        let consensus = consensus.dangerously_assume_timely().set_n_authorities(3);

        // The set of authorities we know _could_ validate this cert.
        assert!(consensus.authorities_are_correct(&auth_ids));
        // A subset would also work.
        assert!(consensus.authorities_are_correct(&auth_ids[0..1]));
        {
            // If we only believe in an authority that isn't listed,
            // that won't work.
            let bad_auth_id = (*b"xxxxxxxxxxxxxxxxxxxx").into();
            assert!(!consensus.authorities_are_correct(&[&bad_auth_id]));
        }

        let missing = consensus.key_is_correct(&[]).err().unwrap();
        assert_eq!(3, missing.len());
        assert!(consensus.key_is_correct(&certs).is_ok());
        let missing = consensus.key_is_correct(&certs[0..1]).err().unwrap();
        assert_eq!(2, missing.len());

        // here is a trick that had better not work.
        let same_three_times = vec![certs[0].clone(), certs[0].clone(), certs[0].clone()];
        let missing = consensus.key_is_correct(&same_three_times).err().unwrap();

        assert_eq!(2, missing.len());
        assert!(consensus.is_well_signed(&same_three_times).is_err());

        assert!(consensus.key_is_correct(&certs).is_ok());
        let consensus = consensus.check_signature(&certs)?;

        assert_eq!(6, consensus.relays().len());
        let r0 = &consensus.relays()[0];
        assert_eq!(
            r0.md_digest(),
            &hex!("73dabe0a0468f4f7a67810a18d11e36731bb1d2ec3634db459100609f3b3f535")
        );
        assert_eq!(
            r0.rsa_identity().as_bytes(),
            &hex!("0a3057af2910415794d8ea430309d9ac5f5d524b")
        );
        assert!(!r0.weight().is_measured());
        assert!(!r0.weight().is_nonzero());
        let pv = &r0.protovers();
        assert!(pv.supports_subver("HSDir", 2));
        assert!(!pv.supports_subver("HSDir", 3));
        let ip4 = "127.0.0.1:5002".parse::<SocketAddr>().unwrap();
        let ip6 = "[::1]:5002".parse::<SocketAddr>().unwrap();
        assert!(r0.addrs().any(|a| a == ip4));
        assert!(r0.addrs().any(|a| a == ip6));

        Ok(())
    }

    #[test]
    #[cfg(feature = "plain-consensus")]
    fn parse_and_validate_ns() -> Result<()> {
        use tor_checkable::{SelfSigned, Timebound};
        let mut certs = Vec::new();
        for cert in AuthCert::parse_multiple(PLAIN_CERTS)? {
            let cert = cert?.check_signature()?.dangerously_assume_timely();
            certs.push(cert);
        }
        let auth_ids: Vec<_> = certs.iter().map(|c| c.id_fingerprint()).collect();
        assert_eq!(certs.len(), 4);

        let (_, _, consensus) = PlainConsensus::parse(PLAIN_CONSENSUS)?;
        let consensus = consensus.dangerously_assume_timely().set_n_authorities(3);
        // The set of authorities we know _could_ validate this cert.
        assert!(consensus.authorities_are_correct(&auth_ids));
        // A subset would also work.
        assert!(consensus.authorities_are_correct(&auth_ids[0..1]));

        assert!(consensus.key_is_correct(&certs).is_ok());

        let _consensus = consensus.check_signature(&certs)?;

        Ok(())
    }

    #[test]
    #[cfg(all(feature = "ns-vote", feature = "parse2"))]
    fn parse2_vote() -> anyhow::Result<()> {
        let file = "testdata2/v3-status-votes--1";
        let text = fs::read_to_string(file)?;

        // TODO replace the poc struct here when we have parsing of proper whole votes
        use crate::parse2::poc::netstatus::NetworkStatusSignedVote;

        let input = ParseInput::new(&text, file);
        let doc: NetworkStatusSignedVote = parse_netdoc(&input)?;

        println!("{doc:?}");
        println!("{:#?}", doc.inspect_unverified().0.r[0]);

        Ok(())
    }

    #[test]
    fn test_bad() {
        use crate::Pos;
        fn check(fname: &str, e: &Error) {
            let content = read_bad(fname);
            let res = MdConsensus::parse(&content);
            assert!(res.is_err());
            assert_eq!(&res.err().unwrap(), e);
        }

        check(
            "bad-flags",
            &EK::BadArgument
                .at_pos(Pos::from_line(27, 1))
                .with_msg("Flags out of order"),
        );
        check(
            "bad-md-digest",
            &EK::BadArgument
                .at_pos(Pos::from_line(40, 3))
                .with_msg("Invalid base64"),
        );
        check(
            "bad-weight",
            &EK::BadArgument
                .at_pos(Pos::from_line(67, 141))
                .with_msg("invalid digit found in string"),
        );
        check(
            "bad-weights",
            &EK::BadArgument
                .at_pos(Pos::from_line(51, 13))
                .with_msg("invalid digit found in string"),
        );
        check(
            "wrong-order",
            &EK::WrongSortOrder.at_pos(Pos::from_line(52, 1)),
        );
        check(
            "wrong-start",
            &EK::UnexpectedToken
                .with_msg("vote-status")
                .at_pos(Pos::from_line(1, 1)),
        );
        check("wrong-version", &EK::BadDocumentVersion.with_msg("10"));
    }

    fn gettok(s: &str) -> Result<Item<'_, NetstatusKwd>> {
        let mut reader = NetDocReader::new(s)?;
        let tok = reader.next().unwrap();
        assert!(reader.next().is_none());
        tok
    }

    #[test]
    fn test_weight() {
        let w = gettok("w Unmeasured=1 Bandwidth=6\n").unwrap();
        let w = RelayWeight::from_item(&w).unwrap();
        assert!(!w.is_measured());
        assert!(w.is_nonzero());

        let w = gettok("w Bandwidth=10\n").unwrap();
        let w = RelayWeight::from_item(&w).unwrap();
        assert!(w.is_measured());
        assert!(w.is_nonzero());

        let w = RelayWeight::default();
        assert!(!w.is_measured());
        assert!(!w.is_nonzero());

        let w = gettok("w Mustelid=66 Cheato=7 Unmeasured=1\n").unwrap();
        let w = RelayWeight::from_item(&w).unwrap();
        assert!(!w.is_measured());
        assert!(!w.is_nonzero());

        let w = gettok("r foo\n").unwrap();
        let w = RelayWeight::from_item(&w);
        assert!(w.is_err());

        let w = gettok("r Bandwidth=6 Unmeasured=Frog\n").unwrap();
        let w = RelayWeight::from_item(&w);
        assert!(w.is_err());

        let w = gettok("r Bandwidth=6 Unmeasured=3\n").unwrap();
        let w = RelayWeight::from_item(&w);
        assert!(w.is_err());
    }

    #[test]
    fn test_netparam() {
        let p = "Hello=600 Goodbye=5 Fred=7"
            .parse::<NetParams<u32>>()
            .unwrap();
        assert_eq!(p.get("Hello"), Some(&600_u32));

        let p = "Hello=Goodbye=5 Fred=7".parse::<NetParams<u32>>();
        assert!(p.is_err());

        let p = "Hello=Goodbye Fred=7".parse::<NetParams<u32>>();
        assert!(p.is_err());
    }

    #[test]
    fn test_sharedrand() {
        let sr =
            gettok("shared-rand-previous-value 9 5LodY4yWxFhTKtxpV9wAgNA9N8flhUCH0NqQv1/05y4\n")
                .unwrap();
        let sr = SharedRandStatus::from_item(&sr).unwrap();

        assert_eq!(sr.n_reveals, 9);
        assert_eq!(
            sr.value.0,
            hex!("e4ba1d638c96c458532adc6957dc0080d03d37c7e5854087d0da90bf5ff4e72e")
        );
        assert!(sr.timestamp.is_none());

        let sr2 = gettok(
            "shared-rand-current-value 9 \
                    5LodY4yWxFhTKtxpV9wAgNA9N8flhUCH0NqQv1/05y4 2022-01-20T12:34:56\n",
        )
        .unwrap();
        let sr2 = SharedRandStatus::from_item(&sr2).unwrap();
        assert_eq!(sr2.n_reveals, sr.n_reveals);
        assert_eq!(sr2.value.0, sr.value.0);
        assert_eq!(
            sr2.timestamp.unwrap().0,
            humantime::parse_rfc3339("2022-01-20T12:34:56Z").unwrap()
        );

        let sr = gettok("foo bar\n").unwrap();
        let sr = SharedRandStatus::from_item(&sr);
        assert!(sr.is_err());
    }

    #[test]
    fn test_protostatus() {
        let my_protocols: Protocols = "Link=7 Cons=1-5 Desc=3-10".parse().unwrap();

        let outcome = ProtoStatus {
            recommended: "Link=7".parse().unwrap(),
            required: "Desc=5".parse().unwrap(),
        }
        .check_protocols(&my_protocols);
        assert!(outcome.is_ok());

        let outcome = ProtoStatus {
            recommended: "Microdesc=4 Link=7".parse().unwrap(),
            required: "Desc=5".parse().unwrap(),
        }
        .check_protocols(&my_protocols);
        assert_eq!(
            outcome,
            Err(ProtocolSupportError::MissingRecommended(
                "Microdesc=4".parse().unwrap()
            ))
        );

        let outcome = ProtoStatus {
            recommended: "Microdesc=4 Link=7".parse().unwrap(),
            required: "Desc=5 Cons=5-12 Wombat=15".parse().unwrap(),
        }
        .check_protocols(&my_protocols);
        assert_eq!(
            outcome,
            Err(ProtocolSupportError::MissingRequired(
                "Cons=6-12 Wombat=15".parse().unwrap()
            ))
        );
    }

    #[test]
    fn serialize_protostatus() {
        let ps = ProtoStatuses {
            client: ProtoStatus {
                recommended: "Link=1-5 LinkAuth=2-5".parse().unwrap(),
                required: "Link=5 LinkAuth=3".parse().unwrap(),
            },
            relay: ProtoStatus {
                recommended: "Wombat=20-30 Knish=20-30".parse().unwrap(),
                required: "Wombat=20-22 Knish=25-27".parse().unwrap(),
            },
        };
        let json = serde_json::to_string(&ps).unwrap();
        let ps2 = serde_json::from_str(json.as_str()).unwrap();
        assert_eq!(ps, ps2);

        let ps3: ProtoStatuses = serde_json::from_str(
            r#"{
            "client":{
                "required":"Link=5 LinkAuth=3",
                "recommended":"Link=1-5 LinkAuth=2-5"
            },
            "relay":{
                "required":"Wombat=20-22 Knish=25-27",
                "recommended":"Wombat=20-30 Knish=20-30"
            }
        }"#,
        )
        .unwrap();
        assert_eq!(ps, ps3);
    }
}
