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
//! TODO: We need an object safe trait that combines the common operations found
//! on netstatus documents, so we can store one in a `Box<dyn CommonNs>` or
//! something similar; otherwise interfacing applications have a hard time to
//! process netstatus documents in a flavor agnostic fashion.
//!
//! TODO: More testing is needed!
//!
//! TODO: There should be accessor functions for most of the fields here.
//! As with the other tor-netdoc types, I'm deferring those till I know what
//! they should be.

mod dir_source;
mod rs;

pub mod md;
pub mod plain;
pub mod vote;

#[cfg(feature = "build_docs")]
mod build;

pub use proto_statuses_parse2_encode::ProtoStatusesNetdocParseAccumulator;

use crate::doc::authcert::EncodedAuthCert;

use crate::doc::authcert::{self, AuthCert, AuthCertKeyIds, AuthCertUnverified};
use crate::encode::{
    EncodeOrd, ItemArgument, ItemEncoder, ItemValueEncodable, NetdocEncodable, NetdocEncoder,
};
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules, SectionRulesBuilder};
use crate::parse::tokenize::{Item, ItemResult, NetDocReader};
use crate::parse2::{
    self, ArgumentError, ArgumentStream, ErrorProblem, IsStructural, ItemArgumentParseable,
    ItemStream, ItemValueParseable, KeywordRef, NetdocParseable, NetdocParseableUnverified,
    SignatureHashInputs, SignatureItemParseable, StopAt, UnparsedItem, VerifyFailed,
};
use crate::types::relay_flags::{self, DocRelayFlags};
use crate::types::{self, *};
use crate::util::PeekableIterator;
use crate::{Error, KeywordEncodable, NetdocErrorKind as EK, NormalItemArgument, Pos};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display};
use std::slice;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{self, SystemTime};
use std::{net, result};
use tor_basic_utils::iter_join;
use tor_error::{Bug, HasKind, bad_api_usage, internal};
use tor_protover::Protocols;
use void::ResultVoidExt as _;

use derive_deftly::{Deftly, define_derive_deftly};
use digest::Digest;
use itertools::Itertools;
use saturating_time::SaturatingTime as _;
use std::sync::LazyLock;
use tor_checkable::{ExternallySigned, TimeBound, timed::TimeRangeBound};
use tor_llcrypto as ll;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::{Deserialize, Deserializer};

#[cfg(feature = "build_docs")]
pub use build::MdConsensusBuilder;
#[cfg(feature = "build_docs")]
pub use build::PlainConsensusBuilder;
#[cfg(feature = "build_docs")]
ns_export_each_flavor! {
    ty: RouterStatusBuilder;
}

ns_export_each_variety! {
    ty: Footer, RouterStatus, Preamble;
}

#[deprecated]
pub use PlainConsensus as NsConsensus;
#[deprecated]
pub use PlainRouterStatus as NsRouterStatus;
#[deprecated]
pub use UncheckedPlainConsensus as UncheckedNsConsensus;
#[deprecated]
pub use UnvalidatedPlainConsensus as UnvalidatedNsConsensus;

pub use rs::{RouterStatusMdDigestsVote, SoftwareVersion};

pub use dir_source::{ConsensusAuthoritySection, DirSource, SupersededAuthorityKey};

define_constant_string! {
    /// `network-status-version` version value
    ///
    /// This is the fixed string `3`.
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:network-status-version>
    //
    // IMO this is nicer than the formulation with an enum.
    // In practice we are not going to support other versions with the same parsing approach;
    // probably not even with the same code.
    NetworkStatusVersion = "3";
}

define_constant_string! {
    /// The `status` value in a `vote-status` line in a consensus
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:vote-status>
    VoteStatusConsensus = "consensus";
}

define_constant_string! {
    /// The `vote` value in a `vote-status` line in a vote
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:vote-status>
    VoteStatusVote = "vote";
}

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
#[derive_deftly(Constructor, NetdocEncodableFields, NetdocParseableFields)]
#[derive_deftly(Lifetime)]
#[allow(clippy::exhaustive_structs)]
pub struct Lifetime {
    /// `valid-after` --- Time at which the document becomes valid
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// (You might see a consensus a little while before this time,
    /// since voting tries to finish up before the.)
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub valid_after: Iso8601TimeSp,
    /// `fresh-until` --- Time after which there is expected to be a better version
    /// of this consensus
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// You can use the consensus after this time, but there is (or is
    /// supposed to be) a better one by this point.
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub fresh_until: Iso8601TimeSp,
    /// `valid-until` --- Time after which this consensus is expired.
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:published>
    ///
    /// You should try to get a better consensus after this time,
    /// though it's okay to keep using this one if no more recent one
    /// can be found.
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub valid_until: Iso8601TimeSp,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

define_derive_deftly! {
    /// Bespoke derive for `Lifetime`, for `new` and accessors
    Lifetime:

    ${defcond FIELD not(approx_equal($fname, __non_exhaustive))}

    impl Lifetime {
        /// Construct a new Lifetime.
        pub fn new(
            $( ${when FIELD} $fname: time::SystemTime, )
        ) -> crate::Result<Self> {
            // Make this now because otherwise literal `valid_after` here in the body
            // has the wrong span - the compiler refuses to look at the argument.
            // But we can refer to the field names.
            let self_ = Lifetime {
                $( ${when FIELD} $fname: $fname.into(), )
                __non_exhaustive: (),
            };
            if self_.valid_after < self_.fresh_until && self_.fresh_until < self_.valid_until {
                Ok(self_)
            } else {
                Err(EK::InvalidLifetime.err())
            }
        }
      $(
        ${when FIELD}

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
#[allow(clippy::exhaustive_structs)] // we're v unlikely to want to change this to u16 or u64
pub struct ConsensusMethod(pub u32);
impl NormalItemArgument for ConsensusMethod {}

/// A set of consensus methods
///
/// Implements `ItemValueParseable` as required for `consensus-methods`,
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:consensus-methods>
///
/// There is also [`consensus_methods_comma_separated`] for `m` lines in votes.
#[derive(Debug, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[non_exhaustive]
pub struct ConsensusMethods {
    /// Consensus methods.
    pub methods: BTreeSet<ConsensusMethod>,
}

/// Module for use with parse2's `with`, to parse one argument of comma-separated consensus methods
///
/// As found in an `m` item in a vote:
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:m>
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

    /// Encode
    pub fn write_arg_onto(self_: &ConsensusMethods, out: &mut ItemEncoder) -> Result<(), Bug> {
        out.args_raw_string(&iter_join(",", &self_.methods));
        Ok(())
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
/// for example routerstatus entry `w` items (bandwidth weights):
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:w>
//
// TODO DIRAUTH torspec#401 Replace `String` with a suitable newtype
// Currently:
//  - Our parser allows any keyword that makes it into a netdoc argument,
//    but it splits on the *first* `=` so a `NetParams<i32>` cannot parse a keyword with a `=`.
//  - We provide constructors that allow any `String`, even ones containing space, `=`,
//    newline, etc.
//  - Encoding throws `Bug` if the resulting document will be clearly garbage,
//    forbidding `=`, whitespace, and controls.  If the supplied keywords are bizarre,
//    it may generate surprising documents (eg, containing exciting Unicode).
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
    ) -> Result<(), ProtocolSupportError> {
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

/// List of recommended Tor versions
///
/// As seen in `client-versions` and `server-versions` in the preamble.
///
/// Technically these are supposed to be as according to
/// "`version-spec.txt`" but we actually allow anything that doesn't contain commas.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:client-versions>
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:server-versions>
///
/// An empty set means no information, not no recommended versions.
//
// TODO should we have a CommaSeparated<T> type for arguments like this?
// But maybe we wouldn't be able to use it here anyway because of
// the special handling of the missing value.
//
// This is yet a third version number representation in arti!  Here it's just String.
// TODO unify RecommendedTorVersions, RelayPlatform, TorVersion
// When this is fixed, remove the workaround in netstatus::test::roundtrip_netstatus
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(derive_more::Deref, derive_more::Into)]
pub struct RecommendedTorVersions(BTreeSet<String>);

/// Erroneous "recommended Tor versions" information
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidRecommendedTorVersions {
    /// Identical version appears twice
    #[error("version {_0:?} contains whitespace")]
    ContainsWhitespace(String),

    /// Identical version appears twice
    #[error("version {_0:?} is repeated")]
    Repeated(String),
}

impl RecommendedTorVersions {
    /// Return a `RecommendedTorVersions` that has no information
    pub fn new_unknown() -> Self {
        Self::default()
    }

    /// Does this `RecommendedTorVersions` have any information?
    ///
    /// Ie, is it not empty.
    ///
    /// The opposite of [`BTreeSet::is_empty()`] (which available via deref).
    pub fn is_known(&self) -> bool {
        !self.is_empty()
    }

    /// Construct a RecommendedTorVersions from a list of strings
    #[allow(clippy::should_implement_trait)] // we can't due to coherence
    pub fn from_iter<I, S>(i: I) -> Result<Self, InvalidRecommendedTorVersions>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for v in i {
            let v = v.as_ref();
            if v.is_empty() {
                continue;
            }
            if v.chars().any(|c| c.is_whitespace()) {
                return Err(InvalidRecommendedTorVersions::ContainsWhitespace(
                    v.to_owned(),
                ));
            }
            if !set.insert(v.to_owned()) {
                return Err(InvalidRecommendedTorVersions::Repeated(v.to_owned()));
            }
        }
        Ok(RecommendedTorVersions(set))
    }
}

impl FromStr for RecommendedTorVersions {
    type Err = InvalidRecommendedTorVersions;
    fn from_str(s: &str) -> Result<Self, InvalidRecommendedTorVersions> {
        Self::from_iter(s.split(','))
    }
}

impl Display for RecommendedTorVersions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", iter_join(",", &self.0))
    }
}

impl NormalItemArgument for RecommendedTorVersions {}

impl ItemValueEncodable for RecommendedTorVersions {
    fn write_item_value_onto(&self, mut out: ItemEncoder) -> Result<(), Bug> {
        out.args_raw_string(self);
        Ok(())
    }
}

impl ItemValueParseable for RecommendedTorVersions {
    fn from_unparsed(mut item: UnparsedItem) -> Result<Self, ErrorProblem> {
        const FIELD: &str = "versions";
        item.check_no_object()?;
        let args = item.args_mut();
        let arg = args.next().unwrap_or("");
        arg.parse::<Self>()
            .map_err(|_| args.handle_error(FIELD, ArgumentError::Invalid))
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
    pub fn from_opt_name(name: Option<&str>) -> crate::Result<Self> {
        match name {
            Some("microdesc") => Ok(ConsensusFlavor::Microdesc),
            Some("ns") | None => Ok(ConsensusFlavor::Plain),
            Some(other) => {
                Err(EK::BadDocumentType.with_msg(format!("unrecognized flavor {:?}", other)))
            }
        }
    }
}

define_derive_deftly! {
    /// Bespoke derives applied to [`DirectorySignatureHashAlgo`]
    ///
    /// Generates:
    ///
    ///  * [`DirectorySignaturesHashesAccu`]
    ///  * [`DirectorySignaturesHashesAccu::update_from`]
    ///  * [`DirectorySignaturesHashesAccu::hash_slice_for_verification`]
    DirectorySignaturesHashesAccu:

    ${define FNAME ${paste ${snake_case $vname}} }

    /// `directory-signature`a hash algorithm argument
    #[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Deftly)]
    #[derive_deftly(AsMutSelf)]
    #[non_exhaustive]
    pub struct DirectorySignaturesHashesAccu {
      $(
        ${vattrs doc}
        pub $FNAME: Option<[u8; ${vmeta(hash_len) as expr}]>,
      )

      /// `sha1` but without the algorithm name
      ///
      /// This is needed because the hash includes the whole signature item keyword line,
      /// and therefore a signature with the `sha1` explicitly stated,
      /// and one without, have different hashes!
      ///
      /// So we mustn't use the `sha1` field for both implicit and explicit use of SHA-1,
      /// or multiple signatures with different syntax would overwrite each others'
      /// different hashes.
      pub sha1_unnamed: Option<[u8; 20]>,
    }

    impl DirectorySignaturesHashesAccu {
        /// Calculate the hash for a signature item and update this accumulator
        fn update_from(
            &mut self,
            algo: &DigestAlgoInSignature,
            body: &SignatureHashInputs,
        ) {
            // Update the hash in self.$UPDATE according to algorithm $AGLO
            // (uses dynamic bindings of those parameters)
            ${define HASH {
                // Avoid recalculating if we don't need to
                self.$UPDATE.get_or_insert_with(|| {
                    let mut h = tor_llcrypto::d::$ALGO::new();
                    h.update(body.body().body());
                    h.update(body.signature_item_kw_spc);
                    h.finalize().into()
                });
            }}

            match &**algo {
              $(
                Some(KeywordOrString::Known($vtype)) => {
                    ${define UPDATE $FNAME}
                    ${define ALGO $vname}
                    $HASH
                }
              )
                None => {
                    ${define UPDATE sha1_unnamed}
                    ${define ALGO Sha1}
                    $HASH
                }
                Some(KeywordOrString::Unknown(..)) => {}
            }
        }

        /// Return the hash value for a specific algorithm, as a slice
        ///
        /// `None` if the value wasn't computed.
        /// That shouldn't happen.
        fn hash_slice_for_verification(
            &self,
            algo: &DigestAlgoInSignature,
        ) -> Option<&[u8]> {
            match &**algo {
              $(
                Some(KeywordOrString::Known($vtype)) => Some(self.$FNAME.as_ref()?),
              )
                None => Some(self.sha1_unnamed.as_ref()?),
                Some(KeywordOrString::Unknown(..)) => None,
            }
        }
    }
}

/// `directory-signature` hash algorithm argument
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::Display, strum::EnumString, Deftly)]
#[derive_deftly(DirectorySignaturesHashesAccu)]
#[non_exhaustive]
#[strum(serialize_all = "snake_case")]
pub enum DirectorySignatureHashAlgo {
    /// SHA-1
    #[deftly(hash_len = "20")]
    Sha1,
    /// SHA-256
    #[deftly(hash_len = "32")]
    Sha256,
}

/// `algorithm` field in a `directory-signature` item
///
/// This is extremely bizarre: it's an *optional item at the start of the arguments*!
// TODO SPEC #350
///
/// So we parse it with some kind of nightmarish lookahead.
///
/// Additionally, to be able to convey the signatures accurately, without breaking them,
/// we must remember whether the argument was present.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:directory-signature>
#[derive(Debug, Clone, derive_more::Deref, derive_more::DerefMut)]
#[allow(clippy::exhaustive_structs)]
pub struct DigestAlgoInSignature(pub Option<KeywordOrString<DirectorySignatureHashAlgo>>);

impl ItemArgumentParseable for DigestAlgoInSignature {
    fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, ArgumentError> {
        let v = if args
            .clone()
            .next()
            // Treat it as a fingerprint if it doesn't have any non-hex characters
            // (including lowercase ones).  If we reuse this item for new algorithms
            // they should have at least one letter g-z in their name.
            .and_then(|s| s.chars().all(|c| c.is_ascii_hexdigit()).then_some(()))
            .is_some()
        {
            // next argument looks enough like a fingerprint that we don't treat as an algo name
            None
        } else {
            Some(KeywordOrString::from_args(args)?)
        };
        Ok(DigestAlgoInSignature(v))
    }
}
impl ItemArgument for DigestAlgoInSignature {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        if let Some(y) = &self.0 {
            y.write_arg_onto(out)?;
        }
        Ok(())
    }
}
impl DigestAlgoInSignature {
    /// Return the actual algorithm
    ///
    /// This handles the defaulting, where an absent argument means `sha1`.
    pub fn algorithm(&self) -> &KeywordOrString<DirectorySignatureHashAlgo> {
        self.as_ref()
            .unwrap_or(&KeywordOrString::Known(DirectorySignatureHashAlgo::Sha1))
    }
}

impl NormalItemArgument for DirectorySignatureHashAlgo {}

/// The signature of a single directory authority on a networkstatus document.
///
/// Implements `ItemValueParseable` which parses without hashing anything;
/// this is mostly useful for use by the `SignatureItemParseable` implementation.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[non_exhaustive]
pub struct Signature {
    /// The name of the digest algorithm used to make the signature.
    ///
    /// Currently sha1 and sh256 are recognized.  Here we only support
    /// sha256.
    pub digest_algo: DigestAlgoInSignature,
    /// Fingerprints of the keys for the authority that made
    /// this signature.
    #[deftly(netdoc(with = authcert::keyids_directory_signature_args))]
    pub key_ids: AuthCertKeyIds,
    /// The signature itself.
    #[deftly(netdoc(object(label = "SIGNATURE"), with = types::raw_data_object))]
    pub signature: Vec<u8>,
}

impl SignatureItemParseable for Signature {
    type HashAccu = DirectorySignaturesHashesAccu;

    fn from_unparsed_and_body(
        item: UnparsedItem,
        body: &SignatureHashInputs<'_>,
        hash: &mut Self::HashAccu,
    ) -> Result<Self, ErrorProblem> {
        let signature = Signature::from_unparsed(item)?;
        hash.update_from(&signature.digest_algo, body);
        Ok(signature)
    }
}

/// A collection of signatures that can be checked on a networkstatus document
///
/// This is derived from the signatures section of a netstatus,
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:signature>,
/// but it is not isomorphic to it, and is not directly parseable.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureGroup {
    /// The document hashes of the signed part of the document
    ///
    /// The pre-parse2 parser always sets `hashes.sha1` and `hashes.sha1_unnamed`
    /// to the same value, which is wrong. which is
    /// [bug #2530](https://gitlab.torproject.org/tpo/core/arti/-/work_items/2530)
    pub hashes: DirectorySignaturesHashesAccu,
    /// The signatures listed on the document.
    pub signatures: Vec<Signature>,
}

/// Error which will prevent us from attempting to verify signatures on a consensus
///
/// This error occurs if we the consensus isn't signed by the right people,
/// or we are lacking authcerts.
///
/// Does not represent actual verification errors.
/// Those show up as `VerifyFailed`, typically [`ConsensusVerifyFailed::InvalidSignature`].
///
/// Can be converted to a `VerifyFailed`,
/// giving [`InsufficientTrustedSigners`](VerifyFailed::InsufficientTrustedSigners).
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusVerifiabilityError {
    /// Insufficient trusted signers
    #[error("consensus not signed by enough authorities")]
    InsufficientTrustedSigners,

    /// Insufficient trusted signers because we are missing authcerts
    #[error("missing auth certs mean we could not verify enough consensuis signatures (need at least {deficit} more, out of {} that are missing)", missing.len())]
    MissingAuthCerts {
        /// The number of additional useful authcerts that would be sufficient
        deficit: usize,
        /// All the authcerts that would be useful
        missing: HashSet<AuthCertKeyIds>,
    },
}

/// Error encountered while verifying a consensus
///
/// Thrown by
/// [`plain::NetworkStatusUnverified::verify`]
/// and
/// [`md::NetworkStatusUnverified::verify`].
///
/// Not used for problems with the validity period:
/// that's handled by `tor-checkable` and shows up as [`tor_checkable::TimeValidityError`].
///
/// Can be converted to a `VerifyFailed` (which, in effect, summarises the error).
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusVerifyFailed {
    /// Certificates or signatures insufficient
    #[error("certs/sigs insufficient")]
    CertificationInsufficient(#[from] ConsensusVerifiabilityError),

    /// One or more signatures failed to verify
    #[error("invalid signature")]
    //
    // Not `#[from]` because we don't want to accidentally convert
    // ConsensusVerifiabilityError -> VerifyFailed -> ConsensusVerifyFailed
    // since that would give the wrong variant.
    InvalidSignature(#[source] VerifyFailed),
}

/// Error encountered while verifying a vote
///
/// Thrown by
/// [`vote::NetworkStatusUnverified::verify`].
///
/// Not used for problems with the validity period:
/// that's handled by `tor-checkable` and shows up as [`tor_checkable::TimeValidityError`].
///
/// Can be converted to a `VerifyFailed` (which, in effect, summarises the error).
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VoteVerifyFailed {
    /// The document signature failed to verify
    #[error("invalid signature")]
    //
    // Not `#[from]` because we don't want to accidentally convert
    // VoteVerifyFailed::Something -> VerifyFailed -> VoteVerifyFailed
    // since that would give the wrong variant.
    InvalidSignature(#[source] VerifyFailed),

    /// Authcert couldn't be parsed
    #[error("unparseable authcert")]
    AuthCertParseError(#[source] parse2::ParseError),

    /// Authcert isn't valid for this vote's validity period
    #[error("authcert not valid for vote period")]
    AuthCertWrongValidity(#[source] tor_checkable::TimeValidityError),

    /// Authcert is for a different authority
    #[error("wrong authcert")]
    AuthCertWrongAuthority,
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
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
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

/// The two shared random values, `shared-rand-*-value`
///
/// As found in the consensus preamble
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-current-value>
/// and a vote's authority section
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#authority-item-shared-rand-value>
#[derive(Debug, Clone, Default, Deftly)]
#[derive_deftly(Constructor, NetdocEncodableFields, NetdocParseableFields)]
#[allow(clippy::exhaustive_structs)]
pub struct SharedRandStatuses {
    /// Global shared-random value for the previous shared-random period.
    pub shared_rand_previous_value: Option<SharedRandStatus>,

    /// Global shared-random value for the current shared-random period.
    pub shared_rand_current_value: Option<SharedRandStatus>,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// Relay weight information - `w` item in routerstatus
///
/// This is a combination of two representations of (subsets of) the same information,
/// from an optional `w` in the document.
///
///  * [`effective`](RelayWeightsItem::effective):
///
///    Always contains the effective weight, as [`RelayWeight`].
///    This is what is used by clients.
///    It does not record whether a `w` line was actually present.
///
///  * [`params`](RelayWeightsItem::params):
///
///    Can represent the presence and whole contents of the `w` line,
///    including all the known and unknown parameters.
///    This is within [`Unknown`], so it is only present with crate `feature = "retain-unknown"`,
///    and only some constructors/parsers record it.
///
/// # Parsing
///
/// Parsing is done with `NetdocParseableFields` rather than `ItemValueParseable`.
/// The `params` are [`Retained`](Unknown::Retained) if `retain_unknown_values` is
/// selected in [`parse2::ParseOptions`].
//
// We use NetdocParseableFields because the containing document, RouterStatus,
// contains `RelayWeightsItem` rather than `Option<RelayWeightsItem>`.
// The item parsing multiplicity machinery would see plain `RelayWeightsItem` as a required item.
//
// This representation also means so that if retaining unknown information is compiled out
// (ie, in clients) each routerstatus entry stored in memory does not need to record
// whether `w` was present, merely what the implications were.
//
// We can't use ItemValueParseable with #[deftly(netdoc(default))]
// because `RelayWeightsItem::default()` is a RelayWeightsItem that definitively
// contains no pazrameters, ie with `Unknown::Retained`,
// and is therefore only conditionally available.
/// # Encoding
///
/// Encoding requires knowing whether a `w` line is to be included, and its contents,
/// so is implemented only with if `effective` is `Unknown::Retained`.
/// The encoding impl is only compiled in with `"retain-unknown"`,
/// and throws [`Bug`] if applied to a `RelayWeightsItem` whose `params` are `Discarded`.
///
/// # Constructors
///
/// An "empty" `RelayWeightsItem` can be constructed with [`RelayWeightsItem::new_no_info`].
///
/// A `RelayWeightsItem` containing only the effective `RelayWeight`
/// can be constructed using [`RelayWeightsItem::from_effective`].
///
/// With `"retain-unknown"`:
/// a `RelayWeightsItem` can be constructed from a [`NetParams<u32>`] using `TryFrom`;
/// and, implements `Default`, which yields a `RelayWeightsItem`
/// representing the (known) absence of a `w` line.
//
// Fields are private to maintain the invariant.
#[derive(Debug, Clone)]
pub struct RelayWeightsItem {
    /// The effective relay weight
    effective: RelayWeight,

    /// The complete parameter set, if available and `w` was present.
    params: Unknown<Option<NetParams<u32>>>,
}

/// Recognized weight fields on a single relay in a consensus
///
/// The part of a `w` item that we understand as a client.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum RelayWeight {
    /// An unmeasured weight for a relay.
    Unmeasured(u32),
    /// An measured weight for a relay.
    Measured(u32),
}

/// Error processing a `w` line's netparams into an effective relay weight
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidRelayWeights {
    /// Invalid value for `Unmeasured`
    #[error("invalid value for Unmeasured")]
    InvalidUnmeasured,
}

/// Authority entry in a consensus - deprecated compatibility type alias
#[deprecated = "renamed to ConsensusAuthorityEntry"]
pub type ConsensusVoterInfo = ConsensusAuthorityEntry;

/// Authority entry in a plain consensus - type alias provided for consistency
pub type PlainAuthorityEntry = ConsensusAuthorityEntry;
/// Authority entry in an md consensus - type alias provided for consistency
pub type MdAuthorityEntry = ConsensusAuthorityEntry;

/// An authority entry as found in a consensus
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority-entry>
///
/// See also [`VoteAuthorityEntry`]
//
// We don't use the `each_variety` system for this because:
//  1. That avoids separating the two consensus authority entry types, which are identical
//  2. The only common fields are `dir-source` and `contact`, so there is little duplication
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor, NetdocEncodable, NetdocParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct ConsensusAuthorityEntry {
    /// Contents of the `dir-source` line about an authority
    #[deftly(constructor)]
    pub dir_source: DirSource,

    /// Human-readable contact information about the authority
    //
    // If more non-intro fields get added that are the same in votes and cosensuses,
    // consider using each_variety.rs or breaking those fields out into
    // `AuthorityEntryCommon` implementing `NetdocParseableFields`, or something.
    #[deftly(constructor)]
    pub contact: ContactInfo,

    /// Digest of the vote that the authority cast to contribute to
    /// this consensus.
    ///
    /// This is not a fixed-length, fixed-algorithm field.
    /// Bizarrely, the algorithm is supposed to be inferred from the length!
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:vote-digest>
    #[deftly(netdoc(single_arg))]
    #[deftly(constructor)]
    pub vote_digest: B16U,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// An authority entry as found in a vote
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority-entry>
///
/// See also [`ConsensusAuthorityEntry`]
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor, NetdocEncodable, NetdocParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct VoteAuthorityEntry {
    /// Contents of the `dir-source` line about an authority
    #[deftly(constructor)]
    pub dir_source: DirSource,

    /// Human-readable contact information about the authority
    #[deftly(constructor)]
    pub contact: ContactInfo,

    /// `legacy-dir-key` - superseded authority identity key
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:legacy-dir-key>
    #[deftly(netdoc(single_arg))]
    pub legacy_dir_key: Option<Fingerprint>,

    /// `shared-rand-participate` - Indicate shared random participation
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-participate>
    pub shared_rand_participate: Option<SharedRandParticipate>,

    /// `shared-rand-commit` - Shared random commitment
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-commit>
    pub shared_rand_commit: Vec<SharedRandCommit>,

    /// Global shared-random values
    #[deftly(netdoc(flatten))]
    pub shared_rand: SharedRandStatuses,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// `shared-rand-participate` in a vote authority entry
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-participate>
//
// We could have done `shared_rand_participate: Option<()>` in VoteAuthorityEntry,
// but then we might end up with variables of type `&Option<()>` etc.
// whose meaning has been detached from its type.
//
// TODO DIRAUTH rework this according to the API design conclusion from !3977 when there is one
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor, ItemValueEncodable, ItemValueParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct SharedRandParticipate {
    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// `shared-rand-commit` in a vote authority entry
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-commit>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deftly)]
// If new protocols use this item with a different version, we'll call it an API break.
#[allow(clippy::exhaustive_enums)]
pub enum SharedRandCommit {
    /// Version 1, the only one supported
    V1(SharedRandCommitV1),

    /// Other versions.  Cannot be encoded.
    // It's not clear that future versions will use this version mechanism.  torspec#408.
    Unknown {},
}

/// `shared-rand-commit` in a vote authority entry
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:shared-rand-commit>
///
/// Version and hash are not explicitly represented.  See torspec#407.
///
/// `ItemValueEncodable` and `ItemValueParseable` impls do not include the fixed arguments;
/// in a netdoc, this type should be used within `SharedRandCommit::V1`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deftly)]
#[derive_deftly(Constructor, ItemValueEncodable, ItemValueParseable)]
#[allow(clippy::exhaustive_structs)]
pub struct SharedRandCommitV1 {
    /// Authority id key, recapitulated.
    // TODO this field shouldn't here at all torspec#407
    #[deftly(constructor)]
    h_kp_auth_id_rsa: Fingerprint,

    /// Commitment
    ///
    /// `TIMESTAMP || SHA3_256(REVEAL)`, as per
    /// <https://spec.torproject.org/srv-spec/specification.html#COMMITREVEAL>
    //
    // TOOD we would like to replace this with a type that separates out the pieces!
    // But that would need a FixedB64 generic over some tor-bytes trait, or something.
    #[deftly(constructor)]
    commit: FixedB64<40>,

    /// Reveal
    ///
    /// `TIMESTAMP || random number`, as per
    /// <https://spec.torproject.org/srv-spec/specification.html#COMMITREVEAL>
    reveal: Option<FixedB64<40>>,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

impl SharedRandCommitV1 {
    /// The fixed arguments that precede the actual value in `shared-rand-commit 1 ...`
    const FIXED_ARGUMENTS: &[&str] = &["1", "sha3-256"];
}
impl ItemValueEncodable for SharedRandCommit {
    fn write_item_value_onto(&self, mut out: ItemEncoder) -> Result<(), Bug> {
        match self {
            SharedRandCommit::V1(values) => {
                for fixed in SharedRandCommitV1::FIXED_ARGUMENTS {
                    out.args_raw_string(fixed);
                }
                values.write_item_value_onto(out)
            }
            SharedRandCommit::Unknown {} => Err(internal!("encoding SharedRandCommit::Unknown")),
        }
    }
}
impl ItemValueParseable for SharedRandCommit {
    fn from_unparsed(mut item: UnparsedItem<'_>) -> Result<Self, ErrorProblem> {
        let mut fixed = SharedRandCommitV1::FIXED_ARGUMENTS.iter().copied();
        let args = item.args_mut();
        let version = args
            .next()
            .ok_or_else(|| args.handle_error("version", ArgumentError::Missing))?;
        if version != fixed.next().expect("nonempty") {
            return Ok(SharedRandCommit::Unknown {});
        }
        for exp in fixed {
            let got = args
                .next()
                .ok_or_else(|| args.handle_error(exp, ArgumentError::Missing))?;
            if got != exp {
                Err(args.handle_error(exp, ArgumentError::Invalid))?;
            }
        }
        let values = SharedRandCommitV1::from_unparsed(item)?;
        Ok(SharedRandCommit::V1(values))
    }
}

// For `ConsensusAuthoritySection`, see `dir_source.rs`.

define_derive_deftly! {
    /// Ad-hoc derive, `impl NetdocParseable for VoteAuthoritySection`
    ///
    /// We can't derive from `VoteAuthoritySection` with the normal macros, because
    /// it's not a document, with its own intro item.  It's just a collection of sub-documents.
    /// The netdoc derive macros don't have support for that - and it would be a fairly
    /// confusing thing to support because you'd end up with nested multiplicities and a whole
    /// variety of "intro item keywords" that were keywords for arbitrary sub-documents.
    ///
    /// Instead, we do that ad-hoc here.  It's less confusing because we don't need to
    /// worry about multiplicity, and because we know what only the outer document is
    /// that will contain this.
    VoteAuthoritySection:

    ${defcond F_NORMAL not(fmeta(netdoc(skip)))}

    impl NetdocParseable for VoteAuthoritySection {
        fn doctype_for_error() -> &'static str {
            "vote.authority.section"
        }
        fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
            VoteAuthorityEntry::is_intro_item_keyword(kw)
        }
        fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
          $(
            ${when F_NORMAL}
            if let y @ Some(_) = $ftype::is_structural_keyword(kw) {
                return y;
            }
          )
            None
        }
        fn from_items<'s>(
            input: &mut ItemStream<'s>,
            stop_outer: stop_at!(),
        ) -> Result<Self, ErrorProblem> {
            let stop_inner = stop_outer
              $(
                ${when F_NORMAL}
                | StopAt($ftype::is_intro_item_keyword)
              )
            ;
            Ok(VoteAuthoritySection { $(
                ${when F_NORMAL}
                $fname: NetdocParseable::from_items(input, stop_inner)?,
            )
                __non_exhaustive: (),
            })
        }
    }

    impl NetdocEncodable for VoteAuthoritySection {
        fn encode_unsigned(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
          $(
            ${when F_NORMAL}
            self.$fname.encode_unsigned(out)?;
          )
          Ok(())
        }
    }
}

/// An authority section in a vote
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>
//
// We have split this out to help encapsulate vote/consensus-specific
// information in a forthcoming overall network status document type.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(VoteAuthoritySection, Constructor)]
#[allow(clippy::exhaustive_structs)]
pub struct VoteAuthoritySection {
    /// Authority entry
    #[deftly(constructor)]
    pub authority: VoteAuthorityEntry,

    /// Authority key certificate
    #[deftly(constructor)]
    pub cert: EmbeddedCert<AuthCert, EncodedAuthCert>,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// Fields in the footer of a consensus
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:footer>
///
/// Not the whole footer, because it lacks the `directory-footer` item.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor, NetdocEncodableFields, NetdocParseableFields)]
#[allow(clippy::exhaustive_structs)]
pub struct ConsensusFooterFields {
    /// `bandwidth-weights`
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:bandwidth-weights>
    #[deftly(netdoc(default))]
    pub bandwidth_weights: NetParams<i32>,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
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

/// A consensus document that lists relays along with their
/// router descriptor documents.
pub type PlainConsensus = plain::Consensus;

/// An PlainConsensus that has been parsed and checked for timeliness,
/// but not for signatures.
pub type UnvalidatedPlainConsensus = plain::UnvalidatedConsensus;

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
    ) -> crate::Result<ProtoStatus> {
        /// Helper: extract a Protocols entry from an item's arguments.
        fn parse(t: Option<&Item<'_, NetstatusKwd>>) -> crate::Result<Protocols> {
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
    fn from_str(s: &str) -> crate::Result<Self> {
        /// Helper: parse a single K=V pair.
        fn parse_pair<U>(p: &str) -> crate::Result<(String, U)>
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
            .try_collect()?;
        Ok(NetParams { params })
    }
}

impl FromStr for SharedRandVal {
    type Err = Error;
    fn from_str(s: &str) -> crate::Result<Self> {
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
    fn from_item(item: &Item<'_, NetstatusKwd>) -> crate::Result<Self> {
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
    fn from_item(item: &Item<'_, NetstatusKwd>) -> crate::Result<Self> {
        if item.kwd() != NetstatusKwd::DIR_SOURCE {
            return Err(
                Error::from(internal!("Bad keyword {:?} on dir-source", item.kwd()))
                    .at_pos(item.pos()),
            );
        }
        let nickname = item
            .required_arg(0)?
            .parse()
            .map_err(|e: InvalidNickname| {
                EK::BadArgument.at_pos(item.pos()).with_msg(e.to_string())
            })?;
        let identity = item.parse_arg(1)?;
        let hostname = item
            .required_arg(2)?
            .parse()
            .map_err(|e: InvalidInternetHost| {
                EK::BadArgument.at_pos(item.pos()).with_msg(e.to_string())
            })?;
        let ip = item.parse_arg(3)?;
        let dir_port = item.parse_arg(4)?;
        let or_port = item.parse_arg(5)?;

        Ok(DirSource {
            nickname,
            identity,
            hostname,
            ip,
            dir_port,
            or_port,
            __non_exhaustive: (),
        })
    }
}

impl ConsensusAuthorityEntry {
    /// Parse a single ConsensusAuthorityEntry from a voter info section.
    fn from_section(sec: &Section<'_, NetstatusKwd>) -> crate::Result<ConsensusAuthorityEntry> {
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

        let contact = sec.required(CONTACT)?;
        // Ideally we would parse_args_as_str but that requires us to
        // impl From<InvalidContactInfo> for crate::Error which is wrong
        // because many it's a footgun which lets you just write ? here
        // resulting in lack of position information.
        // (This is a general problem with the error handling in crate::parse.)
        let contact = contact
            .args_as_str()
            .parse()
            .map_err(|err: InvalidContactInfo| {
                EK::BadArgument
                    .with_msg(err.to_string())
                    .at_pos(contact.pos())
            })?;

        let vote_digest = sec.required(VOTE_DIGEST)?.parse_arg::<B16U>(0)?;

        Ok(ConsensusAuthorityEntry {
            dir_source,
            contact,
            vote_digest,
            __non_exhaustive: (),
        })
    }
}

impl RelayWeightsItem {
    /// Return a new `RelayWeightsItem` containing no information
    ///
    /// As if parsed from a document with no `w` line, discarding unknown information.
    pub fn new_no_info() -> Self {
        RelayWeightsItem {
            effective: RelayWeight::default(),
            params: Unknown::new_discard(),
        }
    }

    /// Return a new `RelayWeightsItem` containing only the effective weight
    pub fn from_effective(effective: RelayWeight) -> Self {
        RelayWeightsItem {
            effective,
            params: Unknown::new_discard(),
        }
    }

    /// Get the effective relay weight (bandwidth estimate) for path selection.
    ///
    /// Invariant: consistent with from [`params`](RelayWeightsItem::params),
    /// if `parsed` isn't [`Discarded`](Unknown::Discarded).
    //
    // We open-code this rather than deriving it so we can provide better docs.
    pub fn effective(&self) -> RelayWeight {
        self.effective
    }

    /// Get the complete parameter set, if this information is available.
    ///
    /// After parsing, this is the parsed but not interpreted `w` item,
    /// or `None` if the document contained no `w` item.
    //
    // We open-code this rather than deriving it because we want to return
    // `Unknown<&...>` rather than `&Unknown<..>`, which the user would just have to .as_ref().
    pub fn params(&self) -> Unknown<&Option<NetParams<u32>>> {
        self.params.as_ref()
    }

    /// Parse a routerweight from a "w" line.
    fn from_item(item: &Item<'_, NetstatusKwd>) -> crate::Result<RelayWeightsItem> {
        if item.kwd() != NetstatusKwd::RS_W {
            return Err(
                Error::from(internal!("Wrong keyword {:?} on W line", item.kwd()))
                    .at_pos(item.pos()),
            );
        }

        let params = item.args_as_str().parse()?;
        let effective = RelayWeight::from_net_params(&params).map_err(|e| e.at_pos(item.pos()))?;

        Ok(RelayWeightsItem {
            effective,
            params: Unknown::new_discard(),
        })
    }

    /// The keyword for parsing and encoding
    const KEYWORD: &str = "w";
}

#[cfg(feature = "retain-unknown")]
impl Default for RelayWeightsItem {
    fn default() -> Self {
        RelayWeightsItem {
            effective: RelayWeight::default(),
            params: Unknown::Retained(None),
        }
    }
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

    /// Parse a routerweight from partially-parsed `w` line in the form of a `NetParams`
    ///
    /// This function is the common part shared between `parse2` and `parse`.
    fn from_net_params(params: &NetParams<u32>) -> crate::Result<RelayWeight> {
        params
            .try_into()
            .map_err(|e: InvalidRelayWeights| EK::BadArgument.with_msg(e.to_string()))
    }
}

impl Default for RelayWeight {
    fn default() -> RelayWeight {
        RelayWeight::Unmeasured(0)
    }
}

impl TryFrom<&NetParams<u32>> for RelayWeight {
    type Error = InvalidRelayWeights;

    fn try_from(params: &NetParams<u32>) -> Result<RelayWeight, InvalidRelayWeights> {
        let bw = params.params.get("Bandwidth");
        let unmeas = params.params.get("Unmeasured");

        let bw = match bw {
            None => return Ok(RelayWeight::Unmeasured(0)),
            Some(b) => *b,
        };

        match unmeas {
            None | Some(0) => Ok(RelayWeight::Measured(bw)),
            Some(1) => Ok(RelayWeight::Unmeasured(bw)),
            _ => Err(InvalidRelayWeights::InvalidUnmeasured),
        }
    }
}

#[cfg(feature = "retain-unknown")]
impl TryFrom<NetParams<u32>> for RelayWeightsItem {
    type Error = InvalidRelayWeights;

    fn try_from(params: NetParams<u32>) -> Result<RelayWeightsItem, InvalidRelayWeights> {
        Ok(RelayWeightsItem {
            effective: (&params).try_into()?,
            params: Unknown::Retained(Some(params)),
        })
    }
}

/// `parse2` impls for types in this modulea
///
/// Separate module for a separate namespace.
mod parse2_impls {
    use super::*;
    pub(super) use parse2::{
        ArgumentError as AE, ArgumentStream, ErrorProblem as EP, ItemArgumentParseable,
        ItemValueParseable, NetdocParseableFields,
    };
    use std::result::Result;

    // The NormalItemArgument bound ensures that this is applied only to sane types eg integers
    impl<T: FromStr + NormalItemArgument> ItemValueParseable for NetParams<T>
    where
        T::Err: std::error::Error,
    {
        fn from_unparsed(item: parse2::UnparsedItem<'_>) -> Result<Self, EP> {
            item.check_no_object()?;
            item.args_copy()
                .into_remaining()
                .parse()
                .map_err(item.invalid_argument_handler("parameters"))
        }
    }

    impl NetdocParseableFields for RelayWeightsItem {
        type Accumulator = Option<NetParams<u32>>;

        fn is_item_keyword(kw: KeywordRef) -> bool {
            kw == Self::KEYWORD
        }

        fn accumulate_item(acc: &mut Self::Accumulator, item: UnparsedItem) -> Result<(), EP> {
            if acc.is_some() {
                return Err(EP::ItemRepeated);
            }
            item.check_no_object()?;
            let params = NetParams::from_unparsed(item)?;
            *acc = Some(params);
            Ok(())
        }

        fn finish(params: Self::Accumulator, items: &ItemStream) -> Result<Self, EP> {
            let effective = params
                .as_ref()
                .map(TryFrom::try_from)
                .transpose()
                .map_err(|_| EP::OtherBadDocument("invalid information in `w` item"))?
                .unwrap_or_default();

            let params = items.parse_options().retain_unknown_values.map(|()| params);

            Ok(RelayWeightsItem { effective, params })
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

/// `encode` impls for types in this modulea
///
/// Separate module for a separate namespace.
mod encode_impls {
    use super::*;
    use std::result::Result;
    pub(crate) use {
        crate::encode::{ItemEncoder, ItemValueEncodable, NetdocEncodableFields},
        tor_error::Bug,
    };

    impl NetdocEncodableFields for RelayWeightsItem {
        fn encode_fields(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
            if let Some(w) = self.params.as_ref().into_retained()? {
                w.write_item_value_onto(out.item(Self::KEYWORD))?;
            }
            Ok(())
        }
    }

    // The NormalItemArgument bound ensures that this is applied only to sane types eg integers
    impl<T: NormalItemArgument + Ord + Display> ItemValueEncodable for NetParams<T> {
        fn write_item_value_onto(&self, mut out: ItemEncoder) -> Result<(), Bug> {
            for (k, v) in self.iter().collect::<BTreeSet<_>>() {
                if k.is_empty()
                    || k.chars()
                        .any(|c| c.is_whitespace() || c.is_control() || c == '=')
                {
                    // TODO torspec#401 see TODO in NetParams<T> definition
                    return Err(bad_api_usage!(
                        "tried to encode NetParms with unreasonable keyword {k:?}"
                    ));
                }
                out.args_raw_string(&format_args!("{k}={v}"));
            }
            Ok(())
        }
    }

    impl ItemValueEncodable for rs::SoftwareVersion {
        fn write_item_value_onto(&self, mut out: ItemEncoder) -> Result<(), Bug> {
            out.args_raw_string(self);
            Ok(())
        }
    }

    impl ItemArgument for IgnoredPublicationTimeSp {
        fn write_arg_onto(&self, out: &mut ItemEncoder) -> Result<(), Bug> {
            out.args_raw_string(&"2000-01-01 00:00:01");
            Ok(())
        }
    }
}

impl ConsensusFooterFields {
    /// Parse a directory footer from a footer section.
    fn from_section(sec: &Section<'_, NetstatusKwd>) -> crate::Result<ConsensusFooterFields> {
        use NetstatusKwd::*;
        sec.required(DIRECTORY_FOOTER)?;

        let bandwidth_weights = sec
            .maybe(BANDWIDTH_WEIGHTS)
            .args_as_str()
            .unwrap_or("")
            .parse()?;

        Ok(ConsensusFooterFields {
            bandwidth_weights,
            __non_exhaustive: (),
        })
    }
}

/// `ProtoStatuses` parsing and encoding
///
/// Separate module for separate namespace
mod proto_statuses_parse2_encode {
    use super::encode_impls::*;
    use super::parse2_impls::*;
    use super::*;
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
            fn finish(acc: Self::Accumulator, items: &ItemStream<'_>) -> Result<Self, EP> {
                let parse = ProtoStatusesParseHelper::finish(acc, items)?;
                let mut out = ProtoStatuses::default();
                $(
                    out.$cr.$rr = parse.[< $rr _ $cr _protocols >];
                )*
                Ok(out)
            }
        }

        impl NetdocEncodableFields for ProtoStatuses {
            fn encode_fields(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
              $(
                self.$cr.$rr.write_item_value_onto(
                    out.item(concat!(stringify!($rr), "-", stringify!($cr), "-protocols"))
                )?;
              )*
                Ok(())
            }
        }
    } } }

    impl_proto_statuses! {
        recommended client;
        recommended relay;
        required client;
        required relay;
    }
}

impl Signature {
    /// Parse a Signature from a directory-signature section
    fn from_item(item: &Item<'_, NetstatusKwd>) -> crate::Result<Signature> {
        if item.kwd() != NetstatusKwd::DIRECTORY_SIGNATURE {
            return Err(Error::from(internal!(
                "Wrong keyword {:?} for directory signature",
                item.kwd()
            ))
            .at_pos(item.pos()));
        }

        let (digest_algo, id_fp, sk_fp) = if item.n_args() > 2 {
            (
                item.required_arg(0)?,
                item.required_arg(1)?,
                item.required_arg(2)?,
            )
        } else {
            // TODO #2530 digest_algo needs to depend on whether SHA1 was stated
            ("sha1", item.required_arg(0)?, item.required_arg(1)?)
        };

        let digest_algo = digest_algo.to_string().parse().void_unwrap();
        let digest_algo = DigestAlgoInSignature(Some(digest_algo));
        let id_fingerprint = id_fp.parse::<Fingerprint>()?.into();
        let sk_fingerprint = sk_fp.parse::<Fingerprint>()?.into();
        let key_ids = AuthCertKeyIds {
            id_fingerprint,
            sk_fingerprint,
        };
        let signature = item.obj("SIGNATURE")?;

        Ok(Signature {
            digest_algo,
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

    /// Find the certificate and assemble the pieces ready for verification
    ///
    /// `None` means precisely that we're missing the authcert.
    fn signature_to_verify<'r>(
        &'r self,
        signed_digest: &'r [u8],
        certs: &'r [AuthCert],
    ) -> Option<ConsensusSignatureToVerify> {
        let cert = self.find_cert(certs)?;
        let key = cert.signing_key();
        Some(ConsensusSignatureToVerify {
            key,
            signed_digest,
            signature: &self.signature,
        })
    }
}

impl EncodeOrd for Signature {
    fn encode_cmp(&self, other: &Self) -> std::cmp::Ordering {
        let k: for<'s> fn(&'_ Signature) -> (&'_ _, &'_ _) = |s| (&s.key_ids, &s.signature);
        Ord::cmp(&k(self), &k(other))
    }
}

/// Signature information in a consensus, to be verified
///
/// Used by callers of [`SignatureGroup::verify_general`],
/// to allow verification to be suppressed if all we wanted to know was
/// whether we have enough signatures and enough authcerts.
#[derive(Debug, Clone, Copy)]
struct ConsensusSignatureToVerify<'r> {
    /// KP_auth_sign_rsa
    key: &'r ll::pk::rsa::PublicKey,

    /// The digest (actual RSA signature payload, before PKCS#11 padding)
    signed_digest: &'r [u8],

    /// The RSA signature value
    signature: &'r [u8],
}

/// Token indicating that signature verification has been done, if required
///
/// Prevents accidentally passing an unintended no-op function as
/// `do_verify` to [`SignatureGroup::verify_general`].
///
/// Write `SignatureVerifiedIfIntended {}` to construct this,
/// only in code which has actually done the verification,
/// or code which is deliberately not verifying at all.
pub(crate) struct SignatureVerifiedIfIntended {}

impl<'r> ConsensusSignatureToVerify<'r> {
    /// Verify this signature
    ///
    fn verify(self) -> Result<SignatureVerifiedIfIntended, VerifyFailed> {
        self.key.verify(self.signed_digest, self.signature)?;
        Ok(SignatureVerifiedIfIntended {})
    }
}

/// How `verify_general` should decide who is a trusted authority
///
/// Don't use this for other purposes
#[derive(Debug, Clone, Copy)]
pub(crate) enum VerifyGeneralTrustedAuthorities<'r> {
    /// Trust these authorities.
    TrustThese {
        /// The HKP_auth_id_rsa
        trusted: &'r [RsaIdentity],
    },

    /// Document is a a vote, so OK if signed by any one of the listed authorities
    AnyOneOfThese {
        /// The HKP_auth_id_rsa
        trusted: &'r [RsaIdentity],
    },

    /// For the benefit of `SignatureGroup::validate`, used by the old parser, only
    ///
    /// Every `AuthCert` passed to `verify_general` is a real authority (!)
    /// (But not necessarily a different one!)
    HazardouslyAssumeAllAuthCertsAreReal {
        /// Total number of authorities that we trust
        ///
        /// Used only to calculate the threshold
        n_authorities: usize,
    },
}

/// Return the minimum number of authorities that we need signatures from
///
/// Enough is strictly more than half.
///
/// The returned value is a [`RangeFrom`](std::ops::RangeFrom), ie an inclusive range.
/// Its `start` value is the minimum acceptable number of authorities
/// from whom we have good signatures.
///
/// Should usually be followed by
/// [`.contains`](std::ops::RangeFrom::contains)`(&actual_number)`.
///
/// # Example
///
/// ```
/// use tor_netdoc::{doc::netstatus::consensus_threshold, parse2::VerifyFailed};
/// # fn main() -> Result<(), VerifyFailed> {
///
/// let n_trusted_authorities = 3;
/// let n_good_signatures_from_different_authorities = 2;
///
/// if consensus_threshold(n_trusted_authorities)
///      .contains(&n_good_signatures_from_different_authorities)
/// {
///     Ok(())
/// } else {
///     Err(VerifyFailed::InsufficientTrustedSigners)
/// }
/// # }
/// ```
pub fn consensus_threshold(n_authorities: usize) -> std::ops::RangeFrom<usize> {
    (n_authorities / 2) + 1 // strict majority
        ..
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

        consensus_threshold(authorities.len()).contains(&signed_by.len())
    }

    /// Return true if the signature group defines a valid signature.
    ///
    /// A signature is valid if it signed by more than half of the
    /// authorities.  This API requires that `n_authorities` is the number of
    /// authorities we believe in, and that every cert in `certs` belongs
    /// to a real authority.
    fn validate(&self, n_authorities: usize, certs: &[AuthCert]) -> Result<(), VerifyFailed> {
        // TODO we ought to take the set of trusted authorities as an argument,
        // rather than use VGTA::HazardouslyAssumeAllAuthCertsAreReal.
        self.verify_general(
            VerifyGeneralTrustedAuthorities::HazardouslyAssumeAllAuthCertsAreReal { n_authorities },
            certs,
            |tv| tv.verify(),
        )
    }

    /// Check signatures (maybe), but not timeliness
    ///
    /// Examines the signatures and collates them with authcerts.
    /// Performs the necessary consensus signature verifications, via `do_verify`.
    ///
    /// If there are not enough authcerts or not enough signatures,
    /// throws a `ConsensusVerifiabilityError`.
    ///
    /// Differs from [`SignatureGroup::validate`]:
    ///
    ///  * Intended also for use with types from parse2.
    ///
    ///  * Yields information about missing authcerts directly in the return value,
    ///    and can be used without actually doing the verification,
    ///    so there's no need for a separate "which certs are we missing" function.
    ///
    ///  * Threshold is passed as a parameter (wanted for votes).
    ///
    ///  * Ability to check authority identities, by passing `trusted_authorities`.
    ///    (done with `authorities_are_correct` in old parser,
    ///    apparently with no engineered safeguard against consensus user omitting to do so).
    ///
    ///    **If `trusted_authorities` is None, all authorities in `certs` are treated as trusted**.
    ///
    ///  * Returns `Result`, not a boolean
    ///
    ///  * We prefer the term `verify` to `validate`.  All this does is signature verification.
    ///
    fn verify_general<E>(
        &self,
        trusted_authorities: VerifyGeneralTrustedAuthorities,
        certs: &[AuthCert],
        do_verify: impl Fn(ConsensusSignatureToVerify) -> Result<SignatureVerifiedIfIntended, E>,
    ) -> Result<(), E>
    where
        ConsensusVerifiabilityError: Into<E>,
    {
        use VerifyGeneralTrustedAuthorities as TA;

        // A set of the authorities (by identity) who have have signed
        // this document.  We use a set here in case `certs` has more
        // than one certificate for a single authority.
        let mut ok: HashSet<RsaIdentity> = HashSet::new();
        let mut missing = HashSet::new();
        let mut verify_failed = Ok(());

        for sig in &self.signatures {
            // Exhaustive pattern makes it hard to accidentally ignore a field.
            let Signature {
                digest_algo,
                key_ids:
                    AuthCertKeyIds {
                        id_fingerprint,
                        // h_kp_auth_sign_rsa, which Signature::check_signature
                        // checks against the authcert.
                        sk_fingerprint: _,
                    },
                // Used by Signature::check_signature
                signature: _,
            } = sig;

            match trusted_authorities {
                TA::TrustThese { trusted } | TA::AnyOneOfThese { trusted } => {
                    if !trusted.contains(id_fingerprint) {
                        continue;
                    }
                }
                TA::HazardouslyAssumeAllAuthCertsAreReal { .. } => {
                    // OK then!
                }
            }

            if ok.contains(id_fingerprint) {
                // We already checked at least one signature using this
                // authority's identity fingerprint.
                continue;
            }

            let Some(d) = self.hashes.hash_slice_for_verification(digest_algo) else {
                // We don't support this kind of digest for this kind
                // of document.
                continue;
            };

            let Some(tv) = sig.signature_to_verify(d, certs) else {
                missing.insert(sig.key_ids);
                continue;
            };
            match do_verify(tv) {
                Ok::<SignatureVerifiedIfIntended, _>(_) => {
                    ok.insert(*id_fingerprint);
                }
                Err(e) => {
                    verify_failed = Err(e);
                }
            }
        }

        let n_authorities = match trusted_authorities {
            TA::TrustThese { trusted } => trusted.len(),
            TA::HazardouslyAssumeAllAuthCertsAreReal { n_authorities: n } => n,
            TA::AnyOneOfThese { .. } => {
                // strict majority of 1 is 1, so n_authorites being 1 leads to threshold of 1
                // (doing it this way avoids having both thresholds and authority counts
                // in the same code area, which might lead to confusing one with the other.
                1
            }
        };
        let threshold = consensus_threshold(n_authorities);

        if threshold.contains(&ok.len()) {
            Ok(())
        } else {
            // Throw the verification error if any of the verifications failed
            verify_failed?;

            // Otherwise report that we're missing certs and/or signers
            Err(if missing.is_empty() {
                ConsensusVerifiabilityError::InsufficientTrustedSigners
            } else {
                let deficit = threshold.start - ok.len();
                ConsensusVerifiabilityError::MissingAuthCerts { missing, deficit }
            }
            .into())
        }
    }
}

impl From<ConsensusVerifiabilityError> for VerifyFailed {
    fn from(cve: ConsensusVerifiabilityError) -> VerifyFailed {
        use ConsensusVerifiabilityError as CVE;
        use VerifyFailed as VF;
        match cve {
            CVE::InsufficientTrustedSigners => VF::InsufficientTrustedSigners,
            CVE::MissingAuthCerts { .. } => VF::InsufficientTrustedSigners,
        }
    }
}

impl From<ConsensusVerifyFailed> for VerifyFailed {
    fn from(cvf: ConsensusVerifyFailed) -> VerifyFailed {
        use ConsensusVerifyFailed as CVF;
        use VerifyFailed as VF;
        match cvf {
            CVF::CertificationInsufficient { .. } => VF::InsufficientTrustedSigners,
            CVF::InvalidSignature { .. } => VF::VerifyFailed,
        }
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::doc::authcert::AuthCertUnverified;
    use crate::encode::{NetdocEncodable, NetdocEncodableFields};
    use crate::parse2::{ParseInput, parse_netdoc, parse_netdoc_multiple};
    use crate::util::regsub;
    use anyhow::Context as _;
    use assert_matches::assert_matches;
    use hex_literal::hex;
    use humantime::parse_rfc3339;
    use std::fmt::Debug;
    use std::fs;
    use std::time::Duration;
    use tor_checkable::TimeBound;

    const CERTS: &str = include_str!("../../testdata/authcerts2.txt");
    const CONSENSUS: &str = include_str!("../../testdata/mdconsensus1.txt");

    const PLAIN_CERTS: &str = include_str!("../../testdata2/cached-certs");
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
    fn parse_and_validate_md() -> crate::Result<()> {
        use std::net::SocketAddr;
        use tor_checkable::{SelfSigned, TimeBound};
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
    fn parse_and_validate_ns() -> crate::Result<()> {
        use tor_checkable::{SelfSigned, TimeBound};
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

    fn gettok(s: &str) -> crate::Result<Item<'_, NetstatusKwd>> {
        let mut reader = NetDocReader::new(s)?;
        let tok = reader.next().unwrap();
        assert!(reader.next().is_none());
        tok
    }

    #[test]
    fn test_weight() {
        let w = gettok("w Unmeasured=1 Bandwidth=6\n").unwrap();
        let w = RelayWeightsItem::from_item(&w).unwrap();
        assert!(!w.effective.is_measured());
        assert!(w.effective.is_nonzero());

        let w = gettok("w Bandwidth=10\n").unwrap();
        let w = RelayWeightsItem::from_item(&w).unwrap();
        assert!(w.effective.is_measured());
        assert!(w.effective.is_nonzero());

        let w = RelayWeightsItem::new_no_info();
        assert!(!w.effective.is_measured());
        assert!(!w.effective.is_nonzero());

        let w = gettok("w Mustelid=66 Cheato=7 Unmeasured=1\n").unwrap();
        let w = RelayWeightsItem::from_item(&w).unwrap();
        assert!(!w.effective.is_measured());
        assert!(!w.effective.is_nonzero());

        let w = gettok("r foo\n").unwrap();
        let w = RelayWeightsItem::from_item(&w);
        assert!(w.is_err());

        let w = gettok("r Bandwidth=6 Unmeasured=Frog\n").unwrap();
        let w = RelayWeightsItem::from_item(&w);
        assert!(w.is_err());

        let w = gettok("r Bandwidth=6 Unmeasured=3\n").unwrap();
        let w = RelayWeightsItem::from_item(&w);
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

        for bad_kw in ["What=The", "", "\n", "\0"] {
            let p = [(bad_kw, 42)].into_iter().collect::<NetParams<i32>>();
            let mut d = NetdocEncoder::new();
            let d = (|| {
                let i = d.item("bad-psrams");
                p.write_item_value_onto(i)?;
                d.finish()
            })();
            let _: tor_error::Bug = d.expect_err(bad_kw);
        }
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

    // consensuses are done in each_flavor.rs: see verify_error_netstatus
    #[test]
    fn verify_error_netstatus_vote() -> Result<(), anyhow::Error> {
        use VerifyFailed as VF;
        use VoteVerifyFailed as VVF;
        use vote::NetworkStatusUnverified as UV;

        let file = "testdata2/v3-status-votes--1";
        let text = fs::read_to_string(file).with_context(|| file.to_owned())?;
        let input = ParseInput::new(&text, file);
        let doc: UV = parse_netdoc(&input)?;
        let trusted = [doc.peek_alleged_authority()];

        let edit_body = |f: &dyn Fn(&mut _)| {
            let (mut body, sigs) = doc.clone().unwrap_unverified();
            f(&mut body);
            UV::from_parts(body, sigs)
        };

        // sabotage the overall signature
        {
            let mut doc = doc.clone();
            for b in &mut doc.sigs.sigs.directory_signature.signature {
                *b = 0xff;
            }
            assert_matches! {
                doc.verify(&trusted),
                Err(VVF::InvalidSignature(VF::VerifyFailed))
            }
        }

        // wrong authority
        {
            let doc = doc.clone();
            assert_matches! {
                doc.verify(&[[0x55; _].into()]),
                Err(VVF::InvalidSignature(VF::InsufficientTrustedSigners))
            }
        }

        // authcert is for a different authority
        {
            let doc = edit_body(&|body| {
                body.authority.authority.dir_source.identity.0 = [0x55; _].into();
            });
            assert_matches! {
                doc.verify(&trusted),
                Err(VVF::AuthCertWrongAuthority)
            }
        }

        // authcert is from a different time
        let with_mutated_lifetime = |f: &dyn Fn(&mut Lifetime)| {
            let doc = edit_body(&|body| f(&mut body.preamble.lifetime));
            assert_matches! {
                doc.verify(&trusted),
                Err(VVF::AuthCertWrongValidity(_))
            }
        };
        let t_past = parse_rfc3339("1990-01-01T00:02:25Z")?;
        let t_future = parse_rfc3339("2010-01-01T00:02:25Z")?;
        with_mutated_lifetime(&|lifetime| lifetime.valid_after.0 = t_future);
        with_mutated_lifetime(&|lifetime| lifetime.fresh_until.0 = t_past);
        with_mutated_lifetime(&|lifetime| lifetime.valid_until.0 = t_past);

        // syntactically invalid authcert
        {
            let mut text = text.clone();
            regsub(&mut text, "^dir-key-expires ", "dir-key-expires-SABOTAGED ");
            let input = ParseInput::new(&text, file);
            let doc: UV = parse_netdoc(&input)?;
            assert_matches! {
                doc.verify(&trusted),
                Err(VVF::AuthCertParseError(..))
            }
        }

        Ok(())
    }

    #[cfg(feature = "retain-unknown")]
    #[allow(clippy::type_complexity)]
    pub(super) fn prep_netstatus_verify<UV: NetdocParseable>(
        file: &str,
    ) -> anyhow::Result<(UV, String, Vec<AuthCert>, Vec<RsaIdentity>, SystemTime)> {
        let text = fs::read_to_string(file).with_context(|| file.to_owned())?;
        let now = parse_rfc3339("2000-01-01T00:02:25Z")?;

        let mut input = ParseInput::new(&text, file);
        input.retain_unknown_values();

        let doc: UV = parse_netdoc(&input)?;

        let certs = {
            let file = "testdata2/cached-certs";
            let text = fs::read_to_string(file)?;
            let input = ParseInput::new(&text, file);
            let certs: Vec<AuthCertUnverified> = parse_netdoc_multiple(&input)?;
            certs
                .into_iter()
                .map(|cert| cert.verify_selfcert(now))
                .collect::<Result<Vec<AuthCert>, _>>()?
        };

        let authorities = certs.iter().map(|cert| *cert.fingerprint).collect_vec();

        Ok((doc, text, certs, authorities, now))
    }

    /// Check that a network document can be parsed and regenerated, mostly identically
    ///
    /// The regenerated encoded form doesn't need to be 100% identical:
    /// it is compared with a *munged* version of the the original input file,
    /// to cope with differences between C Tor and Arti.
    ///
    /// The mungings are:
    ///
    ///  * Some fields' syntax are adjusted, where C Tor and Arti disagree
    ///    in all kinds of network document.
    ///
    ///  * Document-specific, [`MungeForRoundtrip::adjust_exp`]
    #[cfg(feature = "retain-unknown")]
    fn roundtrip_netstatus<UV, V, VE>(
        // TODO DIRAUTH use include_str!, so, at call sites
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4121#note_3428675
        file: &str,
        verify: impl FnOnce(UV, &[RsaIdentity], &[AuthCert]) -> Result<TimeRangeBound<V>, VE>,
        adjust_now: Duration,
    ) -> anyhow::Result<()>
    where
        UV: NetdocParseable + NetdocParseableUnverified + MungeForRoundtrip,
        UV::Signatures: Clone + Debug + NetdocEncodableFields,
        VE: Debug + std::error::Error + Send + Sync + 'static,
        V: Debug + NetdocEncodable,
    {
        let (doc, text, certs, authorities, now) = prep_netstatus_verify::<UV>(file)?;

        let now = now + adjust_now;

        let sigs = doc.inspect_unverified().1.sigs.clone();

        let doc = verify(doc, &authorities, &certs)?.if_valid_at(&now)?;

        println!("{doc:?}");

        let mut enc = NetdocEncoder::new();
        doc.encode_unsigned(&mut enc)?;
        sigs.encode_fields(&mut enc)?;
        let enc = enc.finish()?;

        let mut exp: String = text.clone();

        // TODO DIRAUTH torspec!507 C Tor emits padded base64 in shared-rand-* items.
        regsub(
            //
            &mut exp,
            r#"^(shared-rand-.*)$"#,
            |c: &regex::Captures| {
                let mut s = c[1].to_owned();
                regsub(&mut s, r#"="#, "");
                s
            },
        );

        // We don't manage proper numerical sorting of version numbers.
        // Doing so is awkward.  See the (2nd) TODO on RecommendedTorVersions.
        regsub(
            //
            &mut exp,
            r#"^(client|server)-versions (.+)$"#,
            |c: &regex::Captures| -> String {
                format!(
                    "{}-versions {}",
                    &c[1],
                    iter_join(",", c[2].split(',').sorted()),
                )
            },
        );

        let mut regsub = |re, repl| regsub(&mut exp, re, repl);

        // C Tor writes empty versions lines with trailing space
        regsub(
            //
            r#"^((?:client|server)-versions) $"#,
            "$1",
        );

        // C Tor emits `m` in varying places: after `a` in votes,
        // and at the end of each routerstatus in md consensuses.
        // We emit it at the start of each routerstatus, right after `r`.
        regsub(
            r#"(?x)
                   ( ^    r\ .* \n     )  #  ( r  )  $1, part before where we want to put m's
                   ( (?:     .* \n )*? )  #  (.*? )  $2, the rest, before the m's
                   ( (?:  m\ .* \n )+  )  #  ( m+ )  $3, one or more m's
            "#,
            r#"$1$3$2"#,
        );

        UV::adjust_exp(&mut exp);

        assert_eq_or_diff!(&exp, &enc);

        Ok(())
    }

    trait MungeForRoundtrip {
        /// Munge `s` so that it resembles the output of C Tor
        fn adjust_exp(exp: &mut String);
    }

    /// Test that we can re-encode the consensus we parsed, and that we get the same thing back.
    ///
    /// Well, roughly the same thing.
    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_netstatus_plain() -> anyhow::Result<()> {
        roundtrip_netstatus::<plain::NetworkStatusUnverified, _, _>(
            "testdata2/cached-consensus",
            plain::NetworkStatusUnverified::verify,
            Duration::ZERO,
        )
    }

    impl MungeForRoundtrip for plain::NetworkStatusUnverified {
        fn adjust_exp(exp: &mut String) {
            let mut regsub = |re, repl| regsub(exp, re, repl);

            // We emit the optional `ns`
            // https://spec.torproject.org/dir-spec/consensus-formats.html#item:network-status-version
            regsub(
                r#"^network-status-version 3$"#,
                "network-status-version 3 ns",
            );

            // C Tor writes nontrivial values for `publication` in rs `r` items,
            // but we use a fixed string.
            // https://spec.torproject.org/dir-spec/consensus-formats.html#item:r
            regsub(
                r#"^(r \S+ \S+ \S+) \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"#,
                "$1 2000-01-01 00:00:01",
            );
        }
    }

    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_netstatus_md() -> anyhow::Result<()> {
        roundtrip_netstatus::<md::NetworkStatusUnverified, _, _>(
            "testdata2/cached-microdesc-consensus",
            md::NetworkStatusUnverified::verify,
            Duration::ZERO,
        )
    }

    impl MungeForRoundtrip for md::NetworkStatusUnverified {
        fn adjust_exp(exp: &mut String) {
            let mut regsub = |re, repl| regsub(exp, re, repl);

            // C Tor writes nontrivial values for `publication` in rs `r` items,
            // but we use a fixed string.
            // https://spec.torproject.org/dir-spec/consensus-formats.html#item:r
            //
            // Not the same as in plain consensus: one fewer fields!
            regsub(
                r#"^(r \S+ \S+) \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"#,
                "$1 2000-01-01 00:00:01",
            );
        }
    }

    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_netstatus_vote() -> anyhow::Result<()> {
        roundtrip_netstatus::<vote::NetworkStatusUnverified, _, _>(
            "testdata2/v3-status-votes--1",
            |doc, trusted, _| vote::NetworkStatusUnverified::verify(doc, trusted),
            Duration::from_secs(20),
        )
    }

    impl MungeForRoundtrip for vote::NetworkStatusUnverified {
        fn adjust_exp(exp: &mut String) {
            // C Tor writes items in consensuses a different order to in votes!

            // C Tor writes different stats items with different floating point formats!
            let stats_massage_entry = |e: &str| {
                let mut e = e.to_owned();
                if e.contains('.') {
                    regsub(
                        &mut e,
                        // strip trailing 0's and then trailing `.`
                        r#"(?x)^ ( (?:wfu) = [0-9.]*? )( \.? 0+ ) $"#,
                        "$1",
                    );
                }
                e
            };

            // C Tor writes stats items in votes in an apparently arbitrarily chosen order
            regsub(exp, r#"^stats (.+)$"#, |c: &regex::Captures| -> String {
                format!(
                    "stats {}",
                    iter_join(" ", c[1].split(' ').sorted().map(stats_massage_entry)),
                )
            });

            let mut regsub = |re: &_, repl| regsub(exp, re, repl);

            // C Tor writes *-protocols in an apparently arbitrarily chosen order
            regsub(
                r#"(?x)
                       ^ (recommended-relay-protocols\ .*)  \n
                         (recommended-client-protocols\ .*) \n
                         (required-relay-protocols\ .*)     \n
                         (required-client-protocols\ .*)    \n
                         (known-flags .*)$                  \n
                    "#,
                r#"$5
$2
$1
$4
$3
"#,
            );

            // C Tor emits empty `client-versions` in consensuses, but not in votes.
            // (See also the fixup in `roundtrip_netstatus`, which relates to the *syntax*)
            //
            // Some of our inputs (eg the testdata2 votes) don't contain meaningful
            // info, so to make the C Tor output match our output, add them.
            regsub(
                r#"(?x) ^ (voting-delay\ .*) \n
                          (known-flags\ .*) \n"#,
                "$1
client-versions
server-versions
$2
",
            );

            //#                         (?:  a\ .* \n )?    )   #    a? )           we want to put m's

            for missing_field in [
                "bandwidth-file-headers", // TODO DIRAUTH implement
                "bandwidth-file-digest",  // TODO DIRAUTH implement
                "flag-thresholds",        // TODO DIRAUTH implement
            ] {
                regsub(&format!(r#"^{missing_field} .*\n"#), "");
            }
        }
    }

    fn testdata_live(f: &str) -> String {
        // We implement an overrideable *prefix* rather than suffix, here,
        // so that we can access the files in a totally different directory.
        // (This is helpful with nailing-cargo, amongst other things.)
        let var = "TOR_NETDOC_TESTDATA_LIVE_PREFIX";
        let prefix = std::env::var_os(var)
            .map(|s| s.into_string().expect(var))
            .unwrap_or("testdata-live/".into());
        format!("{prefix}{f}")
    }

    #[allow(clippy::unnecessary_wraps)] // signature needs to match for roundtrip_netstatus
    fn unwrap_unverified_for_test<UV: NetdocParseableUnverified>(
        uv: UV,
        _ids: &[RsaIdentity],
        _certs: &[AuthCert],
    ) -> Result<TimeRangeBound<UV::Body>, std::convert::Infallible> {
        Ok(TimeRangeBound::new(uv.unwrap_unverified().0, ..))
    }

    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_live_plain() -> anyhow::Result<()> {
        roundtrip_netstatus::<plain::NetworkStatusUnverified, _, _>(
            &testdata_live("consensus"),
            unwrap_unverified_for_test,
            Duration::ZERO,
        )
    }

    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_live_md() -> anyhow::Result<()> {
        roundtrip_netstatus::<md::NetworkStatusUnverified, _, _>(
            &testdata_live("consensus-microdesc"),
            unwrap_unverified_for_test,
            Duration::ZERO,
        )
    }

    #[cfg(feature = "retain-unknown")]
    #[test]
    fn roundtrip_live_vote() -> anyhow::Result<()> {
        roundtrip_netstatus::<vote::NetworkStatusUnverified, _, _>(
            &testdata_live("authority"),
            unwrap_unverified_for_test,
            Duration::ZERO,
        )
    }
}
