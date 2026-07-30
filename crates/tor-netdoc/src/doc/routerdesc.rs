//!
//! A "router descriptor" is a signed statement that a relay makes
//! about itself, explaining its keys, its capabilities, its location,
//! and its status.
//!
//! Relays upload their router descriptors to authorities, which use
//! them to build consensus documents.  Old clients and relays used to
//! fetch and use router descriptors for all the relays, but nowadays they use
//! microdescriptors instead.
//!
//! Clients still use router descriptors when communicating with
//! bridges: since bridges are not passed through an authority,
//! clients accept their descriptors directly.
//!
//! For full information about the router descriptor format, see
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! # Limitations
//!
//! TODO: This needs to get tested much more!
//!
//! TODO: This implementation can be memory-inefficient.  In practice,
//! it gets really expensive storing policy entries, family
//! descriptions, parsed keys, and things like that.  We will probably want to
//! de-duplicate those.
//!
//! TODO: There should be accessor functions for some or all of the
//! fields in RouterDesc.  I'm deferring those until I know what they
//! should be.
//!
//! # Availability
//!
//! Most of this module is only available when this crate is built with the
//! `routerdesc` feature enabled.
use crate::encode::{ItemEncoder, ItemValueEncodable};
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules};
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::parse2::{
    ArgumentError, ErrorProblem, ItemValueParseable, SignaturesData, UnparsedItem, VerifyFailed,
};
use crate::types::family::{RelayFamily, RelayFamilyIds};
use crate::types::policy::*;
use crate::types::routerdesc::*;
use crate::types::version::TorVersion;
use crate::types::{EmbeddedCert, misc::*};
use crate::util::PeekableIterator;
use crate::{AllowAnnotations, Error, KeywordEncodable, NetdocErrorKind as EK, Result};

use derive_deftly::Deftly;
use ll::pk::ed25519::Ed25519Identity;
use saturating_time::SaturatingTime;
use std::fmt::Display;
use std::sync::LazyLock;
use std::{iter, net, time};
use tor_basic_utils::intern::Intern;
use tor_cert::{CertType, KeyUnknownCert};
use tor_checkable::timed::TimeRangeBound;
use tor_checkable::{Timebound, signed, timed};
use tor_error::{internal, into_internal};
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public;
use tor_llcrypto::pk::rsa::RsaIdentity;

use digest::Digest;

/// Length of a router descriptor digest
pub const DOC_DIGEST_LEN: usize = 20;

/// The digest of a RouterDesc document, as reported in a NS consensus.
pub type RdDigest = [u8; DOC_DIGEST_LEN];

/// The digest of an ExtraInfo document, as reported in a RouterDesc.
pub type ExtraInfoDigest = [u8; DOC_DIGEST_LEN];

/// A router descriptor, with possible annotations.
#[non_exhaustive]
pub struct AnnotatedRouterDesc {
    /// Annotation for this router descriptor; possibly empty.
    pub ann: RouterAnnotation,
    /// Underlying router descriptor; signatures not checked yet.
    pub router: UncheckedRouterDesc,
}

/// Annotations about a router descriptor, as stored on disc.
#[derive(Default)]
#[non_exhaustive]
pub struct RouterAnnotation {
    /// Description of where we got this router descriptor
    pub source: Option<String>,
    /// When this descriptor was first downloaded.
    pub downloaded: Option<time::SystemTime>,
    /// Description of what we're willing to use this descriptor for.
    pub purpose: Option<String>,
}

/// Information about a relay, parsed from a router descriptor.
///
/// This type does not hold all the information in the router descriptor
///
/// # Limitations
///
/// See module documentation.
///
/// Additionally, some fields that from router descriptors are not yet
/// parsed: see the comments in ROUTER_BODY_RULES for information about those.
///
/// Before using this type to connect to a relay, you MUST check that
/// it is valid, using is_expired_at().
///
/// # Specification
///
/// <https://spec.torproject.org/dir-spec/server-descriptor-format.html>
#[derive(Clone, Debug, Deftly, PartialEq)]
#[derive_deftly(NetdocParseableUnverified, NetdocEncodable)]
#[non_exhaustive]
pub struct RouterDesc {
    /// `router` --- Introduce a router descriptor.
    /// * `router <nickname> <address> <orport> <socksport> <dirport>`
    /// * At start, exactly once.
    pub router: RouterDescIntroItem,

    /// `identity-ed25519` --- Specify the router's ed25519 identity.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:identity-ed25519>
    pub identity_ed25519: EmbeddedCert<Ed25519IdentityCert, KeyUnknownCert>,

    /// `master-key-ed25519` --- Redundantly specify the router's ed25519 identity.
    ///
    /// * `master-key-ed25519 <master key>`
    /// * Exactly once.
    #[deftly(netdoc(single_arg))]
    pub master_key_ed25519: Ed25519Public,

    /// `bandwidth` --- Report router's network bandwidth.
    ///
    /// * `bandwidth <average> <burst> <observed>`
    /// * Exactly once.
    pub bandwidth: Bandwidth,

    /// `platform` --- Describe the platform on which this relay is running.
    ///
    /// * `platform <rest of line>`
    /// * At most once.
    pub platform: Option<RelayPlatform>,

    /// `published` --- Time this descriptor (and extra-info) was generated.
    ///
    /// * `published <date> <time>`
    /// * Exactly once.
    #[deftly(netdoc(single_arg))]
    pub published: Iso8601TimeSp,

    /// `fingerprint` --- Redundant hash of ASN-1 encoding of router identity key.
    ///
    /// * `fingerprint <spaced fingerprint>`
    /// * At most once.
    #[deftly(netdoc(single_arg))]
    pub fingerprint: Option<SpFingerprint>,

    /// `hibernating` --- Whether the relay is hibernating.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:hibernating>
    #[deftly(netdoc(single_arg, default(skip)))]
    pub hibernating: NumericBoolean,

    /// `uptime` --- How long this relay has been continously running
    ///
    /// * `uptime <number>`
    /// * At most once.
    #[deftly(netdoc(single_arg))]
    pub uptime: Option<u64>,

    /// `ntor-onion-key` --- The circuit extension key.
    ///
    /// * `ntor-onion-key <base64 padded key>`
    /// * Exactly once.
    #[deftly(netdoc(single_arg))]
    pub ntor_onion_key: Curve25519Public,

    /// `ntor-onion-key-crosscert` --- Reverse cert by K_ntor on KP_relayid_ed
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:ntor-onion-key-crosscert>
    pub ntor_onion_key_crosscert: NtorOnionKeyCrossCert,

    /// `signing-key` --- Obsolete RSA identity key.
    ///
    /// * `signing-key\n<rsa public key>`
    pub signing_key: ll::pk::rsa::PublicKey,

    /// `accept, reject` --- Exit policy.
    ///
    /// * `accept exitpattern`
    /// * `reject exitpattern`
    /// * Any number of times.
    // TODO: these polices can get bulky too. Perhaps we should
    // de-duplicate them too.
    // Not skipping the default here is probably desirable, as this field should
    // generally always be ended with a default policy (i.e. default accept,
    // default deny).
    #[deftly(netdoc(flatten))]
    pub ipv4_policy: AddrPolicy,

    /// `ipv6-policy` --- Exit plicy summary for IPv6
    ///
    /// * `ipv6-policy <accept/reject> PortList`
    /// * At most once.
    #[deftly(netdoc(default(skip)))]
    pub ipv6_policy: Intern<PortPolicy>,

    /// `overload-general` --- Relay is overloaded.
    ///
    /// * `overload-general 1 <time>`
    /// * At most once.
    // TODO in OverloadGeneral use ConstantString (from !3985) for version
    pub overload_general: Option<OverloadGeneral>,

    /// `contact` --- Server administrator contact information.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:contact>
    pub contact: Option<ContactInfo>,

    /// `family` --- Group relays for the purpose of path selection.
    ///
    /// * `family <LongIdent> ...`
    /// * One or more `LongIdent` arguments.
    /// * At most once.
    #[deftly(netdoc(default(skip)))]
    pub family: Intern<RelayFamily>,

    /// `family-cert` --- Prove membership in a relay family.
    ///
    /// * `family-cert\n<object>`
    /// * Any number of times.
    pub family_cert: RetainedOrderVec<EmbeddedCert<Ed25519FamilyCert, KeyUnknownCert>>,

    /// `caches-extra-info` --- Router provides extra-info as a dirmirror.
    ///
    /// * `caches-extra-info`
    /// * At most once.
    /// * No extra arguments.
    pub caches_extra_info: Option<ItemPresent<CachesExtraInfoToken>>,

    /// `extra-info-digest` --- Hash of the extra-info document.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:extra-info-digest>
    pub extra_info_digest: Option<ExtraInfoDigests>,

    /// `hidden-service-dir` --- Declares this router to be a hidden service directory
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:hidden-service-dir>
    pub hidden_service_dir: Option<ItemPresent<HiddenServiceDirToken>>,

    /// `or-address` --- Alternative ORport address and port
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:or-address>
    #[deftly(netdoc(single_arg))]
    pub or_address: Vec<net::SocketAddr>,

    /// `tunnelled-dir-server` --- Accepts a `BEGIN_DIR` relay message.
    ///
    /// * `tunnelled-dir-server`
    /// * At most once.
    /// * No extra arguments.
    pub tunnelled_dir_server: Option<ItemPresent<TunnelledDirServerToken>>,

    /// `proto` --- Subprotocol capabilities supported.
    ///
    /// * `proto <entries>`
    /// * Exactly once.
    pub proto: tor_protover::Protocols,
}

/// Signatures of a [`RouterDesc`].
///
/// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:router-sig-ed25519>
#[derive(Clone, Debug, PartialEq, Deftly)]
#[derive_deftly(NetdocParseableSignatures, NetdocEncodable)]
#[deftly(netdoc(signatures(hashes_accu = "RouterHashAccu")))]
#[non_exhaustive]
pub struct RouterDescSignatures {
    /// `router-sig-ed25519` --- Ed25519 signature
    ///
    /// Ed25519 signature by the Ed25519 signing key on the SHA-256 digest of
    /// the document prefixed by a magic up until and including the
    /// `router-sig-ed25519` keyword plus space.
    pub router_sig_ed25519: RouterSigEd25519,

    /// `router-signature` --- RSA signature
    ///
    /// * At end, exactly once.
    /// * RSA signature of the document, including `router-sig-ed25519`.
    pub router_signature: RouterSignature,
}

// TODO: Implement a .encode_sign() method.
impl RouterDescUnverified {
    /// Verifies a self-signed [`RouterDescUnverified`].
    ///
    /// This verification performs the following checks:
    /// * [`RouterDesc::identity_ed25519`] is validly signed.
    /// * [`RouterDesc::master_key_ed25519`] is as implied by [`RouterDesc::identity_ed25519`].
    /// * [`RouterDesc::fingerprint`] is as implied by [`RouterDesc::signing_key`].
    /// * [`RouterDesc::ntor_onion_key_crosscert`] is validly signed.
    /// * [`RouterDesc::signing_key`] has correct length and exponent.
    /// * All [`RouterDesc::family_cert`] elements are valid.
    /// * The inner and outer [`RouterDescSignatures`] are valid.
    ///
    /// The result will be a [`TimeRangeBound`] composed from the respective
    /// minimums and maximums found in the present certificates.  For the lower
    /// bound, [`RouterDesc::published`] will also be taken into account when
    /// determining the minimum.
    //
    // We deny the use of unused variables as a hint to use all TimeRangeBound
    // values obtained through a dangerous split.
    #[deny(unused_variables)]
    #[cfg(feature = "incomplete")]
    pub fn verify(self) -> std::result::Result<TimeRangeBound<RouterDesc>, VerifyFailed> {
        // Type annotations to make LSP happy.
        let (mut body, sigs): (RouterDesc, SignaturesData<_>) = (self.body, self.sigs);

        // Collect all timebounds returned by .dangerously_into_parts().
        let mut timebounds = Vec::new();

        // Verify the ed25519 identity certificate.
        // This also includes a check for the master-key-ed25519.
        let (identity_ed25519, identity_ed25519_bounds) =
            Ed25519IdentityCert::verify(body.identity_ed25519.raw_unverified().clone())?
                .dangerously_into_parts(); // TODO DIRMIRROR: Use TimeRangeBoundBuilder
        let Ed25519IdentityCert {
            id_ed25519,
            sign_ed25519,
        } = identity_ed25519;
        if id_ed25519 != body.master_key_ed25519.0 {
            return Err(VerifyFailed::Inconsistent);
        }
        body.identity_ed25519.set_verified(identity_ed25519);
        timebounds.push(identity_ed25519_bounds);

        // Keep track of the published value as lower time bound.
        timebounds.push(TimeRangeBound::new_from_start_end(
            (),
            Some(body.published.0),
            None,
        ));

        // If set, ensure that the fingerprint equals to the signing key id.
        if body
            .fingerprint
            .is_some_and(|fp| fp.0 != body.signing_key.to_rsa_identity())
        {
            return Err(VerifyFailed::Inconsistent);
        }

        // Verify the ntor-onion-key-crosscert.
        // For this, we also need to convert the X25519 ntor key to an Ed25519
        // key using convert_curve25519_to_ed25519_public().
        let ntor_pk = convert_curve25519_to_ed25519_public(
            &body.ntor_onion_key.0,
            // Rust std turns false into 0 and true into 1.
            body.ntor_onion_key_crosscert.bit.0.into(),
        )
        .ok_or(VerifyFailed::Other)?;
        let (ntor_cc, ntor_cc_bounds) = Ed25519NtorCrossCert::verify(
            ntor_pk.into(),
            id_ed25519,
            body.ntor_onion_key_crosscert.cert.raw_unverified().clone(),
        )?
        .dangerously_into_parts(); // TODO DIRMIRROR: Use TimeRangeBoundBuilder
        body.ntor_onion_key_crosscert.cert.set_verified(ntor_cc);
        timebounds.push(ntor_cc_bounds);

        // Verify that the signing key has the proper exponent and length.
        // TODO DIRAUTH: We want to enforce this type wise with parse2.
        if body.signing_key.bits() != 1024 || !body.signing_key.exponent_is(65537) {
            return Err(VerifyFailed::Other);
        }

        // Verify all family certificates.
        for cert in body.family_cert.0.iter_mut() {
            let (cert_verified, cert_bounds) =
                Ed25519FamilyCert::verify(id_ed25519, cert.raw_unverified().clone())?
                    .dangerously_into_parts(); // TODO DIRMIRROR: Use TimeRangeBoundBuilder
            cert.set_verified(cert_verified);
            timebounds.push(cert_bounds);
        }

        // Verify the actual outer document signatures.
        // VerifyFailed should be an okay error variant in case that the hashes
        // were not accumulated, as it is not possible to verify without a
        // hash.
        ed25519::PublicKey::try_from(sign_ed25519)
            .map_err(|_| VerifyFailed::Other)?
            .verify(
                &sigs.hashes.sha256.ok_or(VerifyFailed::VerifyFailed)?,
                &sigs.sigs.router_sig_ed25519.0,
            )?;
        body.signing_key.verify(
            sigs.hashes.sha1.ok_or(VerifyFailed::VerifyFailed)?.as_ref(),
            sigs.sigs.router_signature.0.as_ref(),
        )?;

        // Construct the final TimeRangeBound by obtaining the min and max.
        // TODO DIRMIRROR: Replace the map logic with TimeRangeBound::intersect_bounds().
        // Alternatively, we may also want to add a TimeBoundAccumulator, as outlined in
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4144#note_3440907
        let start_time = timebounds
            .iter()
            .filter_map(|x| x.bounds_start_end().0)
            .max();
        let end_time = timebounds
            .iter()
            .filter_map(|x| x.bounds_start_end().1)
            .min();
        debug_assert!(start_time.is_some()); // At least always obtained from published.
        debug_assert!(end_time.is_some()); // At least always obtained from an edcert.

        Ok(TimeRangeBound::new_from_start_end(
            body, start_time, end_time,
        ))
    }
}

/// Description of the software a relay is running.
///
/// `platform` line in a routerstatus.
/// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:platform>
// TODO: Move this to types/misc.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayPlatform {
    /// Software advertised to be some version of Tor, on some platform.
    Tor(TorVersion, Option<String>),
    /// Software not advertised to be Tor.
    Other(String),
}

/// Zero-sized token type for use in [`RouterDesc::caches_extra_info`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct CachesExtraInfoToken;

/// Zero-sized token type for use in [`RouterDesc::hidden_service_dir`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct HiddenServiceDirToken;

/// Zero-sized token type for use in [`RouterDesc::tunnelled_dir_server`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct TunnelledDirServerToken;

impl std::str::FromStr for RelayPlatform {
    type Err = Error;
    fn from_str(args: &str) -> Result<Self> {
        if args.starts_with("Tor ") {
            let v: Vec<_> = args.splitn(4, ' ').collect();
            match &v[..] {
                ["Tor", ver, "on", p] => {
                    Ok(RelayPlatform::Tor(ver.parse()?, Some((*p).to_string())))
                }
                ["Tor", ver, ..] => Ok(RelayPlatform::Tor(ver.parse()?, None)),
                _ => unreachable!(),
            }
        } else {
            Ok(RelayPlatform::Other(args.to_string()))
        }
    }
}

impl Display for RelayPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Tor(v, Some(p)) => write!(f, "Tor {v} on {p}"),
            Self::Tor(v, None) => write!(f, "Tor {v}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl ItemValueParseable for RelayPlatform {
    fn from_unparsed(item: UnparsedItem<'_>) -> std::result::Result<Self, ErrorProblem> {
        let mut args = item.args_copy();
        item.check_no_object()?;
        args.into_remaining()
            .parse()
            .map_err(|_| args.handle_error("platform", ArgumentError::Invalid))
    }
}

impl ItemValueEncodable for RelayPlatform {
    fn write_item_value_onto(
        &self,
        mut out: ItemEncoder,
    ) -> std::result::Result<(), tor_error::Bug> {
        // Adding a raw string is fine because this is effectively a free form
        // field.
        out.args_raw_string(&self);
        Ok(())
    }
}

decl_keyword! {
    /// RouterKwd is an instance of Keyword, used to denote the different
    /// Items that are recognized as appearing in a router descriptor.
    RouterKwd {
        annotation "@source" => ANN_SOURCE,
        annotation "@downloaded-at" => ANN_DOWNLOADED_AT,
        annotation "@purpose" => ANN_PURPOSE,
        "accept" | "reject" => POLICY,
        "bandwidth" => BANDWIDTH,
        "bridge-distribution-request" => BRIDGE_DISTRIBUTION_REQUEST,
        "caches-extra-info" => CACHES_EXTRA_INFO,
        "contact" => CONTACT,
        "extra-info-digest" => EXTRA_INFO_DIGEST,
        "family" => FAMILY,
        "family-cert" => FAMILY_CERT,
        "fingerprint" => FINGERPRINT,
        "hibernating" => HIBERNATING,
        "identity-ed25519" => IDENTITY_ED25519,
        "ipv6-policy" => IPV6_POLICY,
        "master-key-ed25519" => MASTER_KEY_ED25519,
        "ntor-onion-key" => NTOR_ONION_KEY,
        "ntor-onion-key-crosscert" => NTOR_ONION_KEY_CROSSCERT,
        "or-address" => OR_ADDRESS,
        "platform" => PLATFORM,
        "proto" => PROTO,
        "published" => PUBLISHED,
        "router" => ROUTER,
        "router-sig-ed25519" => ROUTER_SIG_ED25519,
        "router-signature" => ROUTER_SIGNATURE,
        "signing-key" => SIGNING_KEY,
        "tunnelled_dir_server" => TUNNELLED_DIR_SERVER,
        "uptime" => UPTIME,
        // "protocols" once existed, but is obsolete
        // "eventdns" once existed, but is obsolete
        // "allow-single-hop-exits" is also obsolete.
    }
}

/// Rules for parsing a set of router descriptor annotations.
static ROUTER_ANNOTATIONS: LazyLock<SectionRules<RouterKwd>> = LazyLock::new(|| {
    use RouterKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(ANN_SOURCE.rule());
    rules.add(ANN_DOWNLOADED_AT.rule().args(1..));
    rules.add(ANN_PURPOSE.rule().args(1..));
    rules.add(ANN_UNRECOGNIZED.rule().may_repeat().obj_optional());
    // Unrecognized annotations are fine; anything else is an error in this
    // context.
    rules.reject_unrecognized();
    rules.build()
});
/// Rules for tokens that are allowed in the first part of a
/// router descriptor.
static ROUTER_HEADER_RULES: LazyLock<SectionRules<RouterKwd>> = LazyLock::new(|| {
    use RouterKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(ROUTER.rule().required().args(5..));
    rules.add(IDENTITY_ED25519.rule().required().no_args().obj_required());
    // No other intervening tokens are permitted in the header.
    rules.reject_unrecognized();
    rules.build()
});
/// Rules for  tokens that are allowed in the first part of a
/// router descriptor.
static ROUTER_BODY_RULES: LazyLock<SectionRules<RouterKwd>> = LazyLock::new(|| {
    use RouterKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(MASTER_KEY_ED25519.rule().required().args(1..));
    rules.add(PLATFORM.rule());
    rules.add(PUBLISHED.rule().required());
    rules.add(FINGERPRINT.rule());
    rules.add(UPTIME.rule().args(1..));
    rules.add(NTOR_ONION_KEY.rule().required().args(1..));
    rules.add(
        NTOR_ONION_KEY_CROSSCERT
            .rule()
            .required()
            .args(1..=1)
            .obj_required(),
    );
    rules.add(SIGNING_KEY.rule().no_args().required().obj_required());
    rules.add(POLICY.rule().may_repeat().args(1..));
    rules.add(IPV6_POLICY.rule().args(2..));
    rules.add(FAMILY.rule().args(1..));
    rules.add(FAMILY_CERT.rule().obj_required().may_repeat());
    rules.add(CACHES_EXTRA_INFO.rule().no_args());
    rules.add(OR_ADDRESS.rule().may_repeat().args(1..));
    rules.add(TUNNELLED_DIR_SERVER.rule());
    rules.add(PROTO.rule().required().args(1..));
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    // TODO: these aren't parsed yet.  Only authorities use them.
    {
        rules.add(BANDWIDTH.rule().required().args(3..));
        rules.add(BRIDGE_DISTRIBUTION_REQUEST.rule().args(1..));
        rules.add(HIBERNATING.rule().args(1..));
        rules.add(CONTACT.rule());
    }
    // TODO: this is ignored for now.
    {
        rules.add(EXTRA_INFO_DIGEST.rule().args(1..));
    }
    rules.build()
});

/// Rules for items that appear at the end of a router descriptor.
static ROUTER_SIG_RULES: LazyLock<SectionRules<RouterKwd>> = LazyLock::new(|| {
    use RouterKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(ROUTER_SIG_ED25519.rule().required().args(1..));
    rules.add(ROUTER_SIGNATURE.rule().required().no_args().obj_required());
    // No intervening tokens are allowed in the footer.
    rules.reject_unrecognized();
    rules.build()
});

impl RouterAnnotation {
    /// Extract a single RouterAnnotation (possibly empty) from a reader.
    fn take_from_reader(reader: &mut NetDocReader<'_, RouterKwd>) -> Result<RouterAnnotation> {
        use RouterKwd::*;
        let mut items = reader.pause_at(|item| item.is_ok_with_non_annotation());

        let body = ROUTER_ANNOTATIONS.parse(&mut items)?;

        let source = body.maybe(ANN_SOURCE).args_as_str().map(String::from);
        let purpose = body.maybe(ANN_PURPOSE).args_as_str().map(String::from);
        let downloaded = body
            .maybe(ANN_DOWNLOADED_AT)
            .parse_args_as_str::<Iso8601TimeSp>()?
            .map(|t| t.into());
        Ok(RouterAnnotation {
            source,
            downloaded,
            purpose,
        })
    }
}

/// A parsed router descriptor whose signatures and/or validity times
/// may or may not be invalid.
pub type UncheckedRouterDesc = signed::SignatureGated<timed::TimeRangeBound<RouterDesc>>;

/// How long after its published time is a router descriptor officially
/// supposed to be usable?
const ROUTER_EXPIRY_SECONDS: u64 = 5 * 86400;

/// How long before its published time is a router descriptor usable?
// TODO(nickm): This valid doesn't match C tor, which only enforces this rule
// ("routers should not some from the future") at directory authorities, and
// there only enforces a 12-hour limit (`ROUTER_ALLOW_SKEW`).  Eventually we
// should probably harmonize these cutoffs.
const ROUTER_PRE_VALIDITY_SECONDS: u64 = 86400;

impl RouterDesc {
    /// Return a reference to this relay's RSA identity.
    pub fn rsa_identity(&self) -> RsaIdentity {
        self.signing_key.to_rsa_identity()
    }

    /// Return a reference to this relay's Ed25519 identity.
    pub fn ed_identity(&self) -> &Ed25519Identity {
        &self
            .identity_ed25519
            .get()
            .expect("ed25519 identity cert should be verified")
            .id_ed25519
    }

    /// Return a reference to the list of subprotocol versions supported by this
    /// relay.
    pub fn protocols(&self) -> &tor_protover::Protocols {
        &self.proto
    }

    /// Return a reference to this relay's Ntor onion key.
    pub fn ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        &self.ntor_onion_key.0
    }

    /// Return the publication
    pub fn published(&self) -> time::SystemTime {
        self.published.0
    }

    /// Return an iterator of every `SocketAddr` at which this descriptor says
    /// its relay can be reached.
    pub fn or_ports(&self) -> impl Iterator<Item = net::SocketAddr> + '_ {
        iter::once(net::SocketAddr::new(
            self.router.address.into(),
            self.router.orport,
        ))
        .chain(self.or_address.iter().copied())
    }

    /// Return the declared family of this descriptor.
    pub fn family(&self) -> Intern<RelayFamily> {
        Intern::clone(&self.family)
    }

    /// Return the authenticated family IDs of this descriptor.
    pub fn family_ids(&self) -> RelayFamilyIds {
        RelayFamilyIds::from_iter(
            self.family_cert
                .iter()
                .map(|cert| cert.get().expect("unverified family cert?"))
                .map(|cert| cert.family_ed25519.into()),
        )
    }

    /// Helper: tokenize `s`, and divide it into three validated sections.
    fn parse_sections<'a>(
        reader: &mut NetDocReader<'a, RouterKwd>,
    ) -> Result<(
        Section<'a, RouterKwd>,
        Section<'a, RouterKwd>,
        Section<'a, RouterKwd>,
    )> {
        use RouterKwd::*;

        // Parse everything up through the header.
        let header = ROUTER_HEADER_RULES.parse(
            reader.pause_at(|item| item.is_ok_with_kwd_not_in(&[ROUTER, IDENTITY_ED25519])),
        )?;

        // Parse everything up to but not including the signature.
        let body =
            ROUTER_BODY_RULES.parse(reader.pause_at(|item| {
                item.is_ok_with_kwd_in(&[ROUTER_SIGNATURE, ROUTER_SIG_ED25519])
            }))?;

        // Parse the signature.
        let sig = ROUTER_SIG_RULES.parse(reader.pause_at(|item| {
            item.is_ok_with_annotation() || item.is_ok_with_kwd(ROUTER) || item.is_empty_line()
        }))?;

        Ok((header, body, sig))
    }

    /// Try to parse `s` as a router descriptor.
    ///
    /// Does not actually check liveness or signatures; you need to do that
    /// yourself before you can do the output.
    ///
    /// The following fields are not parsed with the legacy parser and their
    /// default value is used instead.
    /// * [`RouterDescIntroItem::socksport`] in [`RouterDesc::router`]
    /// * [`RouterDesc::bandwidth`]
    /// * [`RouterDesc::or_address`]
    ///     * Extracts only the first IPv6 address.
    /// * [`RouterDesc::hibernating`]
    /// * [`RouterDesc::overload_general`]
    /// * [`RouterDesc::contact`]
    /// * [`RouterDesc::extra_info_digest`]
    /// * [`RouterDesc::hidden_service_dir`]
    pub fn parse(s: &str) -> Result<UncheckedRouterDesc> {
        let mut reader = crate::parse::tokenize::NetDocReader::new(s)?;
        let result = Self::parse_internal(&mut reader).map_err(|e| e.within(s))?;
        // We permit empty lines at the end of router descriptors, since there's
        // a known issue in Tor relays that causes them to return them this way.
        reader
            .should_be_exhausted_but_for_empty_lines()
            .map_err(|e| e.within(s))?;
        Ok(result)
    }

    /// Helper: parse a router descriptor from `s`.
    ///
    /// This function does the same as parse(), but returns errors based on
    /// byte-wise positions.  The parse() function converts such errors
    /// into line-and-byte positions.
    fn parse_internal(r: &mut NetDocReader<'_, RouterKwd>) -> Result<UncheckedRouterDesc> {
        // TODO: This function is too long!  The little "paragraphs" here
        // that parse one item at a time should be made into sub-functions.
        use RouterKwd::*;

        let s = r.str();
        let (header, body, sig) = RouterDesc::parse_sections(r)?;

        // Unwrap should be safe because inline `required` call should return
        // `Error::MissingToken` if `ROUTER` is not `Ok`
        #[allow(clippy::unwrap_used)]
        let start_offset = header.required(ROUTER)?.offset_in(s).unwrap();

        // ed25519 identity and signing key.
        //
        // Small digression: This is terrible.  We return a tuple containing
        // a KeyUnknownCert and an UncheckedCert.  This is because of a parse2
        // and legacy incongruence.  For parse2, we need the KeyUnknownCert
        // to properly include it into EmbeddedCert, whereas the legacy parser
        // will need an UncheckedCert because the verification chain is
        // performed at the end.  Because tor-cert's method all consume self,
        // we can not go backwards, meaning we have to store two separate
        // copies.  It is also not possible to do the conversion to
        // UncheckedCert later, because then we lose the error context returned
        // in EK::BadObjectVal if the signed-by extension is missing.
        //
        let (ku_identity_cert, identity_cert, ed25519_signing_key) = {
            let cert_tok = header.required(IDENTITY_ED25519)?;
            // Unwrap should be safe because above `required` call should
            // return `Error::MissingToken` if `IDENTITY_ED25519` is not `Ok`
            #[allow(clippy::unwrap_used)]
            if cert_tok.offset_in(s).unwrap() < start_offset {
                return Err(EK::MisplacedToken
                    .with_msg("identity-ed25519")
                    .at_pos(cert_tok.pos()));
            }
            let ku_cert = cert_tok
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .check_cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)?
                .into_unchecked();
            let cert = ku_cert.clone().should_have_signing_key().map_err(|err| {
                EK::BadObjectVal
                    .err()
                    .with_source(err)
                    .at_pos(cert_tok.pos())
            })?;
            let sk = *cert.peek_subject_key().as_ed25519().ok_or_else(|| {
                EK::BadObjectVal
                    .at_pos(cert_tok.pos())
                    .with_msg("wrong type for signing key in cert")
            })?;
            let sk: ll::pk::ed25519::PublicKey = sk.try_into().map_err(|_| {
                EK::BadObjectVal
                    .at_pos(cert_tok.pos())
                    .with_msg("invalid ed25519 signing key")
            })?;
            (ku_cert, cert, sk)
        };

        // master-key-ed25519: required, and should match certificate.
        #[allow(unexpected_cfgs)]
        let ed25519_identity_key = {
            let master_key_tok = body.required(MASTER_KEY_ED25519)?;
            let ed_id: Ed25519Public = master_key_tok.parse_arg(0)?;
            let ed_id: ll::pk::ed25519::Ed25519Identity = ed_id.into();
            if ed_id != *identity_cert.peek_signing_key() {
                #[cfg(not(fuzzing))] // No feature here; never omit in production.
                return Err(EK::BadObjectVal
                    .at_pos(master_key_tok.pos())
                    .with_msg("master-key-ed25519 does not match key in identity-ed25519"));
            }
            ed_id
        };

        // Legacy RSA identity
        let rsa_identity_key: ll::pk::rsa::PublicKey = body
            .required(SIGNING_KEY)?
            .parse_obj::<RsaPublicParse1Helper>("RSA PUBLIC KEY")?
            .check_len_eq(1024)?
            .check_exponent(65537)?
            .into();
        let rsa_identity = rsa_identity_key.to_rsa_identity();

        let ed_sig = sig.required(ROUTER_SIG_ED25519)?;
        let rsa_sig = sig.required(ROUTER_SIGNATURE)?;
        // Unwrap should be safe because above `required` calls should return
        // an `Error::MissingToken` if `ROUTER_...` is not `Ok`
        #[allow(clippy::unwrap_used)]
        let ed_sig_pos = ed_sig.offset_in(s).unwrap();
        #[allow(clippy::unwrap_used)]
        let rsa_sig_pos = rsa_sig.offset_in(s).unwrap();

        if ed_sig_pos > rsa_sig_pos {
            return Err(EK::UnexpectedToken
                .with_msg(ROUTER_SIG_ED25519.to_str())
                .at_pos(ed_sig.pos()));
        }

        // Extract ed25519 signature.
        let ed_signature: ll::pk::ed25519::ValidatableEd25519Signature = {
            let mut d = ll::d::Sha256::new();
            d.update(&b"Tor router descriptor signature v1"[..]);
            let signed_end = ed_sig_pos + b"router-sig-ed25519 ".len();
            d.update(
                s.get(start_offset..signed_end)
                    .ok_or(internal!("chopped utf8"))?,
            );
            let d = d.finalize();
            let sig: [u8; 64] = ed_sig
                .parse_arg::<B64>(0)?
                .into_array()
                .map_err(|_| EK::BadSignature.at_pos(ed_sig.pos()))?;
            let sig = ll::pk::ed25519::Signature::from(sig);
            ll::pk::ed25519::ValidatableEd25519Signature::new(ed25519_signing_key, sig, &d)
        };

        // Extract legacy RSA signature.
        let rsa_signature: ll::pk::rsa::ValidatableRsaSignature = {
            let mut d = ll::d::Sha1::new();
            let signed_end = rsa_sig_pos + b"router-signature\n".len();
            d.update(
                s.get(start_offset..signed_end)
                    .ok_or(internal!("chopped utf8"))?,
            );
            let d = d.finalize();
            let sig = rsa_sig.obj("SIGNATURE")?;
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            ll::pk::rsa::ValidatableRsaSignature::new(&rsa_identity_key, &sig, &d)
        };

        // router nickname ipv4addr orport socksport dirport
        let (nickname, ipv4addr, orport, dirport) = {
            let rtrline = header.required(ROUTER)?;
            (
                rtrline.required_arg(0)?.parse::<Nickname>().map_err(|e| {
                    EK::BadArgument
                        .with_msg(e.to_string())
                        .at_pos(rtrline.pos())
                })?,
                rtrline.parse_arg::<net::Ipv4Addr>(1)?,
                rtrline.parse_arg(2)?,
                // Skipping socksport.
                rtrline.parse_arg(4)?,
            )
        };

        // uptime
        let uptime = body.maybe(UPTIME).parse_arg(0)?;

        // published time.
        let published = body
            .required(PUBLISHED)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?;

        // ntor key
        let ntor_onion_key: Curve25519Public = body.required(NTOR_ONION_KEY)?.parse_arg(0)?;
        // ntor crosscert
        let (cc_sig, cc_expiry, cc_cert) = {
            let cc = body.required(NTOR_ONION_KEY_CROSSCERT)?;
            let sign: u8 = cc.parse_arg(0)?;
            if sign != 0 && sign != 1 {
                return Err(EK::BadArgument.at_pos(cc.arg_pos(0)).with_msg("not 0 or 1"));
            }
            let ntor_as_ed: ll::pk::ed25519::PublicKey =
                ll::pk::keymanip::convert_curve25519_to_ed25519_public(&ntor_onion_key.0, sign)
                    .ok_or_else(|| {
                        EK::BadArgument
                            .at_pos(cc.pos())
                            .with_msg("Uncheckable crosscert")
                    })?;

            let cert = cc
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .into_unchecked();
            let (_, sig, expiry) = Ed25519NtorCrossCert::verify_inner(
                ntor_as_ed.into(),
                ed25519_identity_key,
                cert.clone(),
            )
            .map_err(|_| EK::BadSignature.err())?;

            let cert = NtorOnionKeyCrossCert {
                bit: NumericBoolean(sign != 0),
                // Okay to call because we added the signature to the batch.
                cert: EmbeddedCert::new(Ed25519NtorCrossCert::dangerous_new_unverified(), cert),
            };

            (sig, expiry, cert)
        };

        // List of subprotocol versions
        let proto = {
            let proto_tok = body.required(PROTO)?;
            proto_tok
                .args_as_str()
                .parse::<tor_protover::Protocols>()
                .map_err(|e| EK::BadArgument.at_pos(proto_tok.pos()).with_source(e))?
        };

        // tunneled-dir-server
        let is_dircache = ((dirport != 0) || body.get(TUNNELLED_DIR_SERVER).is_some())
            .then_some(ItemPresent::default());

        // caches-extra-info
        let is_extrainfo_cache = body.get(CACHES_EXTRA_INFO).map(|_| ItemPresent::default());

        // fingerprint: check for consistency with RSA identity.
        if let Some(fp_tok) = body.get(FINGERPRINT) {
            let fp: RsaIdentity = fp_tok.args_as_str().parse::<SpFingerprint>()?.into();
            if fp != rsa_identity {
                return Err(EK::BadArgument
                    .at_pos(fp_tok.pos())
                    .with_msg("fingerprint does not match RSA identity"));
            }
        }

        // Family
        let family = {
            let mut family = body
                .maybe(FAMILY)
                .parse_args_as_str::<RelayFamily>()?
                .unwrap_or_else(RelayFamily::new);
            if !family.is_empty() {
                // If this family is nonempty, we add our own RSA id to it, on
                // the theory that doing so will improve the odds of having a
                // canonical family shared by all of the members of this family.
                // If the family is empty, there's no point in adding our own ID
                // to it, and doing so would only waste memory.
                family.push(rsa_identity);
            }
            family.intern()
        };

        // Family ids (for "happy families")
        //
        // Unfortunately we have to store this as a tuple of KeyUnknownCert and
        // UncheckedCert due to a parse2/legacy incongruence.  parse2 requires
        // KeyUnknownCert for EmbeddedCert whereas the legacy parser needs
        // descendants of it obtained by passing it irreversibly through the
        // tor_cert verification chain.
        let family_certs = body
            .slice(FAMILY_CERT)
            .iter()
            .map(|ent| {
                let ku = ent
                    .parse_obj::<UnvalidatedEdCert>("FAMILY CERT")?
                    .check_cert_type(CertType::FAMILY_V_IDENTITY)?
                    .check_subject_key_is(identity_cert.peek_signing_key())?
                    .into_unchecked();
                let unchecked = ku.clone().should_have_signing_key().map_err(|e| {
                    EK::BadObjectVal
                        .with_msg("missing public key")
                        .at_pos(ent.pos())
                        .with_source(e)
                })?;
                Ok((ku, unchecked))
            })
            .collect::<Result<Vec<_>>>()?;

        // or-address
        // Extract at most one ipv6 address from the list.  It's not great,
        // but it's what the legacy parser does.
        let mut ipv6addr = Vec::with_capacity(1);
        for tok in body.slice(OR_ADDRESS) {
            if let Ok(net::SocketAddr::V6(a)) = tok.parse_arg::<net::SocketAddr>(0) {
                ipv6addr.push(a.into());
                break;
            }
            // We skip over unparsable addresses. Is that right?
        }

        // platform
        let platform = body.maybe(PLATFORM).parse_args_as_str::<RelayPlatform>()?;

        // ipv4_policy
        let ipv4_policy = {
            let mut pol = AddrPolicy::new();
            for ruletok in body.slice(POLICY).iter() {
                let accept = match ruletok.kwd_str() {
                    "accept" => RuleKind::Accept,
                    "reject" => RuleKind::Reject,
                    _ => {
                        return Err(Error::from(internal!(
                            "tried to parse a strange line as a policy"
                        ))
                        .at_pos(ruletok.pos()));
                    }
                };
                let pat: AddrPortPattern = ruletok
                    .args_as_str()
                    .parse()
                    .map_err(|e| EK::BadPolicy.at_pos(ruletok.pos()).with_source(e))?;
                pol.push(accept, pat);
            }
            pol
        };

        // ipv6 policy
        let ipv6_policy = match body.get(IPV6_POLICY) {
            Some(p) => p
                .args_as_str()
                .parse()
                .map_err(|e| EK::BadPolicy.at_pos(p.pos()).with_source(e))?,
            // Unwrap is safe here because str is not empty
            #[allow(clippy::unwrap_used)]
            None => "reject 1-65535".parse::<PortPolicy>().unwrap(),
        };

        // Now we're going to collect signatures and expiration times.
        let (identity_cert, identity_sig) = identity_cert.dangerously_split().map_err(|err| {
            EK::BadObjectVal
                .with_msg("missing public key")
                .with_source(err)
        })?;
        let mut signatures: Vec<Box<dyn ll::pk::ValidatableSignature>> = vec![
            Box::new(rsa_signature),
            Box::new(ed_signature),
            Box::new(identity_sig),
            Box::new(cc_sig),
        ];

        let identity_cert = identity_cert.dangerously_assume_timely();
        let mut expirations = vec![
            published
                .0
                .saturating_add(time::Duration::new(ROUTER_EXPIRY_SECONDS, 0)),
            identity_cert.expiry(),
            cc_expiry,
        ];

        // As outlined above, we have to do this ... :/
        //
        // Composing the verified part of the EmbeddedCert by just extracting
        // the key alone is OK because it gets checked at the end anyways
        // due to the push to signatures and expirations.
        let mut embedded_family_certs = Vec::with_capacity(family_certs.len());
        for (ku_cert, cert) in family_certs {
            let family_ed25519 = *cert.peek_signing_key();
            let (inner, sig) = cert.dangerously_split().map_err(into_internal!(
                "Missing a public key that was previously there."
            ))?;
            let embedded_cert = EmbeddedCert::new(Ed25519FamilyCert { family_ed25519 }, ku_cert);
            signatures.push(Box::new(sig));
            expirations.push(inner.dangerously_assume_timely().expiry());
            embedded_family_certs.push(embedded_cert);
        }

        // Unwrap is safe here because `expirations` array is not empty
        #[allow(clippy::unwrap_used)]
        let expiry = *expirations.iter().min().unwrap();

        let start_time = published
            .0
            .saturating_sub(time::Duration::new(ROUTER_PRE_VALIDITY_SECONDS, 0));

        let desc = RouterDesc {
            router: RouterDescIntroItem {
                nickname,
                address: ipv4addr,
                orport,
                socksport: 0,
                dirport,
            },
            identity_ed25519: EmbeddedCert::new(
                Ed25519IdentityCert {
                    id_ed25519: ed25519_identity_key,
                    sign_ed25519: ed25519_signing_key.into(),
                },
                ku_identity_cert,
            ),
            master_key_ed25519: ed25519_identity_key.into(),
            bandwidth: Default::default(),
            platform,
            published,
            fingerprint: Some(rsa_identity.into()),
            hibernating: Default::default(),
            uptime,
            ntor_onion_key,
            ntor_onion_key_crosscert: cc_cert,
            signing_key: rsa_identity_key,
            ipv4_policy,
            ipv6_policy: ipv6_policy.intern(),
            overload_general: Default::default(),
            contact: Default::default(),
            family,
            family_cert: embedded_family_certs.into(),
            caches_extra_info: is_extrainfo_cache,
            extra_info_digest: Default::default(),
            hidden_service_dir: Default::default(),
            or_address: ipv6addr,
            tunnelled_dir_server: is_dircache,
            proto,
        };

        let time_gated = timed::TimeRangeBound::new(desc, start_time..expiry);
        let sig_gated = signed::SignatureGated::new(time_gated, signatures);

        Ok(sig_gated)
    }
}

/// An iterator that parses one or more (possibly annotated
/// router descriptors from a string.
//
// TODO: This is largely copy-pasted from MicrodescReader. Can/should they
// be merged?
pub struct RouterReader<'a> {
    /// True iff we accept annotations
    annotated: bool,
    /// Reader that we're extracting items from.
    reader: NetDocReader<'a, RouterKwd>,
}

/// Skip this reader forward until the next thing it reads looks like the
/// start of a router descriptor.
///
/// Used to recover from errors.
fn advance_to_next_routerdesc(reader: &mut NetDocReader<'_, RouterKwd>, annotated: bool) {
    use RouterKwd::*;
    loop {
        let item = reader.peek();
        match item {
            Some(Ok(t)) => {
                let kwd = t.kwd();
                if (annotated && kwd.is_annotation()) || kwd == ROUTER {
                    return;
                }
            }
            Some(Err(_)) => {
                // Skip over broken tokens.
            }
            None => {
                return;
            }
        }
        let _ = reader.next();
    }
}

impl<'a> RouterReader<'a> {
    /// Construct a RouterReader to take router descriptors from a string.
    pub fn new(s: &'a str, allow: &AllowAnnotations) -> Result<Self> {
        let reader = NetDocReader::new(s)?;
        let annotated = allow == &AllowAnnotations::AnnotationsAllowed;
        Ok(RouterReader { annotated, reader })
    }

    /// Extract an annotation from this reader.
    fn take_annotation(&mut self) -> Result<RouterAnnotation> {
        if self.annotated {
            RouterAnnotation::take_from_reader(&mut self.reader)
        } else {
            Ok(RouterAnnotation::default())
        }
    }

    /// Extract an annotated router descriptor from this reader
    ///
    /// (internal helper; does not clean up on failures.)
    fn take_annotated_routerdesc_raw(&mut self) -> Result<AnnotatedRouterDesc> {
        let ann = self.take_annotation()?;
        let router = RouterDesc::parse_internal(&mut self.reader)?;
        Ok(AnnotatedRouterDesc { ann, router })
    }

    /// Extract an annotated router descriptor from this reader
    ///
    /// Ensure that at least one token is consumed
    fn take_annotated_routerdesc(&mut self) -> Result<AnnotatedRouterDesc> {
        let pos_orig = self.reader.pos();
        let result = self.take_annotated_routerdesc_raw();
        if result.is_err() {
            if self.reader.pos() == pos_orig {
                // No tokens were consumed from the reader.  We need
                // to drop at least one token to ensure we aren't in
                // an infinite loop.
                //
                // (This might not be able to happen, but it's easier to
                // explicitly catch this case than it is to prove that
                // it's impossible.)
                let _ = self.reader.next();
            }
            advance_to_next_routerdesc(&mut self.reader, self.annotated);
        }
        result
    }
}

impl<'a> Iterator for RouterReader<'a> {
    type Item = Result<AnnotatedRouterDesc>;
    fn next(&mut self) -> Option<Self::Item> {
        // Is there a next token? If not, we're done.
        self.reader.peek()?;

        Some(
            self.take_annotated_routerdesc()
                .map_err(|e| e.within(self.reader.str())),
        )
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
    use std::{net::Ipv4Addr, str::FromStr, time::Duration};

    use crate::{
        encode::{NetdocEncodable, NetdocEncoder},
        parse2::{self, NetdocParseableUnverified, ParseInput},
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_checkable::TimeValidityError;
    use tor_llcrypto::pk::{curve25519, ed25519::Ed25519PublicKey, rsa};

    use super::*;
    const TESTDATA: &str = include_str!("../../testdata/routerdesc1.txt");
    const TESTDATA2: &str = include_str!("../../testdata/routerdesc2.txt");
    // Generated with a patched C tor to include "happy family" IDs.
    const TESTDATA3: &str = include_str!("../../testdata/routerdesc3.txt");

    fn read_bad(fname: &str) -> String {
        use std::fs;
        use std::path::PathBuf;
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("testdata");
        path.push("bad-routerdesc");
        path.push(fname);

        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn parse_arbitrary() -> Result<()> {
        use std::str::FromStr;
        use tor_checkable::{SelfSigned, TimeBound};
        let rd = RouterDesc::parse(TESTDATA)?
            .check_signature()?
            .dangerously_assume_timely();

        assert_eq!(rd.router.nickname.as_str(), "Akka");
        assert_eq!(rd.router.orport, 443);
        assert_eq!(rd.router.dirport, 0);
        assert_eq!(rd.uptime, Some(1036923));
        assert_eq!(
            rd.family.as_ref(),
            &RelayFamily::from_str(
                "$303509ab910ef207b7438c27435c4a2fd579f1b1 \
                 $56927e61b51e6f363fb55498150a6ddfcf7077f2"
            )
            .unwrap()
        );

        assert_eq!(
            rd.rsa_identity().to_string(),
            "$56927e61b51e6f363fb55498150a6ddfcf7077f2"
        );
        assert_eq!(
            rd.ed_identity().to_string(),
            "CVTjf1oeaL616hH+1+UvYZ8OgkwF3z7UMITvJzm5r7A"
        );
        assert_eq!(
            rd.protocols().to_string(),
            "Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 \
             HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 \
             Padding=2 Relay=1-4"
        );

        assert_eq!(
            hex::encode(rd.ntor_onion_key().to_bytes()),
            "329b3b52991613392e35d1a821dd6753e1210458ecc3337f7b7d39bfcf5da273"
        );
        assert_eq!(
            rd.published(),
            humantime::parse_rfc3339("2022-11-14T19:58:52Z").unwrap()
        );
        assert_eq!(
            rd.or_ports().collect::<Vec<_>>(),
            vec![
                "95.216.33.58:443".parse().unwrap(),
                "[2a01:4f9:2a:2145::2]:443".parse().unwrap(),
            ]
        );

        Ok(())
    }

    #[test]
    fn parse_no_tap_key() -> Result<()> {
        use tor_checkable::{SelfSigned, TimeBound};
        let _rd = RouterDesc::parse(TESTDATA2)?
            .check_signature()?
            .dangerously_assume_timely();

        Ok(())
    }

    #[test]
    fn test_bad() {
        use crate::Pos;
        use crate::types::policy::PolicyError;
        fn check(fname: &str, e: &Error) {
            let text = read_bad(fname);
            let rd = RouterDesc::parse(&text);
            assert!(rd.is_err());
            assert_eq!(&rd.err().unwrap(), e);
        }

        check(
            "bad-sig-order",
            &EK::UnexpectedToken
                .with_msg("router-sig-ed25519")
                .at_pos(Pos::from_line(50, 1)),
        );
        check(
            "bad-start1",
            &EK::MisplacedToken
                .with_msg("identity-ed25519")
                .at_pos(Pos::from_line(1, 1)),
        );
        check("bad-start2", &EK::MissingToken.with_msg("identity-ed25519"));
        check(
            "mismatched-fp",
            &EK::BadArgument
                .at_pos(Pos::from_line(12, 1))
                .with_msg("fingerprint does not match RSA identity"),
        );
        check("no-ed-sk", &EK::MissingToken.with_msg("identity-ed25519"));

        check(
            "bad-cc-sign",
            &EK::BadArgument
                .at_pos(Pos::from_line(34, 26))
                .with_msg("not 0 or 1"),
        );
        check(
            "bad-ipv6policy",
            &EK::BadPolicy
                .at_pos(Pos::from_line(43, 1))
                .with_source(PolicyError::InvalidPolicy),
        );
        check(
            "no-ed-id-key-in-cert",
            &EK::BadObjectVal
                .at_pos(Pos::from_line(2, 1))
                .with_source(tor_cert::CertError::MissingPubKey),
        );
        check(
            "non-ed-sk-in-cert",
            &EK::BadObjectVal
                .at_pos(Pos::from_line(2, 1))
                .with_msg("wrong type for signing key in cert"),
        );
        check(
            "bad-ed-sk-in-cert",
            &EK::BadObjectVal
                .at_pos(Pos::from_line(2, 1))
                .with_msg("invalid ed25519 signing key"),
        );
        check(
            "mismatched-ed-sk-in-cert",
            &EK::BadObjectVal
                .at_pos(Pos::from_line(8, 1))
                .with_msg("master-key-ed25519 does not match key in identity-ed25519"),
        );
    }

    #[test]
    fn parse_multiple_annotated() {
        use crate::AllowAnnotations;
        let mut s = read_bad("bad-cc-sign");
        s += "\
@uploaded-at 2020-09-26 18:15:41
@source \"127.0.0.1\"
";
        s += TESTDATA;
        s += "\
@uploaded-at 2020-09-26 18:15:41
@source \"127.0.0.1\"
";
        s += &read_bad("mismatched-fp");

        let rd = RouterReader::new(&s, &AllowAnnotations::AnnotationsAllowed).unwrap();
        let v: Vec<_> = rd.collect();
        assert!(v[0].is_err());
        assert!(v[1].is_ok());
        assert_eq!(
            v[1].as_ref().unwrap().ann.source,
            Some("\"127.0.0.1\"".to_string())
        );
        assert!(v[2].is_err());
    }

    #[test]
    fn test_platform() {
        let tests = [
            // Test with platform.
            (
                "Tor 0.4.4.4-alpha on a flying bison",
                RelayPlatform::Tor(
                    "0.4.4.4-alpha".parse().unwrap(),
                    Some("a flying bison".to_string()),
                ),
            ),
            // Test without platform but potentially weird spacing.
            (
                "Tor 0.4.4.4-alpha on",
                RelayPlatform::Tor("0.4.4.4-alpha".parse().unwrap(), None),
            ),
            (
                "Tor 0.4.4.4-alpha ",
                RelayPlatform::Tor("0.4.4.4-alpha".parse().unwrap(), None),
            ),
            (
                "Tor 0.4.4.4-alpha",
                RelayPlatform::Tor("0.4.4.4-alpha".parse().unwrap(), None),
            ),
            // Test other.
            ("arti 0.0.0", RelayPlatform::Other("arti 0.0.0".to_string())),
        ];
        for (input, output) in tests {
            assert_eq!(input.parse::<RelayPlatform>().unwrap(), output);

            // Round-trip test with input stripped of " on" suffix and trimmed.
            // Otherwise we cannot really make this work because certain inputs
            // contain redundant data on purpose.
            let input = input.strip_suffix(" on").unwrap_or(input);
            let input = input.trim();
            assert_eq!(output.to_string(), input);
        }
    }

    #[test]
    fn test_family_ids() -> Result<()> {
        use tor_checkable::{SelfSigned, TimeBound};
        let rd = RouterDesc::parse(TESTDATA3)?
            .check_signature()?
            .dangerously_assume_timely();

        assert_eq!(
            rd.family_ids().as_ref(),
            &[
                "ed25519:7sToQRuge1bU2hS0CG0ViMndc4m82JhO4B4kdrQey80"
                    .parse()
                    .unwrap(),
                "ed25519:szHUS3ItRd9uk85b1UVnOZx1gg4B0266jCpbuIMNjcM"
                    .parse()
                    .unwrap(),
            ]
        );

        Ok(())
    }

    /// Simple decoding and round-trip encoding for "normal" router descriptors.
    ///
    /// In other words: No edge cases and such.
    #[test]
    fn test_parse2_simple() {
        let input = ParseInput::new(
            include_str!("../../testdata2/cached-descriptors.new"),
            "cached-descriptors.new",
        );
        let rd = parse2::parse_netdoc_multiple::<RouterDescUnverified>(&input)
            .unwrap()
            .into_iter()
            .map(|rd| {
                #[cfg(feature = "incomplete")]
                rd.clone().verify().unwrap();
                rd.unwrap_unverified()
            })
            .map(|(body, sig)| (body, sig.sigs))
            .collect::<Vec<(RouterDesc, RouterDescSignatures)>>();
        assert_eq!(rd.len(), 20);
        assert_eq!(
            rd[0].0.router,
            RouterDescIntroItem {
                nickname: "test002a".parse().unwrap(),
                address: net::Ipv4Addr::LOCALHOST,
                orport: 5102,
                socksport: 0,
                dirport: 7102
            }
        );
        assert_eq!(
            rd[0].0.fingerprint.unwrap(),
            "257D 06F0 360B B224 6388 724F 109E C089 5A1D 41FB"
                .parse()
                .unwrap()
        );

        // Round-trip encoding by verifying that decoding it equals the original.
        // This is the best we can get as the current encoder is not bug for
        // bug compatible with the CTor one (i.e. absence of TAP and different
        // order), so this is the closest we can get.
        //
        // Unfortunately, we cannot verify the re-encoded signatures, because
        // the re-encoded body misses the TAP related fields which are accounted
        // for in the signature however.
        let mut out = NetdocEncoder::new();
        for (body, sig) in &rd {
            body.encode_unsigned(&mut out).unwrap();
            sig.encode_unsigned(&mut out).unwrap();
        }
        let out = out.finish().unwrap();
        let input2 = ParseInput::new(out.as_str(), "<router descriptor encoding>");
        let rd2 = parse2::parse_netdoc_multiple::<RouterDescUnverified>(&input2)
            .unwrap()
            .into_iter()
            .map(|rd| rd.unwrap_unverified())
            .map(|(body, sig)| (body, sig.sigs))
            .collect::<Vec<(RouterDesc, _)>>();
        assert_eq!(rd, rd2);
    }

    /// Very bad encode and sign method for router descriptors.
    // TODO: Replace with proper one, once it exists
    fn rd_encode_sign(doc: &RouterDesc, rsa: &rsa::KeyPair, ed25519: &ed25519::Keypair) -> String {
        /// Helper for writing out router-sig-ed25519.
        #[derive(Deftly)]
        #[derive_deftly(NetdocEncodable)]
        struct Ed25519Writer {
            router_sig_ed25519: RouterSigEd25519,
        }

        /// Helper for writing out router-signature.
        #[derive(Deftly)]
        #[derive_deftly(NetdocEncodable)]
        struct RsaWriter {
            router_signature: RouterSignature,
        }

        // Add the router-sig-ed25519 signature.
        let mut out = NetdocEncoder::new();
        doc.encode_unsigned(&mut out).unwrap();
        Ed25519Writer {
            router_sig_ed25519: RouterSigEd25519::new_sign_netdoc(
                ed25519,
                &out,
                "router-sig-ed25519",
            )
            .unwrap(),
        }
        .encode_unsigned(&mut out)
        .unwrap();

        // Add the router-signature signature.
        RsaWriter {
            router_signature: RouterSignature(
                RsaSha1Signature::new_sign_netdoc(rsa, &out, "router-signature")
                    .unwrap()
                    .signature,
            ),
        }
        .encode_unsigned(&mut out)
        .unwrap();

        out.finish().unwrap()
    }

    /// Test for various succeeding and failing verifications.
    #[test]
    #[cfg(feature = "incomplete")]
    fn test_verify() {
        // Generate keys we will use later.
        let rng = &mut testing_rng();
        let rsa_id = rsa::KeyPair::generate(rng).unwrap();
        let ed25519_id = ed25519::Keypair::generate(rng);
        let ed25519_sign = ed25519::Keypair::generate(rng);
        let curve25519_ntor = curve25519::StaticSecret::random_from_rng(&mut *rng);
        let curve25519_ntor = curve25519::StaticKeypair {
            secret: curve25519_ntor.clone(),
            public: (&curve25519_ntor).into(),
        };
        let ed25519_ntor = tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_private(
            &curve25519_ntor.secret,
        )
        .unwrap();

        // Values arbitrarily chosen for expirations.
        let too_early = Iso8601TimeSp::from_str("2026-05-01 03:00:00").unwrap().0;
        let published = Iso8601TimeSp::from_str("2026-06-01 03:00:00").unwrap().0;
        let now = Iso8601TimeSp::from_str("2026-06-10 15:30:12").unwrap().0;
        let expiration = Iso8601TimeSp::from_str("2026-06-20 03:00:00").unwrap().0;
        let expired = expiration + Duration::from_secs(60 * 60 * 24);

        // Very boilerplatey construction of a router descriptor.
        let mut rd = RouterDesc {
            router: RouterDescIntroItem {
                nickname: "foo".parse().unwrap(),
                address: Ipv4Addr::LOCALHOST,
                orport: 9000,
                socksport: 0,
                dirport: 0,
            },
            identity_ed25519: Ed25519IdentityCert::new_signed(
                &ed25519_id,
                Ed25519Identity::from(ed25519_sign.public_key()),
                expiration,
            )
            .unwrap(),
            master_key_ed25519: Ed25519Identity::from(ed25519_id.public_key()).into(),
            bandwidth: Bandwidth {
                average: 0,
                burst: 0,
                observed: 0,
            },
            platform: None,
            published: published.into(),
            fingerprint: Some(rsa_id.to_public_key().to_rsa_identity().into()),
            hibernating: NumericBoolean(false),
            uptime: None,
            ntor_onion_key: Curve25519Public(curve25519_ntor.public),
            ntor_onion_key_crosscert: NtorOnionKeyCrossCert {
                bit: NumericBoolean(ed25519_ntor.1 == 1),
                cert: Ed25519NtorCrossCert::new_signed(
                    &ed25519_ntor.0,
                    ed25519_id.public_key().into(),
                    expiration,
                )
                .unwrap(),
            },
            signing_key: rsa_id.to_public_key(),
            ipv4_policy: AddrPolicy::default(),
            ipv6_policy: Default::default(),
            overload_general: None,
            contact: None,
            family: Default::default(),
            family_cert: Default::default(),
            caches_extra_info: Some(Default::default()),
            extra_info_digest: None,
            hidden_service_dir: Some(Default::default()),
            or_address: Default::default(),
            tunnelled_dir_server: Some(Default::default()),
            proto: tor_protover::Protocols::new(),
        };
        let rd_original = rd.clone();

        let verify =
            |rd: &RouterDesc| -> std::result::Result<TimeRangeBound<RouterDesc>, VerifyFailed> {
                let encoded = rd_encode_sign(rd, &rsa_id, &ed25519_sign);
                let decoded = parse2::parse_netdoc::<RouterDescUnverified>(&ParseInput::new(
                    &encoded,
                    "<test_invalid>",
                ))
                .unwrap();
                decoded.verify()
            };

        // Test valid and invalid timestamps.
        assert_eq!(
            verify(&rd).unwrap().if_valid_at(&too_early).unwrap_err(),
            TimeValidityError::NotYetValid(published.duration_since(too_early).unwrap())
        );
        verify(&rd).unwrap().if_valid_at(&published).unwrap();
        // This is our good/"everything is working" test
        verify(&rd).unwrap().if_valid_at(&now).unwrap();
        verify(&rd).unwrap().if_valid_at(&expiration).unwrap();
        assert_eq!(
            verify(&rd).unwrap().if_valid_at(&expired).unwrap_err(),
            TimeValidityError::Expired(expired.duration_since(expiration).unwrap())
        );

        // Let's make the certificate inconsistent by changing the master key.
        rd.master_key_ed25519 = Ed25519Public(Ed25519Identity::from([0x12; 32]));
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::Inconsistent);
        rd = rd_original.clone();

        // Set the published to expired (weird on many levels).
        rd.published = expired.into();
        assert_eq!(
            verify(&rd).unwrap().if_valid_at(&now).unwrap_err(),
            TimeValidityError::NotYetValid(expired.duration_since(now).unwrap())
        );
        rd = rd_original.clone();

        // Have an inconsistent fingerprint.
        let other_rsa_key = rsa::KeyPair::generate(rng).unwrap();
        rd.fingerprint = Some(other_rsa_key.to_public_key().to_rsa_identity().into());
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::Inconsistent);
        // It should fail with a different error if we change the signing key.
        // (No longer inconsistent but simply not validly signed)
        rd.signing_key = other_rsa_key.to_public_key();
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::VerifyFailed);
        // It should work again if we set it to None.
        rd.signing_key = rd_original.signing_key.clone();
        rd.fingerprint = None;
        verify(&rd).unwrap().if_valid_at(&now).unwrap();
        rd = rd_original.clone();

        // If we change the ntor-onion-key, the crosscert verification will fail.
        // We must generate a valid random key here because otherwise, decompress
        // will fail.
        let other_curve25519 = curve25519::StaticSecret::random_from_rng(&mut *rng);
        let other_curve25519 = (&other_curve25519).into();
        rd.ntor_onion_key = Curve25519Public(other_curve25519);
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::VerifyFailed);
        rd = rd_original.clone();

        // Testing for a signature key of the wrong size is hard because
        // tor-llcrypto makes it purposely hard to generate key sizes other
        // than 1024 bit.

        // TODO: Test family certificates.

        // Violate the outer ed25519 signatures, which can be done by swapping
        // the signing key to something else.
        let different_ed25519_sign = ed25519::Keypair::generate(rng);
        rd.identity_ed25519 = Ed25519IdentityCert::new_signed(
            &ed25519_id,
            Ed25519Identity::from(different_ed25519_sign.public_key()),
            expiration,
        )
        .unwrap();
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::VerifyFailed);
        rd = rd_original.clone();

        // Violate the outer RSA signature by swapping the signing key and
        // "disabling" the fingerprint.
        let different_rsa_id = rsa::KeyPair::generate(rng).unwrap();
        rd.signing_key = different_rsa_id.to_public_key();
        rd.fingerprint = None;
        assert_eq!(verify(&rd).unwrap_err(), VerifyFailed::VerifyFailed);
    }
}
