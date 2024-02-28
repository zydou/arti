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
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules};
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::types::family::RelayFamily;
use crate::types::misc::*;
use crate::types::policy::*;
use crate::types::version::TorVersion;
use crate::util::PeekableIterator;
use crate::{doc, AllowAnnotations, Error, NetdocErrorKind as EK, Result};

use ll::pk::ed25519::Ed25519Identity;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::{net, time};
use tor_checkable::{signed, timed, Timebound};
use tor_error::internal;
use tor_llcrypto as ll;
use tor_llcrypto::pk::rsa::RsaIdentity;

use digest::Digest;

/// The digest of a RouterDesc document, as reported in a NS consensus.
pub type RdDigest = [u8; 20];

/// A router descriptor, with possible annotations.
#[allow(dead_code)]
pub struct AnnotatedRouterDesc {
    /// Annotation for this router descriptor; possibly empty.
    ann: RouterAnnotation,
    /// Underlying router descriptor; signatures not checked yet.
    router: UncheckedRouterDesc,
}

/// Annotations about a router descriptor, as stored on disc.
#[allow(dead_code)] // don't warn about fields not getting read.
#[derive(Default)]
pub struct RouterAnnotation {
    /// Description of where we got this router descriptor
    source: Option<String>,
    /// When this descriptor was first downloaded.
    downloaded: Option<time::SystemTime>,
    /// Description of what we're willing to use this descriptor for.
    purpose: Option<String>,
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
#[allow(dead_code)] // don't warn about fields not getting read.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    non_exhaustive
)]
#[derive(Clone, Debug)]
pub struct RouterDesc {
    /// Human-readable nickname for this relay.
    ///
    /// This is not secure, and not guaranteed to be unique.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    nickname: Nickname,
    /// IPv4 address for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    ipv4addr: Option<net::Ipv4Addr>,
    /// IPv4 ORPort for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    orport: u16,
    /// IPv6 address and port for this relay.
    // TODO: we don't use a socketaddrv6 because we don't care about
    // the flow and scope fields.  We should decide whether that's a
    // good idea.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    ipv6addr: Option<(net::Ipv6Addr, u16)>,
    /// Directory port for contacting this relay for direct HTTP
    /// directory downloads.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    dirport: u16,
    /// Declared uptime for this relay, in seconds.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    uptime: Option<u64>,
    /// Time when this router descriptor was published.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    published: time::SystemTime,
    /// Ed25519 identity certificate (identity key authenticating a
    /// signing key)
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    identity_cert: tor_cert::Ed25519Cert,
    /// RSA identity key for this relay. (Deprecated; never use this without
    /// the ed25519 identity as well).
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    rsa_identity_key: ll::pk::rsa::PublicKey,
    /// RSA identity key for this relay. (Deprecated; never use this without
    /// the ed25519 identity as well).
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    rsa_identity: ll::pk::rsa::RsaIdentity,
    /// Key for extending a circuit to this relay using the ntor protocol.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    ntor_onion_key: ll::pk::curve25519::PublicKey,
    /// Key for extending a circuit to this relay using the
    /// (deprecated) TAP protocol.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    tap_onion_key: ll::pk::rsa::PublicKey,
    /// List of subprotocol versions supported by this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    proto: Arc<tor_protover::Protocols>,
    /// True if this relay says it's a directory cache.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    is_dircache: bool,
    /// True if this relay says that it caches extrainfo documents.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    is_extrainfo_cache: bool,
    /// Declared family members for this relay.  If two relays are in the
    /// same family, they shouldn't be used in the same circuit.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    family: Arc<RelayFamily>,
    /// Software and version that this relay says it's running.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    platform: Option<RelayPlatform>,
    /// A complete address-level policy for which IPv4 addresses this relay
    /// says it supports.
    // TODO: these polices can get bulky too. Perhaps we should
    // de-duplicate them too.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    ipv4_policy: AddrPolicy,
    /// A summary of which ports this relay is willing to connect to
    /// on IPv6.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    ipv6_policy: Arc<PortPolicy>,
}

/// Description of the software a relay is running.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayPlatform {
    /// Software advertised to be some version of Tor, on some platform.
    Tor(TorVersion, String),
    /// Software not advertised to be Tor.
    Other(String),
}

impl std::str::FromStr for RelayPlatform {
    type Err = Error;
    fn from_str(args: &str) -> Result<Self> {
        if args.starts_with("Tor ") {
            let v: Vec<_> = args.splitn(4, ' ').collect();
            match &v[..] {
                ["Tor", ver, "on", p] => Ok(RelayPlatform::Tor(ver.parse()?, (*p).to_string())),
                ["Tor", ver, ..] => Ok(RelayPlatform::Tor(ver.parse()?, "".to_string())),
                _ => unreachable!(),
            }
        } else {
            Ok(RelayPlatform::Other(args.to_string()))
        }
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
        "fingerprint" => FINGERPRINT,
        "hibernating" => HIBERNATING,
        "identity-ed25519" => IDENTITY_ED25519,
        "ipv6-policy" => IPV6_POLICY,
        "master-key-ed25519" => MASTER_KEY_ED25519,
        "ntor-onion-key" => NTOR_ONION_KEY,
        "ntor-onion-key-crosscert" => NTOR_ONION_KEY_CROSSCERT,
        "onion-key" => ONION_KEY,
        "onion-key-crosscert" => ONION_KEY_CROSSCERT,
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
static ROUTER_ANNOTATIONS: Lazy<SectionRules<RouterKwd>> = Lazy::new(|| {
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
static ROUTER_HEADER_RULES: Lazy<SectionRules<RouterKwd>> = Lazy::new(|| {
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
static ROUTER_BODY_RULES: Lazy<SectionRules<RouterKwd>> = Lazy::new(|| {
    use RouterKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(MASTER_KEY_ED25519.rule().required().args(1..));
    rules.add(PLATFORM.rule());
    rules.add(PUBLISHED.rule().required());
    rules.add(FINGERPRINT.rule());
    rules.add(UPTIME.rule().args(1..));
    rules.add(ONION_KEY.rule().no_args().required().obj_required());
    rules.add(
        ONION_KEY_CROSSCERT
            .rule()
            .required()
            .no_args()
            .obj_required(),
    );
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
static ROUTER_SIG_RULES: Lazy<SectionRules<RouterKwd>> = Lazy::new(|| {
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
pub type UncheckedRouterDesc = signed::SignatureGated<timed::TimerangeBound<RouterDesc>>;

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
    pub fn rsa_identity(&self) -> &RsaIdentity {
        &self.rsa_identity
    }

    /// Return a reference to this relay's Ed25519 identity.
    pub fn ed_identity(&self) -> &Ed25519Identity {
        self.identity_cert
            .signing_key()
            .expect("No ed25519 identity key on identity cert")
    }

    /// Return a reference to the list of subprotocol versions supported by this
    /// relay.
    pub fn protocols(&self) -> &tor_protover::Protocols {
        self.proto.as_ref()
    }

    /// Return a reference to this relay's Ntor onion key.
    pub fn ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        &self.ntor_onion_key
    }

    /// Return the publication
    pub fn published(&self) -> time::SystemTime {
        self.published
    }

    /// Return an iterator of every `SocketAddr` at which this descriptor says
    /// its relay can be reached.
    pub fn or_ports(&self) -> impl Iterator<Item = net::SocketAddr> + '_ {
        self.ipv4addr
            .map(|a| net::SocketAddr::new(a.into(), self.orport))
            .into_iter()
            .chain(self.ipv6addr.map(net::SocketAddr::from))
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
    pub fn parse(s: &str) -> Result<UncheckedRouterDesc> {
        let mut reader = crate::parse::tokenize::NetDocReader::new(s);
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
        let (identity_cert, ed25519_signing_key) = {
            let cert_tok = header.required(IDENTITY_ED25519)?;
            // Unwrap should be safe because above `required` call should
            // return `Error::MissingToken` if `IDENTITY_ED25519` is not `Ok`
            #[allow(clippy::unwrap_used)]
            if cert_tok.offset_in(s).unwrap() < start_offset {
                return Err(EK::MisplacedToken
                    .with_msg("identity-ed25519")
                    .at_pos(cert_tok.pos()));
            }
            let cert: tor_cert::UncheckedCert = cert_tok
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .check_cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)?
                .into_unchecked()
                .should_have_signing_key()
                .map_err(|err| {
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
            (cert, sk)
        };

        // master-key-ed25519: required, and should match certificate.
        {
            let master_key_tok = body.required(MASTER_KEY_ED25519)?;
            let ed_id: Ed25519Public = master_key_tok.parse_arg(0)?;
            let ed_id: ll::pk::ed25519::Ed25519Identity = ed_id.into();
            if ed_id != *identity_cert.peek_signing_key() {
                #[cfg(not(fuzzing))]
                return Err(EK::BadObjectVal
                    .at_pos(master_key_tok.pos())
                    .with_msg("master-key-ed25519 does not match key in identity-ed25519"));
            }
        }

        // Legacy RSA identity
        let rsa_identity_key: ll::pk::rsa::PublicKey = body
            .required(SIGNING_KEY)?
            .parse_obj::<RsaPublic>("RSA PUBLIC KEY")?
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
            d.update(&s[start_offset..signed_end]);
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
            d.update(&s[start_offset..signed_end]);
            let d = d.finalize();
            let sig = rsa_sig.obj("SIGNATURE")?;
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            ll::pk::rsa::ValidatableRsaSignature::new(&rsa_identity_key, &sig, &d)
        };

        // router nickname ipv4addr orport socksport dirport
        let (nickname, ipv4addr, orport, dirport) = {
            let rtrline = header.required(ROUTER)?;
            (
                rtrline.parse_arg::<Nickname>(0)?,
                Some(rtrline.parse_arg::<net::Ipv4Addr>(1)?),
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
            .parse::<Iso8601TimeSp>()?
            .into();

        // ntor key
        let ntor_onion_key: Curve25519Public = body.required(NTOR_ONION_KEY)?.parse_arg(0)?;
        let ntor_onion_key: ll::pk::curve25519::PublicKey = ntor_onion_key.into();
        // ntor crosscert
        let crosscert_cert: tor_cert::UncheckedCert = {
            let cc = body.required(NTOR_ONION_KEY_CROSSCERT)?;
            let sign: u8 = cc.parse_arg(0)?;
            if sign != 0 && sign != 1 {
                return Err(EK::BadArgument.at_pos(cc.arg_pos(0)).with_msg("not 0 or 1"));
            }
            let ntor_as_ed: ll::pk::ed25519::PublicKey =
                ll::pk::keymanip::convert_curve25519_to_ed25519_public(&ntor_onion_key, sign)
                    .ok_or_else(|| {
                        EK::BadArgument
                            .at_pos(cc.pos())
                            .with_msg("Uncheckable crosscert")
                    })?;

            cc.parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .check_cert_type(tor_cert::CertType::NTOR_CC_IDENTITY)?
                .check_subject_key_is(identity_cert.peek_signing_key())?
                .into_unchecked()
                .should_be_signed_with(&ntor_as_ed.into())
                .map_err(|err| EK::BadSignature.err().with_source(err))?
        };

        // TAP key
        let tap_onion_key: ll::pk::rsa::PublicKey = body
            .required(ONION_KEY)?
            .parse_obj::<RsaPublic>("RSA PUBLIC KEY")?
            .check_len_eq(1024)?
            .check_exponent(65537)?
            .into();

        // TAP crosscert
        let tap_crosscert_sig = {
            let cc_tok = body.required(ONION_KEY_CROSSCERT)?;
            let cc_val = cc_tok.obj("CROSSCERT")?;
            let mut signed = Vec::new();
            signed.extend(rsa_identity.as_bytes());
            signed.extend(identity_cert.peek_signing_key().as_bytes());
            ll::pk::rsa::ValidatableRsaSignature::new(&tap_onion_key, &cc_val, &signed)
        };

        // List of subprotocol versions
        let proto = {
            let proto_tok = body.required(PROTO)?;
            doc::PROTOVERS_CACHE.intern(
                proto_tok
                    .args_as_str()
                    .parse::<tor_protover::Protocols>()
                    .map_err(|e| EK::BadArgument.at_pos(proto_tok.pos()).with_source(e))?,
            )
        };

        // tunneled-dir-server
        let is_dircache = (dirport != 0) || body.get(TUNNELLED_DIR_SERVER).is_some();

        // caches-extra-info
        let is_extrainfo_cache = body.get(CACHES_EXTRA_INFO).is_some();

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

        // or-address
        // Extract at most one ipv6 address from the list.  It's not great,
        // but it's what Tor does.
        let mut ipv6addr = None;
        for tok in body.slice(OR_ADDRESS) {
            if let Ok(net::SocketAddr::V6(a)) = tok.parse_arg::<net::SocketAddr>(0) {
                ipv6addr = Some((*a.ip(), a.port()));
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
                        .at_pos(ruletok.pos()))
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
        let (crosscert_cert, cc_sig) = crosscert_cert.dangerously_split().map_err(|err| {
            EK::BadObjectVal
                .with_msg("missing public key")
                .with_source(err)
        })?;
        let signatures: Vec<Box<dyn ll::pk::ValidatableSignature>> = vec![
            Box::new(rsa_signature),
            Box::new(ed_signature),
            Box::new(identity_sig),
            Box::new(cc_sig),
            Box::new(tap_crosscert_sig),
        ];

        let identity_cert = identity_cert.dangerously_assume_timely();
        let crosscert_cert = crosscert_cert.dangerously_assume_timely();
        let expirations = &[
            published + time::Duration::new(ROUTER_EXPIRY_SECONDS, 0),
            identity_cert.expiry(),
            crosscert_cert.expiry(),
        ];
        // Unwrap is safe here because `expirations` array is not empty
        #[allow(clippy::unwrap_used)]
        let expiry = *expirations.iter().min().unwrap();

        let start_time = published - time::Duration::new(ROUTER_PRE_VALIDITY_SECONDS, 0);

        let desc = RouterDesc {
            nickname,
            ipv4addr,
            orport,
            ipv6addr,
            dirport,
            uptime,
            published,
            identity_cert,
            rsa_identity_key,
            rsa_identity,
            ntor_onion_key,
            tap_onion_key,
            proto,
            is_dircache,
            is_extrainfo_cache,
            family,
            platform,
            ipv4_policy,
            ipv6_policy: ipv6_policy.intern(),
        };

        let time_gated = timed::TimerangeBound::new(desc, start_time..expiry);
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
    pub fn new(s: &'a str, allow: &AllowAnnotations) -> Self {
        let reader = NetDocReader::new(s);
        let annotated = allow == &AllowAnnotations::AnnotationsAllowed;
        RouterReader { annotated, reader }
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    const TESTDATA: &str = include_str!("../../testdata/routerdesc1.txt");

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
        use tor_checkable::{SelfSigned, Timebound};
        let rd = RouterDesc::parse(TESTDATA)?
            .check_signature()?
            .dangerously_assume_timely();

        assert_eq!(rd.nickname.as_str(), "Akka");
        assert_eq!(rd.orport, 443);
        assert_eq!(rd.dirport, 0);
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
    fn test_bad() {
        use crate::types::policy::PolicyError;
        use crate::Pos;
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

        let rd = RouterReader::new(&s, &AllowAnnotations::AnnotationsAllowed);
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
        let p = "Tor 0.4.4.4-alpha on a flying bison".parse::<RelayPlatform>();
        assert!(p.is_ok());
        assert_eq!(
            p.unwrap(),
            RelayPlatform::Tor(
                "0.4.4.4-alpha".parse().unwrap(),
                "a flying bison".to_string()
            )
        );

        let p = "Tor 0.4.4.4-alpha on".parse::<RelayPlatform>();
        assert!(p.is_ok());

        let p = "Tor 0.4.4.4-alpha ".parse::<RelayPlatform>();
        assert!(p.is_ok());
        let p = "Tor 0.4.4.4-alpha".parse::<RelayPlatform>();
        assert!(p.is_ok());

        let p = "arti 0.0.0".parse::<RelayPlatform>();
        assert!(p.is_ok());
        assert_eq!(p.unwrap(), RelayPlatform::Other("arti 0.0.0".to_string()));
    }
}
