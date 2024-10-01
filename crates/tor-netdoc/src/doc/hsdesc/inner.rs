//! Code to handle the inner document of an onion service descriptor.

use std::time::SystemTime;

use super::{IntroAuthType, IntroPointDesc};
use crate::batching_split_before::IteratorExt as _;
use crate::doc::hsdesc::pow::PowParamSet;
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::parse::{keyword::Keyword, parser::SectionRules};
use crate::types::misc::{UnvalidatedEdCert, B64};
use crate::{NetdocErrorKind as EK, Result};

use itertools::Itertools as _;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use tor_checkable::signed::SignatureGated;
use tor_checkable::timed::TimerangeBound;
use tor_checkable::Timebound;
use tor_hscrypto::pk::{HsIntroPtSessionIdKey, HsSvcNtorKey};
use tor_hscrypto::NUM_INTRO_POINT_MAX;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::{curve25519, ed25519, ValidatableSignature};

/// The contents of the inner document of an onion service descriptor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
pub(crate) struct HsDescInner {
    /// The authentication types that this onion service accepts when
    /// connecting.
    //
    // TODO: This should probably be a bitfield or enum-set of something.
    // Once we know whether the "password" authentication type really exists,
    // let's change to a better representation here.
    pub(super) intro_auth_types: Option<SmallVec<[IntroAuthType; 2]>>,
    /// Is this onion service a "single onion service?"
    ///
    /// (A "single onion service" is one that is not attempting to anonymize
    /// itself.)
    pub(super) single_onion_service: bool,
    /// A list of advertised introduction points and their contact info.
    //
    // Always has >= 1 and <= NUM_INTRO_POINT_MAX entries
    pub(super) intro_points: Vec<IntroPointDesc>,
    /// A list of offered proof-of-work parameters, at most one per type.
    pub(super) pow_params: PowParamSet,
}

decl_keyword! {
    pub(crate) HsInnerKwd {
        "create2-formats" => CREATE2_FORMATS,
        "intro-auth-required" => INTRO_AUTH_REQUIRED,
        "single-onion-service" => SINGLE_ONION_SERVICE,
        "introduction-point" => INTRODUCTION_POINT,
        "onion-key" => ONION_KEY,
        "auth-key" => AUTH_KEY,
        "enc-key" => ENC_KEY,
        "enc-key-cert" => ENC_KEY_CERT,
        "legacy-key" => LEGACY_KEY,
        "legacy-key-cert" => LEGACY_KEY_CERT,
        "pow-params" => POW_PARAMS,
    }
}

/// Rules about how keywords appear in the header part of an onion service
/// descriptor.
static HS_INNER_HEADER_RULES: Lazy<SectionRules<HsInnerKwd>> = Lazy::new(|| {
    use HsInnerKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(CREATE2_FORMATS.rule().required().args(1..));
    rules.add(INTRO_AUTH_REQUIRED.rule().args(1..));
    rules.add(SINGLE_ONION_SERVICE.rule());
    rules.add(POW_PARAMS.rule().args(1..));
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());

    rules.build()
});

/// Rules about how keywords appear in each introduction-point section of an
/// onion service descriptor.
static HS_INNER_INTRO_RULES: Lazy<SectionRules<HsInnerKwd>> = Lazy::new(|| {
    use HsInnerKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(INTRODUCTION_POINT.rule().required().args(1..));
    // Note: we're labeling ONION_KEY and ENC_KEY as "may_repeat", since even
    // though rend-spec labels them as "exactly once", they are allowed to
    // appear more than once so long as they appear only once _with an "ntor"_
    // key.  torspec!110 tries to document this issue.
    rules.add(ONION_KEY.rule().required().may_repeat().args(2..));
    rules.add(AUTH_KEY.rule().required().obj_required());
    rules.add(ENC_KEY.rule().required().may_repeat().args(2..));
    rules.add(ENC_KEY_CERT.rule().required().obj_required());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());

    // NOTE: We never look at the LEGACY_KEY* fields.  This does provide a
    // distinguisher for Arti implementations and C tor implementations, but
    // that's outside of Arti's threat model.
    //
    // (In fact, there's an easier distinguisher, since we enforce UTF-8 in
    // these documents, and C tor does not.)

    rules.build()
});

/// Helper type returned when we parse an HsDescInner.
pub(crate) type UncheckedHsDescInner = TimerangeBound<SignatureGated<HsDescInner>>;

/// Information about one of the certificates inside an HsDescInner.
///
/// This is a teporary structure that we use when parsing.
struct InnerCertData {
    /// The identity of the key that purportedly signs this certificate.
    signing_key: Ed25519Identity,
    /// The key that is being signed.
    subject_key: ed25519::PublicKey,
    /// A detached signature object that we must validate before we can conclude
    /// that the certificate is valid.
    signature: Box<dyn ValidatableSignature>,
    /// The time when the certificate expires.
    expiry: SystemTime,
}

/// Decode a certificate from `tok`, and check that its tag and type are
/// expected, that it contains a signing key,  and that both signing and subject
/// keys are Ed25519.
///
/// On success, return an InnerCertData.
fn handle_inner_certificate(
    tok: &crate::parse::tokenize::Item<HsInnerKwd>,
    want_tag: &str,
    want_type: tor_cert::CertType,
) -> Result<InnerCertData> {
    let make_err = |e, msg| {
        EK::BadObjectVal
            .with_msg(msg)
            .with_source(e)
            .at_pos(tok.pos())
    };

    let cert = tok
        .parse_obj::<UnvalidatedEdCert>(want_tag)?
        .check_cert_type(want_type)?
        .into_unchecked();

    // These certs have to include a signing key.
    let cert = cert
        .should_have_signing_key()
        .map_err(|e| make_err(e, "Certificate was not self-signed"))?;

    // Peel off the signature.
    let (cert, signature) = cert
        .dangerously_split()
        .map_err(|e| make_err(e, "Certificate was not Ed25519-signed"))?;
    let signature = Box::new(signature);

    // Peel off the expiration
    let cert = cert.dangerously_assume_timely();
    let expiry = cert.expiry();
    let subject_key = cert
        .subject_key()
        .as_ed25519()
        .ok_or_else(|| {
            EK::BadObjectVal
                .with_msg("Certified key was not Ed25519")
                .at_pos(tok.pos())
        })?
        .try_into()
        .map_err(|_| {
            EK::BadObjectVal
                .with_msg("Certified key was not valid Ed25519")
                .at_pos(tok.pos())
        })?;

    let signing_key = *cert.signing_key().ok_or_else(|| {
        EK::BadObjectVal
            .with_msg("Signing key was not Ed25519")
            .at_pos(tok.pos())
    })?;

    Ok(InnerCertData {
        signing_key,
        subject_key,
        signature,
        expiry,
    })
}

impl HsDescInner {
    /// Attempt to parse the inner document of an onion service descriptor from a
    /// provided string.
    ///
    /// On success, return the signing key that was used for every certificate in the
    /// inner document, and the inner document itself.
    #[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
    pub(super) fn parse(s: &str) -> Result<(Option<Ed25519Identity>, UncheckedHsDescInner)> {
        let mut reader = NetDocReader::new(s);
        let result = Self::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        Ok(result)
    }

    /// Attempt to parse the inner document of an onion service descriptor from a
    /// provided reader.
    ///
    /// On success, return the signing key that was used for every certificate in the
    /// inner document, and the inner document itself.
    fn take_from_reader(
        input: &mut NetDocReader<'_, HsInnerKwd>,
    ) -> Result<(Option<Ed25519Identity>, UncheckedHsDescInner)> {
        use HsInnerKwd::*;

        // Split up the input at INTRODUCTION_POINT items
        let mut sections =
            input.batching_split_before_with_header(|item| item.is_ok_with_kwd(INTRODUCTION_POINT));
        // Parse the header.
        let header = HS_INNER_HEADER_RULES.parse(&mut sections)?;

        // Make sure that the "ntor" handshake is supported in the list of
        // `HTYPE`s (handshake types) in `create2-formats`.
        {
            let tok = header.required(CREATE2_FORMATS)?;
            // If we ever want to support a different HTYPE, we'll need to
            // store at least the intersection between "their" and "our" supported
            // HTYPEs.  For now we only support one, so either this set is empty
            // and failing now is fine, or `ntor` (2) is supported, so fine.
            if !tok.args().any(|s| s == "2") {
                return Err(EK::BadArgument
                    .at_pos(tok.pos())
                    .with_msg("Onion service descriptor does not support ntor handshake."));
            }
        }
        // Check whether any kind of introduction-point authentication is
        // specified in an `intro-auth-required` line.
        let auth_types = if let Some(tok) = header.get(INTRO_AUTH_REQUIRED) {
            let mut auth_types: SmallVec<[IntroAuthType; 2]> = SmallVec::new();
            let mut push = |at| {
                if !auth_types.contains(&at) {
                    auth_types.push(at);
                }
            };
            for arg in tok.args() {
                #[allow(clippy::single_match)]
                match arg {
                    "ed25519" => push(IntroAuthType::Ed25519),
                    _ => (), // Ignore unrecognized types.
                }
            }
            // .. but if no types are recognized, we can't connect.
            if auth_types.is_empty() {
                return Err(EK::BadArgument
                    .at_pos(tok.pos())
                    .with_msg("No recognized introduction authentication methods."));
            }

            Some(auth_types)
        } else {
            None
        };

        // Recognize `single-onion-service` if it's there.
        let is_single_onion_service = header.get(SINGLE_ONION_SERVICE).is_some();

        // Recognize `pow-params`, parsing each line and rejecting duplicate types
        let pow_params = PowParamSet::from_items(header.slice(POW_PARAMS))?;

        let mut signatures = Vec::new();
        let mut expirations = Vec::new();
        let mut cert_signing_key: Option<Ed25519Identity> = None;

        // Now we parse the introduction points.  Each of these will be a
        // section starting with `introduction-point`, ending right before the
        // next `introduction-point` (or before the end of the document.)
        let mut intro_points = Vec::new();
        let mut sections = sections.subsequent();
        while let Some(mut ipt_section) = sections.next_batch() {
            let ipt_section = HS_INNER_INTRO_RULES.parse(&mut ipt_section)?;

            // Parse link-specifiers
            let link_specifiers = {
                let tok = ipt_section.required(INTRODUCTION_POINT)?;
                let ls = tok.parse_arg::<B64>(0)?;
                let mut r = tor_bytes::Reader::from_slice(ls.as_bytes());
                let n = r.take_u8()?;
                let res = r.extract_n(n.into())?;
                r.should_be_exhausted()?;
                res
            };

            // Parse the ntor "onion-key" (`KP_ntor`) of the introduction point.
            let ntor_onion_key = {
                let tok = ipt_section
                    .slice(ONION_KEY)
                    .iter()
                    .filter(|item| item.arg(0) == Some("ntor"))
                    .exactly_one()
                    .map_err(|_| EK::MissingToken.with_msg("No unique ntor onion key found."))?;
                tok.parse_arg::<B64>(1)?.into_array()?.into()
            };

            // Extract the auth_key (`KP_hs_ipt_sid`) from the (unchecked)
            // "auth-key" certificate.
            let auth_key: HsIntroPtSessionIdKey = {
                // Note that this certificate does not actually serve any
                // function _as_ a certificate; it was meant to cross-certify
                // the descriptor signing key (`KP_hs_desc_sign`) using the
                // authentication key (`KP_hs_ipt_sid`).  But the C tor
                // implementation got it backwards.
                //
                // We have to parse this certificate to extract
                // `KP_hs_ipt_sid`, but we don't actually need to validate it:
                // it appears inside the inner document, which is already signed
                // with `KP_hs_desc_sign`.  Nonetheless, we validate it anyway,
                // since that's what C tor does.
                //
                // See documentation for `CertType::HS_IP_V_SIGNING for more
                // info`.
                let tok = ipt_section.required(AUTH_KEY)?;
                let InnerCertData {
                    signing_key,
                    subject_key,
                    signature,
                    expiry,
                } = handle_inner_certificate(
                    tok,
                    "ED25519 CERT",
                    tor_cert::CertType::HS_IP_V_SIGNING,
                )?;
                expirations.push(expiry);
                signatures.push(signature);
                if cert_signing_key.get_or_insert(signing_key) != &signing_key {
                    return Err(EK::BadObjectVal
                        .at_pos(tok.pos())
                        .with_msg("Mismatched signing key"));
                }

                subject_key.into()
            };

            // Extract the key `KP_hss_ntor` that we'll use for our
            // handshake with the onion service itself.  This comes from the
            // "enc-key" item.
            let svc_ntor_key: HsSvcNtorKey = {
                let tok = ipt_section
                    .slice(ENC_KEY)
                    .iter()
                    .filter(|item| item.arg(0) == Some("ntor"))
                    .exactly_one()
                    .map_err(|_| EK::MissingToken.with_msg("No unique ntor onion key found."))?;
                let key = curve25519::PublicKey::from(tok.parse_arg::<B64>(1)?.into_array()?);
                key.into()
            };

            // Check that the key in the "enc-key-cert" item matches the
            // `KP_hss_ntor` we just extracted.
            {
                // NOTE: As above, this certificate is backwards, and hence
                // useless.  Still, we validate it because that is what C tor does.
                let tok = ipt_section.required(ENC_KEY_CERT)?;
                let InnerCertData {
                    signing_key,
                    subject_key,
                    signature,
                    expiry,
                } = handle_inner_certificate(
                    tok,
                    "ED25519 CERT",
                    tor_cert::CertType::HS_IP_CC_SIGNING,
                )?;
                expirations.push(expiry);
                signatures.push(signature);

                // Yes, the sign bit is always zero here. This would have a 50%
                // chance of making  the key unusable for verification. But since
                // the certificate is backwards (see above) we don't actually have
                // to check any signatures with it.
                let sign_bit = 0;
                let expected_ed_key =
                    tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public(
                        &svc_ntor_key,
                        sign_bit,
                    );
                if expected_ed_key != Some(subject_key) {
                    return Err(EK::BadObjectVal
                        .at_pos(tok.pos())
                        .with_msg("Mismatched subject key"));
                }

                // Make sure signing key is as expected.
                if cert_signing_key.get_or_insert(signing_key) != &signing_key {
                    return Err(EK::BadObjectVal
                        .at_pos(tok.pos())
                        .with_msg("Mismatched signing key"));
                }
            };

            // TODO SPEC: State who enforces NUM_INTRO_POINT_MAX and how (hsdirs, clients?)
            //
            // Simply discard extraneous IPTs.  The MAX value is hardcoded now, but a future
            // protocol evolution might increase it and we should probably still work then.
            //
            // If the spec intended that hsdirs ought to validate this and reject descriptors
            // with more than MAX (when they can), then this code is wrong because it would
            // prevent any caller (eg future hsdir code in arti relay) from seeing the violation.
            if intro_points.len() < NUM_INTRO_POINT_MAX {
                intro_points.push(IntroPointDesc {
                    link_specifiers,
                    ipt_ntor_key: ntor_onion_key,
                    ipt_sid_key: auth_key,
                    svc_ntor_key,
                });
            }
        }

        // TODO SPEC: Might a HS publish descriptor with no IPTs to declare itself down?
        // If it might, then we should:
        //   - accept such descriptors here
        //   - check for this situation explicitly in tor-hsclient connect.rs intro_rend_connect
        //   - bail with a new `ConnError` (with ErrorKind OnionServiceNotRunning)
        // with the consequence that once we obtain such a descriptor,
        // we'll be satisfied with it and consider the HS down until the descriptor expires.
        if intro_points.is_empty() {
            return Err(EK::MissingEntry.with_msg("no introduction points"));
        }

        let inner = HsDescInner {
            intro_auth_types: auth_types,
            single_onion_service: is_single_onion_service,
            pow_params,
            intro_points,
        };
        let sig_gated = SignatureGated::new(inner, signatures);
        let time_bound = match expirations.iter().min() {
            Some(t) => TimerangeBound::new(sig_gated, ..t),
            None => TimerangeBound::new(sig_gated, ..),
        };

        Ok((cert_signing_key, time_bound))
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

    use std::iter;

    use hex_literal::hex;
    use itertools::chain;
    use tor_checkable::{SelfSigned, Timebound};

    use super::*;
    use crate::doc::hsdesc::{
        middle::HsDescMiddle,
        outer::HsDescOuter,
        test_data::{TEST_DATA, TEST_SUBCREDENTIAL},
    };

    // This is the inner document from hsdesc1.txt aka TEST_DATA
    const TEST_DATA_INNER: &str = include_str!("../../../testdata/hsdesc-inner.txt");

    #[test]
    fn inner_text() {
        use crate::NetdocErrorKind as NEK;
        let _desc = HsDescInner::parse(TEST_DATA_INNER).unwrap();

        let none = format!(
            "{}\n",
            TEST_DATA_INNER
                .split_once("\nintroduction-point")
                .unwrap()
                .0,
        );
        let err = HsDescInner::parse(&none).map(|_| &none).unwrap_err();
        assert_eq!(err.kind, NEK::MissingEntry);

        let ipt = format!(
            "introduction-point{}",
            TEST_DATA_INNER
                .rsplit_once("\nintroduction-point")
                .unwrap()
                .1,
        );
        for n in NUM_INTRO_POINT_MAX..NUM_INTRO_POINT_MAX + 2 {
            let many = chain!(iter::once(&*none), iter::repeat(&*ipt).take(n),).collect::<String>();
            let desc = HsDescInner::parse(&many).unwrap();
            let desc = desc
                .1
                .dangerously_into_parts()
                .0
                .dangerously_assume_wellsigned();
            assert_eq!(desc.intro_points.len(), NUM_INTRO_POINT_MAX);
        }
    }

    #[test]
    fn parse_good() -> Result<()> {
        let desc = HsDescOuter::parse(TEST_DATA)?
            .dangerously_assume_wellsigned()
            .dangerously_assume_timely();
        let subcred = TEST_SUBCREDENTIAL.into();
        let body = desc.decrypt_body(&subcred).unwrap();
        let body = std::str::from_utf8(&body[..]).unwrap();

        let middle = HsDescMiddle::parse(body)?;
        let inner_body = middle
            .decrypt_inner(&desc.blinded_id(), desc.revision_counter(), &subcred, None)
            .unwrap();
        let inner_body = std::str::from_utf8(&inner_body).unwrap();
        let (ed_id, inner) = HsDescInner::parse(inner_body)?;
        let inner = inner
            .check_valid_at(&humantime::parse_rfc3339("2023-01-23T15:00:00Z").unwrap())
            .unwrap()
            .check_signature()
            .unwrap();

        assert_eq!(ed_id.as_ref(), Some(desc.desc_sign_key_id()));

        assert!(inner.intro_auth_types.is_none());
        assert_eq!(inner.single_onion_service, false);
        assert_eq!(inner.intro_points.len(), 3);

        let ipt0 = &inner.intro_points[0];
        assert_eq!(
            ipt0.ipt_ntor_key().as_bytes(),
            &hex!("553BF9F9E1979D6F5D5D7D20BB3FE7272E32E22B6E86E35C76A7CA8A377E402F")
        );

        assert_ne!(ipt0.link_specifiers, inner.intro_points[1].link_specifiers);

        Ok(())
    }
}
