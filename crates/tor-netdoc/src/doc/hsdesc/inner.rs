//! Code to handle the inner document of an onion service descriptor.

use super::{IntroAuthType, IntroPointDesc};
use crate::batching_split_before::IteratorExt as _;
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::parse::{keyword::Keyword, parser::SectionRules};
use crate::types::misc::{UnvalidatedEdCert, B64};
use crate::{ParseErrorKind as EK, Result};

use itertools::Itertools as _;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use tor_hscrypto::pk::{HsIntroPtSessionIdKey, HsSvcNtorKey};
use tor_llcrypto::pk::{curve25519, ed25519};

/// The contents of the inner document of an onion service descriptor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
pub(super) struct HsDescInner {
    /// The authentication types that this onion service accepts when
    /// connecting.
    // TODO HS: This should probably be a bitfield or enum-set of something.
    // Once we know whether the "password" authentication type really exists,
    // let's change to a better representation here.
    pub(super) intro_auth_types: Option<SmallVec<[IntroAuthType; 2]>>,
    /// Is this onion service a "single onion service?"
    ///
    /// (A "single onion service" is one that is not attempting to anonymize
    /// itself.)
    pub(super) single_onion_service: bool,
    /// A list of advertised introduction points and their contact info.
    pub(super) intro_points: Vec<IntroPointDesc>,
}

decl_keyword! {
    HsInnerKwd {
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
    // TODO HS We never look at the LEGACY_KEY* fields.  But might this not open
    // us to distinguishability attacks with C tor?  (OTOH, in theory we do not
    // defend against those.  In fact, there's an easier distinguisher, since we
    // enforce UTF-8 in these documents, and C tor does not.)

    rules.build()
});

impl HsDescInner {
    /// Attempt to parse the inner document of an onion service descriptor from a
    /// provided string.
    #[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
    pub(super) fn parse(s: &str) -> Result<HsDescInner> {
        let mut reader = NetDocReader::new(s);
        let result = Self::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        Ok(result)
    }

    /// Attempt to parse the inner document of an onion service descriptor from a
    /// provided reader.
    fn take_from_reader(input: &mut NetDocReader<'_, HsInnerKwd>) -> Result<HsDescInner> {
        use HsInnerKwd::*;

        // Split up the input at INTRODUCTION_POINT items
        let mut sections = input
            .batching_split_before_with_header(|item| item.is_ok_with_kwd(INTRODUCTION_POINT));
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
                // TODO hs: Check whether c tor enforces that this field is exhausted.
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
                // with `KP_hs_desc_sign`.
                //
                // See documentation for `CertType::HS_IP_V_SIGNING for more
                // info`.
                //
                // TODO HS: Either we should specify that it is okay to skip
                // validation here, or we should validate the silly certificate
                // anyway.
                //
                // TODO HS: Additionally, though the spec says "the signing key
                //    extension is mandatory" we don't check that either.  The
                // spec, or the code, should be fixed. There may be
                // distinguishability implications to both these questions.
                //
                // TODO HS: We need investigate what c tor does, and either just
                // do that, or decide that it is wrong. Either way we should
                // amend the spec for further clarity.
                let tok = ipt_section.required(AUTH_KEY)?;
                let cert = tok
                    .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                    .check_cert_type(tor_cert::CertType::HS_IP_V_SIGNING)?
                    .into_unchecked();
                let ed_key: ed25519::PublicKey = cert
                    .peek_subject_key()
                    .as_ed25519()
                    .ok_or_else(|| {
                        EK::BadObjectVal
                            .with_msg("Certified key was not Ed25519")
                            .at_pos(tok.pos())
                    })?
                    .try_into()
                    .map_err(|e| {
                        EK::BadObjectVal
                            .with_msg("Invalid Ed25519 key")
                            .with_source(e)
                            .at_pos(tok.pos())
                    })?;
                ed_key.into()
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
                // useless. Therefore, we do not validate it: we only check that
                // the subject key is as expected. Probably that is not even
                // necessary, and we could remove this whole section.
                //
                // TODO HS: See all "TODO HS" notes above for the "AUTH_KEY" certificate.
                // Additionally, there is a bunch of code duplication here that we should fix.
                let tok = ipt_section.required(ENC_KEY_CERT)?;
                let cert = tok
                    .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                    .check_cert_type(tor_cert::CertType::HS_IP_CC_SIGNING)?
                    .into_unchecked();
                let ed_key: ed25519::PublicKey = cert
                    .peek_subject_key()
                    .as_ed25519()
                    .ok_or_else(|| {
                        EK::BadObjectVal
                            .with_msg("Certified key was not Ed25519")
                            .at_pos(tok.pos())
                    })?
                    .try_into()
                    .map_err(|e| {
                        EK::BadObjectVal
                            .with_msg("Invalid Ed25519 key")
                            .with_source(e)
                            .at_pos(tok.pos())
                    })?;
                let expected_ed_key =
                    tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public(
                        &svc_ntor_key,
                        0,
                    );
                if expected_ed_key != Some(ed_key) {
                    return Err(EK::BadObjectVal
                        .at_pos(tok.pos())
                        .with_msg("Mismatched subject key"));
                }
            };

            intro_points.push(IntroPointDesc {
                link_specifiers,
                ipt_ntor_key: ntor_onion_key,
                ipt_sid_key: auth_key,
                svc_ntor_key,
            });
        }

        Ok(HsDescInner {
            intro_auth_types: auth_types,
            single_onion_service: is_single_onion_service,
            intro_points,
        })
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_checkable::{SelfSigned, Timebound};

    use super::*;
    use crate::doc::hsdesc::{
        middle::HsDescMiddle,
        outer::HsDescOuter,
        test::{TEST_DATA, TEST_SUBCREDENTIAL},
    };

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
        let inner = HsDescInner::parse(inner_body)?;

        // TODO hs: validate the expected contents of this part of the
        // descriptor.

        Ok(())
    }
}
