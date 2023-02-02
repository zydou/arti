//! Code to handle the inner layer of an onion service descriptor.

use super::{IntroAuthType, IntroPointDesc};
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::parse::{keyword::Keyword, parser::SectionRules};
use crate::types::misc::{UnvalidatedEdCert, B64};
use crate::{ParseErrorKind as EK, Result};

use once_cell::sync::Lazy;
use smallvec::SmallVec;
use tor_hscrypto::pk::{IntroPtAuthKey, IntroPtEncKey};
use tor_llcrypto::pk::{curve25519, ed25519};

/// The contents of the inner layer of an onion service descriptor.
#[derive(Debug, Clone)]
pub(super) struct HsDescInner {
    /// The authentication types that this onion service accepts when
    /// connecting.
    pub(super) authtypes: Option<SmallVec<[IntroAuthType; 2]>>,
    /// Is this onion service a "single onion service?"
    ///
    /// (A "single onion service" is one that is not attempting to anonymize
    /// itself.)
    pub(super) is_single_onion_service: bool,
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

    let mut rules = SectionRules::new();
    rules.add(CREATE2_FORMATS.rule().required().args(1..));
    rules.add(INTRO_AUTH_REQUIRED.rule().args(1..));
    rules.add(SINGLE_ONION_SERVICE.rule());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());

    rules
});

/// Rules about how keywords appear in each introduction-point section of an
/// onion service descriptor.
static HS_INNER_INTRO_RULES: Lazy<SectionRules<HsInnerKwd>> = Lazy::new(|| {
    use HsInnerKwd::*;

    let mut rules = SectionRules::new();
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

    rules
});

impl HsDescInner {
    /// Attempt to parse the inner layer of an onion service descriptor from a
    /// provided string.
    pub(super) fn parse(s: &str) -> Result<HsDescInner> {
        let mut reader = NetDocReader::new(s);
        let result = Self::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        reader.should_be_exhausted()?;
        Ok(result)
    }

    /// Attempt to parse the inner layer of an onion service descriptor from a
    /// provided reader.
    fn take_from_reader(reader: &mut NetDocReader<'_, HsInnerKwd>) -> Result<HsDescInner> {
        use HsInnerKwd::*;

        // Construct a PauseAt iterator that temporarily stops the stream when it is about to
        // yield an INTRODUCTION_POINT Item.
        let mut iter = reader.pause_at(|item| item.is_ok_with_kwd(INTRODUCTION_POINT));

        // Parse the header.
        let header = HS_INNER_HEADER_RULES.parse(&mut iter)?;

        // Make sure that the "ntor" handshake is supported in the list of CREATE2 formats.
        {
            let tok = header.required(CREATE2_FORMATS)?;
            let check = tok.args().any(|s| s == "ntor");
            // TODO hs: actually, do we need to store these?  Would a bit-array make more sense?
            if !tok.args().any(|s| s == "2") {
                return Err(EK::BadArgument
                    .at_pos(tok.pos())
                    .with_msg("Onion service descriptor does not support ntor handshake."));
            }
        }
        // Check whether any kind of introduction-point authentication is required.
        let authtypes = if let Some(tok) = header.get(INTRO_AUTH_REQUIRED) {
            let mut authtypes: SmallVec<[IntroAuthType; 2]> = SmallVec::new();
            let mut push = |at| {
                if !authtypes.contains(&at) {
                    authtypes.push(at);
                }
            };
            for arg in tok.args() {
                match arg {
                    "password" => push(IntroAuthType::Passwd),
                    "ed25519" => push(IntroAuthType::Ed25519),
                    _ => (), // Ignore unrecognized types.
                }
            }
            // .. but if no types are recognized, we can't connect.
            if authtypes.is_empty() {
                return Err(EK::BadArgument
                    .at_pos(tok.pos())
                    .with_msg("No recognized introduction authentication methods."));
            }

            Some(authtypes)
        } else {
            None
        };

        let is_single_onion_service = header.get(SINGLE_ONION_SERVICE).is_some();

        // Now we parse the introduction points.  Each of these will be a
        // section starting with `introduction-point`, ending right before the
        // next `introduction-point` (or before the end of the layer.)
        let mut intro_points = Vec::new();
        while reader.iter().peek().is_some() {
            // Construct a new PauseAt to parse at the _second_ time we see an INTRODUCTION_POINT
            // token
            //
            // TODO: This is a common pattern in this crate, and a bit ugly to type.  Maybe we
            // can add functionality to ParseAt (like an `unpause_once?`) to make it unnecessary.
            let mut seen_intro_point = false;
            let mut iter = reader.pause_at(|item| {
                if item.is_ok_with_kwd(INTRODUCTION_POINT) {
                    if seen_intro_point {
                        return true;
                    } else {
                        seen_intro_point = true;
                    }
                }
                false
            });

            let body = HS_INNER_INTRO_RULES.parse(&mut iter)?;

            // Parse link specifiers
            let link_specifiers = {
                let tok = body.required(INTRODUCTION_POINT)?;
                let ls = tok.parse_arg::<B64>(0)?;
                let mut r = tor_bytes::Reader::from_slice(ls.as_bytes());
                let n = r.take_u8()?;
                let res = r.extract_n(n.into())?;
                r.should_be_exhausted()?;
                res
            };

            // Parse ntor onion key (`KP_onion_ntor`) of the introduction point.
            let ntor_onion_key = {
                let tok = body
                    .slice(ONION_KEY)
                    .iter()
                    .find(|item| item.arg(0) == Some("ntor"))
                    .ok_or_else(|| EK::MissingToken.with_msg("No ntor onion key found."))?;
                tok.parse_arg::<B64>(1)?.into_array()?.into()
            };

            // Extract the auth_key (`KP_hs_intro_tid`) from the (unchecked)
            // "auth-key" certificate.
            let auth_key: IntroPtAuthKey = {
                // Note that this certificate does not actually serve any
                // function _as_ a certificate; it was meant to cross-certify
                // the descriptor signing key (`KP_hs_desc_sign`) using the
                // authentication key (`KP_hs_intro_tid`).  But the C tor
                // implementation got it backwards.
                //
                // We have to parse this certificate to extract
                // `KP_hs_intro_tid`, but we don't actually need to validate it:
                // it appears inside the inner layer, which is already signed
                // with `KP_hs_desc_sign`.
                //
                // See documentation for `CertType::HS_IP_V_SIGNING for more
                // info`.
                //
                // TODO HS: Either we should specify that it is okay to skip
                // validation here, or we should validate the silly certificate
                // anyway.
                let tok = body.required(AUTH_KEY)?;
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

            // Extract the key `KP_hs_intro_ntor` that we'll use for our
            // handshake with the onion service itself.
            let hs_enc_key: IntroPtEncKey = {
                let tok = body
                    .slice(ENC_KEY)
                    .iter()
                    .find(|item| item.arg(0) == Some("ntor"))
                    .ok_or_else(|| EK::MissingToken.with_msg("No ntor onion key found."))?;
                let key = curve25519::PublicKey::from(tok.parse_arg::<B64>(1)?.into_array()?);
                key.into()
            };

            // Check that the key in the enc_key_cert matches the
            // `KP_hs_intro_ntor` we just extracted.
            {
                // NOTE: As above, this certificate is backwards, and hence
                // useless. Therefore, we do not validate it: we only check that
                // the subject key is as expected. Probably that is not even
                // necessary, and we could remove this whole section.
                //
                // TODO HS: Either specify that our behavior is okay, or begin
                // validating this certificate.
                let tok = body.required(ENC_KEY_CERT)?;
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
                        &hs_enc_key,
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
                ntor_onion_key,
                auth_key,
                hs_enc_key,
            });
        }

        Ok(HsDescInner {
            authtypes,
            is_single_onion_service,
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
        middle_layer::HsDescMiddle,
        outer_layer::HsDescOuter,
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
            .decrypt_body(&desc.blinded_id(), desc.revision_counter(), &subcred, None)
            .unwrap();
        let inner_body = std::str::from_utf8(&inner_body).unwrap();
        let inner = HsDescInner::parse(inner_body)?;

        // TODO hs: validate the expected contents of this part of the
        // descriptor.

        Ok(())
    }
}
