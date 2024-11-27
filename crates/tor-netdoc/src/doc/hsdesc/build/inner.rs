//! Functionality for encoding the inner document of an onion service descriptor.
//!
//! NOTE: `HsDescInner` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use crate::build::ItemArgument;
use crate::build::NetdocEncoder;
use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::doc::hsdesc::pow::v1::PowParamsV1;
use crate::doc::hsdesc::pow::PowParams;
use crate::doc::hsdesc::IntroAuthType;
use crate::doc::hsdesc::IntroPointDesc;
use crate::types::misc::Iso8601TimeNoSp;
use crate::NetdocBuilder;

use rand::CryptoRng;
use rand::RngCore;
use tor_bytes::{EncodeError, Writer};
use tor_cell::chancell::msg::HandshakeType;
use tor_cert::{CertType, CertifiedKey, Ed25519Cert};
use tor_error::internal;
use tor_error::{bad_api_usage, into_bad_api_usage};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public;

use base64ct::{Base64, Encoding};

use std::time::SystemTime;

use smallvec::SmallVec;

/// The representation of the inner document of an onion service descriptor.
///
/// The plaintext format of this document is described in section 2.5.2.2. of rend-spec-v3.
#[derive(Debug)]
pub(super) struct HsDescInner<'a> {
    /// The descriptor signing key.
    pub(super) hs_desc_sign: &'a ed25519::Keypair,
    /// A list of recognized CREATE handshakes that this onion service supports.
    pub(super) create2_formats: &'a [HandshakeType],
    /// A list of authentication types that this onion service supports.
    pub(super) auth_required: Option<&'a SmallVec<[IntroAuthType; 2]>>,
    /// If true, this a "single onion service" and is not trying to keep its own location private.
    pub(super) is_single_onion_service: bool,
    /// One or more introduction points used to contact the onion service.
    pub(super) intro_points: &'a [IntroPointDesc],
    /// The expiration time of an introduction point authentication key certificate.
    pub(super) intro_auth_key_cert_expiry: SystemTime,
    /// The expiration time of an introduction point encryption key certificate.
    pub(super) intro_enc_key_cert_expiry: SystemTime,
    /// Proof-of-work parameters
    #[cfg(feature = "hs-pow-full")]
    pub(super) pow_params: Option<&'a PowParams>,
}

#[cfg(feature = "hs-pow-full")]
fn encode_pow_params(
    encoder: &mut NetdocEncoder,
    pow_params: &PowParamsV1,
) -> Result<(), EncodeError> {
    let mut pow_params_enc = encoder.item(HsInnerKwd::POW_PARAMS);
    pow_params_enc.add_arg(&"v1");

    // It's safe to call dangerously_into_parts here, since we encode the
    // expiration alongside the value.
    let (seed, (_, expiration)) = pow_params.seed().clone().dangerously_into_parts();

    seed.write_onto(&mut pow_params_enc)?;

    pow_params
        .suggested_effort()
        .write_onto(&mut pow_params_enc)?;

    let expiration = if let Some(expiration) = expiration {
        expiration
    } else {
        return Err(internal!("PoW seed should always have expiration").into());
    };

    Iso8601TimeNoSp::from(expiration).write_onto(&mut pow_params_enc)?;

    Ok(())
}

impl<'a> NetdocBuilder for HsDescInner<'a> {
    fn build_sign<R: RngCore + CryptoRng>(self, _: &mut R) -> Result<String, EncodeError> {
        use HsInnerKwd::*;

        let HsDescInner {
            hs_desc_sign,
            create2_formats,
            auth_required,
            is_single_onion_service,
            intro_points,
            intro_auth_key_cert_expiry,
            intro_enc_key_cert_expiry,
            #[cfg(feature = "hs-pow-full")]
            pow_params,
        } = self;

        let mut encoder = NetdocEncoder::new();

        {
            let mut create2_formats_enc = encoder.item(CREATE2_FORMATS);
            for fmt in create2_formats {
                let fmt: u16 = (*fmt).into();
                create2_formats_enc = create2_formats_enc.arg(&fmt);
            }
        }

        {
            if let Some(auth_required) = auth_required {
                let mut auth_required_enc = encoder.item(INTRO_AUTH_REQUIRED);
                for auth in auth_required {
                    auth_required_enc = auth_required_enc.arg(&auth.to_string());
                }
            }
        }

        if is_single_onion_service {
            encoder.item(SINGLE_ONION_SERVICE);
        }

        #[cfg(feature = "hs-pow-full")]
        if let Some(pow_params) = pow_params {
            match pow_params {
                #[cfg(feature = "hs-pow-full")]
                PowParams::V1(pow_params) => encode_pow_params(&mut encoder, pow_params)?,
                #[cfg(not(feature = "hs-pow-full"))]
                PowParams::V1(_) => {
                    return Err(internal!(
                        "Got a V1 PoW params but support for V1 is disabled."
                    ))
                }
            }
        }

        // We sort the introduction points here so as not to expose
        // detail about the order in which they were added, which might
        // be useful to an attacker somehow.  The choice of ntor
        // key is arbitrary; we could sort by anything, really.
        //
        // TODO SPEC: Either specify that we should sort by ntor key,
        // or sort by something else and specify that.
        let mut sorted_ip: Vec<_> = intro_points.iter().collect();
        sorted_ip.sort_by_key(|key| key.ipt_ntor_key.as_bytes());
        for intro_point in sorted_ip {
            // rend-spec-v3 0.4. "Protocol building blocks [BUILDING-BLOCKS]": the number of link
            // specifiers (NPSEC) must fit in a single byte.
            let nspec: u8 = intro_point
                .link_specifiers
                .len()
                .try_into()
                .map_err(into_bad_api_usage!("Too many link specifiers."))?;

            let mut link_specifiers = vec![];
            link_specifiers.write_u8(nspec);

            for link_spec in &intro_point.link_specifiers {
                link_specifiers.write(link_spec)?;
            }

            encoder
                .item(INTRODUCTION_POINT)
                .arg(&Base64::encode_string(&link_specifiers));
            encoder
                .item(ONION_KEY)
                .arg(&"ntor")
                .arg(&Base64::encode_string(&intro_point.ipt_ntor_key.to_bytes()));

            // For compatibility with c-tor, the introduction point authentication key is signed by
            // the descriptor signing key.
            let signed_auth_key = Ed25519Cert::constructor()
                .cert_type(CertType::HS_IP_V_SIGNING)
                .expiration(intro_auth_key_cert_expiry)
                .signing_key(ed25519::Ed25519Identity::from(hs_desc_sign.verifying_key()))
                .cert_key(CertifiedKey::Ed25519((*intro_point.ipt_sid_key).into()))
                .encode_and_sign(hs_desc_sign)
                .map_err(into_bad_api_usage!("failed to sign the intro auth key"))?;

            encoder
                .item(AUTH_KEY)
                .object("ED25519 CERT", signed_auth_key.as_ref());

            // "The key is a base64 encoded curve25519 public key used to encrypt the introduction
            // request to service. (`KP_hss_ntor`)"
            //
            // TODO: The spec allows for multiple enc-key lines, but we currently only ever encode
            // a single one.
            encoder
                .item(ENC_KEY)
                .arg(&"ntor")
                .arg(&Base64::encode_string(
                    &intro_point.svc_ntor_key.as_bytes()[..],
                ));

            // The subject key is the ed25519 equivalent of the svc_ntor_key
            // curve25519 public encryption key, with its sign bit set to 0.
            //
            // (Setting the sign bit to zero has a 50% chance of making the
            // ed25519 public key useless for checking signatures, but that's
            // okay: since this cert is generated with its signing/subject keys
            // reversed (for compatibility reasons), we never actually generate
            // or check any signatures using this key.)
            let signbit = 0;
            let ed_svc_ntor_key =
                convert_curve25519_to_ed25519_public(&intro_point.svc_ntor_key, signbit)
                    .ok_or_else(|| {
                        bad_api_usage!("failed to convert curve25519 pk to ed25519 pk")
                    })?;

            // For compatibility with c-tor, the encryption key is signed with the descriptor
            // signing key.
            let signed_enc_key = Ed25519Cert::constructor()
                .cert_type(CertType::HS_IP_CC_SIGNING)
                .expiration(intro_enc_key_cert_expiry)
                .signing_key(ed25519::Ed25519Identity::from(hs_desc_sign.verifying_key()))
                .cert_key(CertifiedKey::Ed25519(ed25519::Ed25519Identity::from(
                    &ed_svc_ntor_key,
                )))
                .encode_and_sign(hs_desc_sign)
                .map_err(into_bad_api_usage!(
                    "failed to sign the intro encryption key"
                ))?;

            encoder
                .item(ENC_KEY_CERT)
                .object("ED25519 CERT", signed_enc_key.as_ref());
        }

        encoder.finish().map_err(|e| e.into())
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
    use crate::doc::hsdesc::build::test::{create_intro_point_descriptor, expect_bug};
    use crate::doc::hsdesc::pow::v1::PowParamsV1;
    use crate::doc::hsdesc::IntroAuthType;

    use rand::thread_rng;
    use smallvec::SmallVec;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;
    use tor_basic_utils::test_rng::Config;
    use tor_checkable::timed::TimerangeBound;
    #[cfg(feature = "hs-pow-full")]
    use tor_hscrypto::pow::v1::{Effort, Seed};
    use tor_linkspec::LinkSpec;

    /// Build an inner document using the specified parameters.
    fn create_inner_desc(
        create2_formats: &[HandshakeType],
        auth_required: Option<&SmallVec<[IntroAuthType; 2]>>,
        is_single_onion_service: bool,
        intro_points: &[IntroPointDesc],
        pow_params: Option<&PowParams>,
    ) -> Result<String, EncodeError> {
        let hs_desc_sign = ed25519::Keypair::generate(&mut Config::Deterministic.into_rng());

        HsDescInner {
            hs_desc_sign: &hs_desc_sign,
            create2_formats,
            auth_required,
            is_single_onion_service,
            intro_points,
            intro_auth_key_cert_expiry: UNIX_EPOCH,
            intro_enc_key_cert_expiry: UNIX_EPOCH,
            #[cfg(feature = "hs-pow-full")]
            pow_params,
        }
        .build_sign(&mut thread_rng())
    }

    #[test]
    fn inner_hsdesc_no_intro_auth() {
        // A descriptor for a "single onion service"
        let hs_desc = create_inner_desc(
            &[HandshakeType::NTOR], /* create2_formats */
            None,                   /* auth_required */
            true,                   /* is_single_onion_service */
            &[],                    /* intro_points */
            None,
        )
        .unwrap();

        assert_eq!(hs_desc, "create2-formats 2\nsingle-onion-service\n");

        // A descriptor for a location-hidden service
        let hs_desc = create_inner_desc(
            &[HandshakeType::NTOR], /* create2_formats */
            None,                   /* auth_required */
            false,                  /* is_single_onion_service */
            &[],                    /* intro_points */
            None,
        )
        .unwrap();

        assert_eq!(hs_desc, "create2-formats 2\n");

        let link_specs1 = &[LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 1234)];
        let link_specs2 = &[LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 5679)];
        let link_specs3 = &[LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 8901)];

        let mut rng = Config::Deterministic.into_rng();
        let intros = &[
            create_intro_point_descriptor(&mut rng, link_specs1),
            create_intro_point_descriptor(&mut rng, link_specs2),
            create_intro_point_descriptor(&mut rng, link_specs3),
        ];

        let hs_desc = create_inner_desc(
            &[
                HandshakeType::TAP,
                HandshakeType::NTOR,
                HandshakeType::NTOR_V3,
            ], /* create2_formats */
            None,   /* auth_required */
            false,  /* is_single_onion_service */
            intros, /* intro_points */
            None,
        )
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"create2-formats 0 2 3
introduction-point AQAGfwAAASLF
onion-key ntor CJi8nDPhIFA7X9Q+oP7+jzxNo044cblmagk/d7oKWGc=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAU4J4xGrMt9q5eHYZSmbOZTi1iKl59nd3ItYXAa/ASlRAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61CGkJzc/ECYHzJeeAKIkRFV/6jr9
zAB5XnEFghZmXdDTQdqcPXAFydyeHWW4uR+Uii0wPI8VokbU0NoLTNYJGAM=
-----END ED25519 CERT-----
enc-key ntor TL7GcN+B++pB6eRN/0nBZGmWe125qh7ccQJ/Hhku+x8=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAabaCv4gv9ddyIztD1J8my9mgotmWnkHX94buLAtt15aAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61GxlI6caS8iFp2bLmg1+Pkgij47f
eetKn+yDC5Q3eo/hJLDBGAQNOX7jFMdr9HjotjXIt6/Khfmg58CZC/gKhAw=
-----END ED25519 CERT-----
introduction-point AQAGfwAAAQTS
onion-key ntor HWIigEAdcOgqgHPDFmzhhkeqvYP/GcMT2fKb5JY6ey8=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAZZVJwNlzVw1ZQGO7MTzC5MsySASd+fswAcjdTJJOifXAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61IVW0XivcAKhvUvNUsU1CFznk3Mz
KSsp/mBoKi2iY4f4eN2SXx8U6pmnxnXFxYP6obi+tc5QWj1Jbfl1Aci3TAA=
-----END ED25519 CERT-----
enc-key ntor 9Upi9XNWyqx3ZwHeQ5r3+Dh116k+C4yHeE9BcM68HDc=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAcH+1K5m7pRnMc01mPp5AYVnJK1iZ/fKHwK0tVR/jtBvAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61Hectpha37ioha85fpNt+/yDfebh
6BKUUQ0jf3SMXuNgX8SV9NSabn14WCSdKG/8RoYBCTR+yRJX0dy55mjg+go=
-----END ED25519 CERT-----
introduction-point AQAGfwAAARYv
onion-key ntor x/stThC6cVWJJUR7WERZj5VYVPTAOA/UDjHdtprJkiE=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAVMhalzZJ8txKHuCX8TEhmO3LbCvDgV0zMT4eQ49SDpBAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61GdVAiMag0dquEx4IywKDLEhxA7N
2RZFTS2QI+Sk3dyz46WO+epj1YBlgfOYCZlBEx+oFkRlUJdOc0Eu0sDlAw8=
-----END ED25519 CERT-----
enc-key ntor XI/a9NGh/7ClaFcKqtdI9DoP8da5ovwPDdgCHUr3xX0=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAZYGETSx12Og2xqJNMS9kGOHTEFeBkFPi7k0UaFv5HNKAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61E8vxB5lB83+rQnWmHLzpfuMUZjG
o7Ct/ZB0j8YRB5lKSd07YAjA6Zo8kMnuZYX2Mb67TxWDQ/zlYJGOwLlj7A8=
-----END ED25519 CERT-----
"#
        );
    }

    #[test]
    fn inner_hsdesc_too_many_link_specifiers() {
        let link_spec = LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 9999);
        let link_specifiers = std::iter::repeat(link_spec)
            .take(u8::MAX as usize + 1)
            .collect::<Vec<_>>();

        let intros = &[create_intro_point_descriptor(
            &mut Config::Deterministic.into_rng(),
            &link_specifiers,
        )];

        // A descriptor for a location-hidden service with an introduction point with too many link
        // specifiers
        let err = create_inner_desc(
            &[HandshakeType::NTOR], /* create2_formats */
            None,                   /* auth_required */
            false,                  /* is_single_onion_service */
            intros,                 /* intro_points */
            None,
        )
        .unwrap_err();

        assert!(expect_bug(err).contains("Too many link specifiers."));
    }

    #[test]
    fn inner_hsdesc_intro_auth() {
        let mut rng = Config::Deterministic.into_rng();
        let link_specs = &[LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 8080)];
        let intros = &[create_intro_point_descriptor(&mut rng, link_specs)];
        let auth = SmallVec::from([IntroAuthType::Ed25519, IntroAuthType::Ed25519]);

        // A descriptor for a location-hidden service with 1 introduction points which requires
        // auth.
        let hs_desc = create_inner_desc(
            &[HandshakeType::NTOR], /* create2_formats */
            Some(&auth),            /* auth_required */
            false,                  /* is_single_onion_service */
            intros,                 /* intro_points */
            None,
        )
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"create2-formats 2
intro-auth-required ed25519 ed25519
introduction-point AQAGfwAAAR+Q
onion-key ntor HWIigEAdcOgqgHPDFmzhhkeqvYP/GcMT2fKb5JY6ey8=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAZZVJwNlzVw1ZQGO7MTzC5MsySASd+fswAcjdTJJOifXAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61IVW0XivcAKhvUvNUsU1CFznk3Mz
KSsp/mBoKi2iY4f4eN2SXx8U6pmnxnXFxYP6obi+tc5QWj1Jbfl1Aci3TAA=
-----END ED25519 CERT-----
enc-key ntor 9Upi9XNWyqx3ZwHeQ5r3+Dh116k+C4yHeE9BcM68HDc=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAcH+1K5m7pRnMc01mPp5AYVnJK1iZ/fKHwK0tVR/jtBvAQAgBACQKRtN
eNThmyleMYdmFucrbgPcZNDO6S81MZD1r7q61Hectpha37ioha85fpNt+/yDfebh
6BKUUQ0jf3SMXuNgX8SV9NSabn14WCSdKG/8RoYBCTR+yRJX0dy55mjg+go=
-----END ED25519 CERT-----
"#
        );
    }

    #[test]
    #[cfg(feature = "hs-pow-full")]
    fn inner_hsdesc_pow_params() {
        use humantime::parse_rfc3339;

        let mut rng = Config::Deterministic.into_rng();
        let link_specs = &[LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 8080)];
        let intros = &[create_intro_point_descriptor(&mut rng, link_specs)];

        let pow_expiration = parse_rfc3339("1994-04-29T00:00:00Z").unwrap();
        let pow_params = PowParams::V1(PowParamsV1::new(
            TimerangeBound::new(Seed::from([0; 32]), ..pow_expiration),
            Effort::new(64),
        ));

        let hs_desc = create_inner_desc(
            &[HandshakeType::NTOR], /* create2_formats */
            None,                   /* auth_required */
            false,                  /* is_single_onion_service */
            intros,                 /* intro_points */
            Some(&pow_params),
        )
        .unwrap();

        assert!(hs_desc.contains(
            "\npow-params v1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 64 1994-04-29T00:00:00\n"
        ));
    }
}
