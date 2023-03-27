//! Functionality for encoding the inner document of an onion service descriptor.
//!
//! NOTE: `HsDescInner` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use crate::build::NetdocEncoder;
use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::doc::hsdesc::IntroAuthType;
use crate::NetdocBuilder;

use rand::CryptoRng;
use rand::RngCore;
use tor_bytes::{EncodeError, Writer};
use tor_cert::{CertType, CertifiedKey, Ed25519Cert};
use tor_error::{bad_api_usage, into_bad_api_usage};
use tor_hscrypto::pk::HsIntroPtSessionIdKey;
use tor_hscrypto::pk::HsSvcNtorKey;
use tor_linkspec::LinkSpec;
use tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_public;
use tor_llcrypto::pk::{curve25519, ed25519};

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
    // TODO hs: this should probably be a caret enum, not an integer
    pub(super) create2_formats: &'a [u32],
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
}

/// Information in an onion service descriptor about a single introduction point.
///
/// TODO hs: Move out of tor-netdoc: this is a general-purpose representation of an introduction
/// point, not merely an intermediate representation for decoding/encoding. There may be other
/// types that need to be factored out tor-netdoc for the same reason.
#[derive(Debug, Clone)]
pub struct IntroPointDesc {
    /// A list of link specifiers needed to extend a circuit to the introduction point.
    ///
    /// These can include public keys and network addresses.
    pub(crate) link_specifiers: Vec<LinkSpec>,
    /// The key used to extend a circuit _to the introduction point_, using the
    /// ntor or ntor3 handshakes.  (`KP_ntor`)
    pub(crate) ipt_ntor_key: curve25519::PublicKey,
    /// A key used to identify the onion service at this introduction point.
    /// (`KP_hs_ipt_sid`)
    pub(crate) ipt_sid_key: HsIntroPtSessionIdKey,
    /// `KP_hss_ntor`, the key used to encrypt a handshake _to the onion
    /// service_ when using this introduction point.
    ///
    /// The onion service uses a separate key of this type with each
    /// introduction point as part of its strategy for preventing replay
    /// attacks.
    pub(crate) svc_ntor_key: HsSvcNtorKey,
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
        } = self;

        let mut encoder = NetdocEncoder::new();

        {
            let mut create2_formats_enc = encoder.item(CREATE2_FORMATS);
            for fmt in create2_formats {
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

        for intro_point in intro_points {
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
                .signing_key(ed25519::Ed25519Identity::from(hs_desc_sign.public))
                .cert_key(CertifiedKey::Ed25519((*intro_point.ipt_sid_key).into()))
                .encode_and_sign(hs_desc_sign)
                .map_err(into_bad_api_usage!("failed to sign the intro auth key"))?;

            encoder
                .item(AUTH_KEY)
                .object("ED25519 CERT", signed_auth_key);

            // "The key is a base64 encoded curve25519 public key used to encrypt the introduction
            // request to service. (`KP_hss_ntor`)"
            //
            // TODO hs: The spec allows for multiple enc-key lines, but we currently only ever encode
            // a single one.
            encoder
                .item(ENC_KEY)
                .arg(&"ntor")
                .arg(&Base64::encode_string(
                    &intro_point.svc_ntor_key.as_bytes()[..],
                ));

            // The subject key is the the ed25519 equivalent of the svc_ntor_key curve25519 public
            // encryption key.

            // TODO hs: should the sign bit be 0 or 1?
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
                .signing_key(ed25519::Ed25519Identity::from(hs_desc_sign.public))
                .cert_key(CertifiedKey::Ed25519(ed25519::Ed25519Identity::from(
                    &ed_svc_ntor_key,
                )))
                .encode_and_sign(hs_desc_sign)
                .map_err(into_bad_api_usage!(
                    "failed to sign the intro encryption key"
                ))?;

            encoder
                .item(ENC_KEY_CERT)
                .object("ED25519 CERT", signed_enc_key);
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::doc::hsdesc::build::test::{
        expect_bug, test_ed25519_keypair, test_intro_point_descriptor,
    };
    use crate::doc::hsdesc::IntroAuthType;

    use rand::thread_rng;
    use smallvec::SmallVec;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;
    use tor_linkspec::LinkSpec;

    /// Build an inner document using the specified parameters.
    fn create_inner_desc(
        create2_formats: &[u32],
        auth_required: Option<&SmallVec<[IntroAuthType; 2]>>,
        is_single_onion_service: bool,
        intro_points: &[IntroPointDesc],
    ) -> Result<String, EncodeError> {
        let hs_desc_sign = test_ed25519_keypair();

        HsDescInner {
            hs_desc_sign: &hs_desc_sign,
            create2_formats,
            auth_required,
            is_single_onion_service,
            intro_points,
            intro_auth_key_cert_expiry: UNIX_EPOCH,
            intro_enc_key_cert_expiry: UNIX_EPOCH,
        }
        .build_sign(&mut thread_rng())
    }

    #[test]
    fn inner_hsdesc_no_intro_auth() {
        // A descriptor for a "single onion service"
        let hs_desc = create_inner_desc(
            &[1234], /* create2_formats */
            None,    /* auth_required */
            true,    /* is_single_onion_service */
            &[],     /* intro_points */
        )
        .unwrap();

        assert_eq!(hs_desc, "create2-formats 1234\nsingle-onion-service\n");

        // A descriptor for a location-hidden service
        let hs_desc = create_inner_desc(
            &[1234], /* create2_formats */
            None,    /* auth_required */
            false,   /* is_single_onion_service */
            &[],     /* intro_points */
        )
        .unwrap();

        assert_eq!(hs_desc, "create2-formats 1234\n");

        let link_specs1 = vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 1234)];
        let link_specs2 = vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 5679)];
        let link_specs3 = vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 8901)];

        let intros = &[
            test_intro_point_descriptor(link_specs1),
            test_intro_point_descriptor(link_specs2),
            test_intro_point_descriptor(link_specs3),
        ];

        let hs_desc = create_inner_desc(
            &[1234, 32, 23], /* create2_formats */
            None,            /* auth_required */
            false,           /* is_single_onion_service */
            intros,          /* intro_points */
        )
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"create2-formats 1234 32 23
introduction-point AQAGfwAAAQTS
onion-key ntor tnEhX8317Kk2N6hoacsCK0ir/LKE3DcPgYlDI5OKegg=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAewZqL9VZkkLDGVQ4eYcCdB/2+XvKqaT6DfOOdIK1zY8AQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PGJfiGR8BqiEDVPAUl0ToUn+72JW
zJUcnzAdNAysaR5UrK0i+/d4vOzNsNFQ2f7vkfFuwvQEeDlqw8lddvNwxg0=
-----END ED25519 CERT-----
enc-key ntor c6PGJQNAqJxyfC6O6VvvHc/wgMrQcKr3Ui7pBvv2dXE=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAR8cWg2fNApajIBOuKccs3OYfVopANyb9NDTpy7J86VTAQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PNm8uaG3bLDi06dUrHSEDBCIVsx5
CPFWD3sGHVPIZA5JnK7mbX8zhsX/MnV/0jj+YKLCQtOPwbqC3R7iXWjBsAE=
-----END ED25519 CERT-----
introduction-point AQAGfwAAARYv
onion-key ntor tnEhX8317Kk2N6hoacsCK0ir/LKE3DcPgYlDI5OKegg=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAewZqL9VZkkLDGVQ4eYcCdB/2+XvKqaT6DfOOdIK1zY8AQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PGJfiGR8BqiEDVPAUl0ToUn+72JW
zJUcnzAdNAysaR5UrK0i+/d4vOzNsNFQ2f7vkfFuwvQEeDlqw8lddvNwxg0=
-----END ED25519 CERT-----
enc-key ntor c6PGJQNAqJxyfC6O6VvvHc/wgMrQcKr3Ui7pBvv2dXE=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAR8cWg2fNApajIBOuKccs3OYfVopANyb9NDTpy7J86VTAQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PNm8uaG3bLDi06dUrHSEDBCIVsx5
CPFWD3sGHVPIZA5JnK7mbX8zhsX/MnV/0jj+YKLCQtOPwbqC3R7iXWjBsAE=
-----END ED25519 CERT-----
introduction-point AQAGfwAAASLF
onion-key ntor tnEhX8317Kk2N6hoacsCK0ir/LKE3DcPgYlDI5OKegg=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAewZqL9VZkkLDGVQ4eYcCdB/2+XvKqaT6DfOOdIK1zY8AQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PGJfiGR8BqiEDVPAUl0ToUn+72JW
zJUcnzAdNAysaR5UrK0i+/d4vOzNsNFQ2f7vkfFuwvQEeDlqw8lddvNwxg0=
-----END ED25519 CERT-----
enc-key ntor c6PGJQNAqJxyfC6O6VvvHc/wgMrQcKr3Ui7pBvv2dXE=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAR8cWg2fNApajIBOuKccs3OYfVopANyb9NDTpy7J86VTAQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PNm8uaG3bLDi06dUrHSEDBCIVsx5
CPFWD3sGHVPIZA5JnK7mbX8zhsX/MnV/0jj+YKLCQtOPwbqC3R7iXWjBsAE=
-----END ED25519 CERT-----
"#
        );
    }

    #[test]
    fn inner_hsdesc_too_many_link_specifiers() {
        let hs_desc_sign = test_ed25519_keypair();

        let link_spec = LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 9999);
        let link_specifiers = std::iter::repeat(link_spec)
            .take(u8::MAX as usize + 1)
            .collect::<Vec<_>>();
        let intros = &[test_intro_point_descriptor(link_specifiers)];

        // A descriptor for a location-hidden service with an introduction point with too many link
        // specifiers
        let err = create_inner_desc(
            &[1234], /* create2_formats */
            None,    /* auth_required */
            false,   /* is_single_onion_service */
            intros,  /* intro_points */
        )
        .unwrap_err();

        assert!(expect_bug(err).contains("Too many link specifiers."));
    }

    #[test]
    fn inner_hsdesc_intro_auth() {
        let hs_desc_sign = test_ed25519_keypair();
        let link_specs = vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 8080)];
        let intros = &[test_intro_point_descriptor(link_specs)];
        let auth = SmallVec::from([IntroAuthType::Ed25519, IntroAuthType::Ed25519]);

        // A descriptor for a location-hidden service with 1 introduction points which requires
        // auth.
        let hs_desc = create_inner_desc(
            &[1234],     /* create2_formats */
            Some(&auth), /* auth_required */
            false,       /* is_single_onion_service */
            intros,      /* intro_points */
        )
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"create2-formats 1234
intro-auth-required ed25519 ed25519
introduction-point AQAGfwAAAR+Q
onion-key ntor tnEhX8317Kk2N6hoacsCK0ir/LKE3DcPgYlDI5OKegg=
auth-key
-----BEGIN ED25519 CERT-----
AQkAAAAAAewZqL9VZkkLDGVQ4eYcCdB/2+XvKqaT6DfOOdIK1zY8AQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PGJfiGR8BqiEDVPAUl0ToUn+72JW
zJUcnzAdNAysaR5UrK0i+/d4vOzNsNFQ2f7vkfFuwvQEeDlqw8lddvNwxg0=
-----END ED25519 CERT-----
enc-key ntor c6PGJQNAqJxyfC6O6VvvHc/wgMrQcKr3Ui7pBvv2dXE=
enc-key-cert
-----BEGIN ED25519 CERT-----
AQsAAAAAAR8cWg2fNApajIBOuKccs3OYfVopANyb9NDTpy7J86VTAQAgBADsGai/
VWZJCwxlUOHmHAnQf9vl7yqmk+g3zjnSCtc2PNm8uaG3bLDi06dUrHSEDBCIVsx5
CPFWD3sGHVPIZA5JnK7mbX8zhsX/MnV/0jj+YKLCQtOPwbqC3R7iXWjBsAE=
-----END ED25519 CERT-----
"#
        );
    }
}
