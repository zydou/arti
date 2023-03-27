//! Functionality for encoding the middle document of an onion service descriptor.
//!
//! NOTE: `HsDescMiddle` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use std::borrow::Cow;

use crate::build::NetdocEncoder;
use crate::doc::hsdesc::build::ClientAuth;
use crate::doc::hsdesc::desc_enc::{HS_DESC_CLIENT_ID_LEN, HS_DESC_ENC_NONCE_LEN, HS_DESC_IV_LEN};
use crate::doc::hsdesc::middle::{AuthClient, HsMiddleKwd, HS_DESC_AUTH_TYPE};
use crate::NetdocBuilder;

use tor_bytes::EncodeError;
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey};
use tor_llcrypto::util::ct::CtByteArray;

use base64ct::{Base64, Encoding};
use rand::{CryptoRng, Rng, RngCore};

/// The representation of the middle document of an onion service descriptor.
///
/// The plaintext format of this document is described in section 2.5.1.2. of rend-spec-v3.
#[derive(Debug)]
pub(super) struct HsDescMiddle<'a> {
    /// Client authorization parameters, if client authentication is enabled. If set to `None`,
    /// client authentication is disabled.
    pub(super) client_auth: Option<&'a ClientAuth>,
    /// The (encrypted) inner document of the onion service descriptor.
    ///
    /// The `encrypted` field is created by encrypting an inner document built using
    /// [`crate::doc::hsdesc::build::inner::HsDescInnerBuilder`] as described in sections
    /// 2.5.2.1. and 2.5.2.2. of rend-spec-v3.
    pub(super) encrypted: Vec<u8>,
}

impl<'a> NetdocBuilder for HsDescMiddle<'a> {
    fn build_sign<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<String, EncodeError> {
        use HsMiddleKwd::*;

        let HsDescMiddle {
            client_auth,
            encrypted,
        } = self;

        let mut encoder = NetdocEncoder::new();

        let (ephemeral_key, auth_clients): (_, Cow<Vec<_>>) = match client_auth {
            Some(client_auth) if client_auth.auth_clients.is_empty() => {
                return Err(tor_error::bad_api_usage!(
                    "client authentication is enabled, but there are no authorized clients"
                )
                .into());
            }
            Some(client_auth) => {
                // Client auth is enabled.
                (
                    *client_auth.ephemeral_key,
                    Cow::Borrowed(&client_auth.auth_clients),
                )
            }
            None => {
                // Generate a single client-auth line filled with random values for client-id,
                // iv, and encrypted-cookie.
                let dummy_auth_client = AuthClient {
                    client_id: CtByteArray::from(rng.gen::<[u8; HS_DESC_CLIENT_ID_LEN]>()),
                    iv: rng.gen::<[u8; HS_DESC_IV_LEN]>(),
                    encrypted_cookie: rng.gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(),
                };

                // As per section 2.5.1.2. of rend-spec-v3, if client auth is disabled, we need to
                // generate some fake data for the desc-auth-ephemeral-key and auth-client fields.
                let secret = EphemeralSecret::new(rng);
                let dummy_ephemeral_key = PublicKey::from(&secret);

                // TODO hs: Remove useless vec![] allocation.
                (dummy_ephemeral_key, Cow::Owned(vec![dummy_auth_client]))
            }
        };

        encoder.item(DESC_AUTH_TYPE).arg(&HS_DESC_AUTH_TYPE);
        encoder
            .item(DESC_AUTH_EPHEMERAL_KEY)
            .arg(&Base64::encode_string(ephemeral_key.as_bytes()));

        for auth_client in &*auth_clients {
            encoder
                .item(AUTH_CLIENT)
                .arg(&Base64::encode_string(&*auth_client.client_id))
                .arg(&Base64::encode_string(&auth_client.iv))
                .arg(&Base64::encode_string(&auth_client.encrypted_cookie));
        }

        encoder.item(ENCRYPTED).object("MESSAGE", encrypted);
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
        create_curve25519_pk, expect_bug, TEST_DESCRIPTOR_COOKIE,
    };
    use crate::doc::hsdesc::build::ClientAuth;
    use tor_basic_utils::test_rng::Config;

    // Some dummy bytes, not actually encrypted.
    const TEST_ENCRYPTED_VALUE: &[u8] = &[1, 2, 3, 4];

    #[test]
    fn middle_hsdesc_encoding_no_client_auth() {
        let hs_desc = HsDescMiddle {
            client_auth: None,
            encrypted: TEST_ENCRYPTED_VALUE.into(),
        }
        .build_sign(&mut Config::Deterministic.into_rng())
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"desc-auth-type x25519
desc-auth-ephemeral-key XI/a9NGh/7ClaFcKqtdI9DoP8da5ovwPDdgCHUr3xX0=
auth-client F+Z6EDfG7oc= 7EIXRtlSozVtGAs6+mNujQ== pNtSIyiCahSvUVg+7s71Ow==
encrypted
-----BEGIN MESSAGE-----
AQIDBA==
-----END MESSAGE-----
"#
        );
    }

    #[test]
    fn middle_hsdesc_encoding_with_bad_client_auth() {
        let client_auth = ClientAuth {
            ephemeral_key: create_curve25519_pk(&mut Config::Deterministic.into_rng()).into(),
            auth_clients: vec![],
            descriptor_cookie: TEST_DESCRIPTOR_COOKIE,
        };

        let err = HsDescMiddle {
            client_auth: Some(&client_auth),
            encrypted: TEST_ENCRYPTED_VALUE.into(),
        }
        .build_sign(&mut Config::Deterministic.into_rng())
        .unwrap_err();

        assert!(expect_bug(err)
            .contains("client authentication is enabled, but there are no authorized clients"));
    }

    #[test]
    fn middle_hsdesc_encoding_client_auth() {
        // 2 authorized clients
        let auth_clients = vec![
            AuthClient {
                client_id: [2; 8].into(),
                iv: [2; 16],
                encrypted_cookie: [3; 16],
            },
            AuthClient {
                client_id: [4; 8].into(),
                iv: [5; 16],
                encrypted_cookie: [6; 16],
            },
        ];

        let client_auth = ClientAuth {
            ephemeral_key: create_curve25519_pk(&mut Config::Deterministic.into_rng()).into(),
            auth_clients,
            descriptor_cookie: TEST_DESCRIPTOR_COOKIE,
        };

        let hs_desc = HsDescMiddle {
            client_auth: Some(&client_auth),
            encrypted: TEST_ENCRYPTED_VALUE.into(),
        }
        .build_sign(&mut Config::Deterministic.into_rng())
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"desc-auth-type x25519
desc-auth-ephemeral-key HWIigEAdcOgqgHPDFmzhhkeqvYP/GcMT2fKb5JY6ey8=
auth-client AgICAgICAgI= AgICAgICAgICAgICAgICAg== AwMDAwMDAwMDAwMDAwMDAw==
auth-client BAQEBAQEBAQ= BQUFBQUFBQUFBQUFBQUFBQ== BgYGBgYGBgYGBgYGBgYGBg==
encrypted
-----BEGIN MESSAGE-----
AQIDBA==
-----END MESSAGE-----
"#
        );
    }
}
