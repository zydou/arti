//! Functionality for encoding the middle document of an onion service descriptor.
//!
//! NOTE: `HsDescMiddle` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use crate::build::NetdocEncoder;
use crate::doc::hsdesc::build::ClientAuth;
use crate::doc::hsdesc::desc_enc::{
    build_descriptor_cookie_key, HS_DESC_CLIENT_ID_LEN, HS_DESC_ENC_NONCE_LEN, HS_DESC_IV_LEN,
};
use crate::doc::hsdesc::middle::{AuthClient, HsMiddleKwd, HS_DESC_AUTH_TYPE};
use crate::NetdocBuilder;

use tor_bytes::EncodeError;
use tor_hscrypto::Subcredential;
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey};
use tor_llcrypto::util::ct::CtByteArray;

use base64ct::{Base64, Encoding};
use rand::{CryptoRng, Rng, RngCore};

/// The representation of the middle document of an onion service descriptor.
///
/// The plaintext format of this document is described in section 2.5.1.2. of rend-spec-v3.
#[derive(Debug)]
pub(super) struct HsDescMiddle<'a> {
    /// Restricted discovery parameters, if restricted discovery is enabled. If set to `None`,
    /// restricted discovery is disabled.
    pub(super) client_auth: Option<&'a ClientAuth<'a>>,
    /// The "subcredential" of the onion service.
    pub(super) subcredential: Subcredential,
    /// The (encrypted) inner document of the onion service descriptor.
    ///
    /// The `encrypted` field is created by encrypting a
    /// [`build::inner::HsDescInner`](super::inner::HsDescInner)
    /// inner document as described in sections
    /// 2.5.2.1. and 2.5.2.2. of rend-spec-v3.
    pub(super) encrypted: Vec<u8>,
}

impl<'a> NetdocBuilder for HsDescMiddle<'a> {
    fn build_sign<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<String, EncodeError> {
        use cipher::{KeyIvInit, StreamCipher};
        use tor_llcrypto::cipher::aes::Aes256Ctr as Cipher;
        use HsMiddleKwd::*;

        let HsDescMiddle {
            client_auth,
            subcredential,
            encrypted,
        } = self;

        let mut encoder = NetdocEncoder::new();

        let (ephemeral_key, auth_clients): (_, Box<dyn std::iter::Iterator<Item = AuthClient>>) =
            match client_auth {
                Some(client_auth) if client_auth.auth_clients.is_empty() => {
                    return Err(tor_error::bad_api_usage!(
                        "restricted discovery is enabled, but there are no authorized clients"
                    )
                    .into());
                }
                Some(client_auth) => {
                    // Restricted discovery is enabled.
                    let auth_clients = client_auth.auth_clients.iter().map(|client| {
                        let (client_id, cookie_key) = build_descriptor_cookie_key(
                            client_auth.ephemeral_key.secret.as_ref(),
                            client,
                            &subcredential,
                        );

                        // Encrypt the descriptor cookie with the public key of the client.
                        let mut encrypted_cookie = client_auth.descriptor_cookie;
                        let iv = rng.gen::<[u8; HS_DESC_IV_LEN]>();
                        let mut cipher = Cipher::new(&cookie_key.into(), &iv.into());
                        cipher.apply_keystream(&mut encrypted_cookie);

                        AuthClient {
                            client_id,
                            iv,
                            encrypted_cookie,
                        }
                    });

                    (*client_auth.ephemeral_key.public, Box::new(auth_clients))
                }
                None => {
                    // Generate a single client-auth line filled with random values for client-id,
                    // iv, and encrypted-cookie.
                    let dummy_auth_client = AuthClient {
                        client_id: CtByteArray::from(rng.gen::<[u8; HS_DESC_CLIENT_ID_LEN]>()),
                        iv: rng.gen::<[u8; HS_DESC_IV_LEN]>(),
                        encrypted_cookie: rng.gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(),
                    };

                    // As per section 2.5.1.2. of rend-spec-v3, if restricted discovery is disabled, we need to
                    // generate some fake data for the desc-auth-ephemeral-key and auth-client fields.
                    let secret = EphemeralSecret::random_from_rng(rng);
                    let dummy_ephemeral_key = PublicKey::from(&secret);

                    (
                        dummy_ephemeral_key,
                        Box::new(std::iter::once(dummy_auth_client)),
                    )
                }
            };

        encoder.item(DESC_AUTH_TYPE).arg(&HS_DESC_AUTH_TYPE);
        encoder
            .item(DESC_AUTH_EPHEMERAL_KEY)
            .arg(&Base64::encode_string(ephemeral_key.as_bytes()));

        for auth_client in auth_clients {
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
    use crate::doc::hsdesc::build::test::{create_curve25519_pk, expect_bug};
    use crate::doc::hsdesc::build::ClientAuth;
    use crate::doc::hsdesc::test_data::TEST_SUBCREDENTIAL;
    use tor_basic_utils::test_rng::Config;
    use tor_hscrypto::pk::HsSvcDescEncKeypair;
    use tor_llcrypto::pk::curve25519;

    // Some dummy bytes, not actually encrypted.
    const TEST_ENCRYPTED_VALUE: &[u8] = &[1, 2, 3, 4];

    #[test]
    fn middle_hsdesc_encoding_no_client_auth() {
        let hs_desc = HsDescMiddle {
            client_auth: None,
            subcredential: TEST_SUBCREDENTIAL.into(),
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
        let mut rng = Config::Deterministic.into_rng();
        let secret = curve25519::StaticSecret::random_from_rng(&mut rng);
        let public = curve25519::PublicKey::from(&secret).into();

        let client_auth = ClientAuth {
            ephemeral_key: HsSvcDescEncKeypair {
                public,
                secret: secret.into(),
            },
            auth_clients: &[],
            descriptor_cookie: rand::Rng::gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(&mut rng),
        };

        let err = HsDescMiddle {
            client_auth: Some(&client_auth),
            subcredential: TEST_SUBCREDENTIAL.into(),
            encrypted: TEST_ENCRYPTED_VALUE.into(),
        }
        .build_sign(&mut rng)
        .unwrap_err();

        assert!(expect_bug(err)
            .contains("restricted discovery is enabled, but there are no authorized clients"));
    }

    #[test]
    fn middle_hsdesc_encoding_client_auth() {
        let mut rng = Config::Deterministic.into_rng();
        // 2 authorized clients
        let auth_clients = vec![
            create_curve25519_pk(&mut rng),
            create_curve25519_pk(&mut rng),
        ];

        let secret = curve25519::StaticSecret::random_from_rng(&mut rng);
        let public = curve25519::PublicKey::from(&secret).into();

        let client_auth = ClientAuth {
            ephemeral_key: HsSvcDescEncKeypair {
                public,
                secret: secret.into(),
            },
            auth_clients: &auth_clients,
            descriptor_cookie: rand::Rng::gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(&mut rng),
        };

        let hs_desc = HsDescMiddle {
            client_auth: Some(&client_auth),
            subcredential: TEST_SUBCREDENTIAL.into(),
            encrypted: TEST_ENCRYPTED_VALUE.into(),
        }
        .build_sign(&mut Config::Deterministic.into_rng())
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"desc-auth-type x25519
desc-auth-ephemeral-key 9Upi9XNWyqx3ZwHeQ5r3+Dh116k+C4yHeE9BcM68HDc=
auth-client pxfSbhBMPw0= F+Z6EDfG7ofsQhdG2VKjNQ== fEursUD9Bj5Q9mFP8sIddA==
auth-client DV7nt+CDOno= bRgLOvpjbo2k21IjKIJqFA== 2yVT+Lpm/WL4JAU64zlGpQ==
encrypted
-----BEGIN MESSAGE-----
AQIDBA==
-----END MESSAGE-----
"#
        );
    }
}
