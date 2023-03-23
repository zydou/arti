//! Functionality for encoding the middle document of an onion service descriptor.
//!
//! NOTE: `HsDescMiddleBuilder` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use crate::build::NetdocEncoder;
use crate::doc::hsdesc::build::ClientAuth;
use crate::doc::hsdesc::desc_enc::{HS_DESC_CLIENT_ID_LEN, HS_DESC_ENC_NONCE_LEN, HS_DESC_IV_LEN};
use crate::doc::hsdesc::middle::{AuthClient, HsMiddleKwd, HS_DESC_AUTH_TYPE};
use crate::NetdocBuilder;

use tor_bytes::EncodeError;
use tor_error::into_bad_api_usage;
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey};
use tor_llcrypto::util::ct::CtByteArray;

use base64ct::{Base64, Encoding};
use derive_builder::Builder;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};

use std::borrow::Cow;

/// The representation of the middle document of an onion service descriptor.
///
/// The plaintext format of this document is described in section 2.5.1.2. of rend-spec-v3.
#[derive(Builder)]
#[builder(public, derive(Debug), pattern = "owned", build_fn(vis = "pub(super)"))]
pub(super) struct HsDescMiddle<'a> {
    /// Client authorization parameters, if client authentication is enabled. If set to `None`,
    /// client authentication is disabled.
    client_auth: Option<&'a ClientAuth>,
    /// The (encrypted) inner document of the onion service descriptor.
    ///
    /// The `encrypted` field is created by encrypting an inner document built using
    /// [`crate::doc::hsdesc::build::inner::HsDescInnerBuilder`] as described in sections
    /// 2.5.2.1. and 2.5.2.2. of rend-spec-v3.
    encrypted: Vec<u8>,
}

impl<'a> NetdocBuilder for HsDescMiddleBuilder<'a> {
    fn build_sign(self) -> Result<String, EncodeError> {
        use HsMiddleKwd::*;

        let HsDescMiddle {
            client_auth,
            encrypted,
        } = self
            .build()
            .map_err(into_bad_api_usage!("the HsDescMiddle could not be built"))?;

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
                // As per section 2.5.1.2. of rend-spec-v3, if client auth is disabled, we need to
                // generate some fake data for the desc-auth-ephemeral-key and auth-client fields.
                let secret = EphemeralSecret::new(OsRng);
                let dummy_ephemeral_key = PublicKey::from(&secret);

                let mut rng = thread_rng();
                // Generate a single client-auth line filled with random values for client-id,
                // iv, and encrypted-cookie.
                let dummy_auth_client = AuthClient {
                    client_id: CtByteArray::from(rng.gen::<[u8; HS_DESC_CLIENT_ID_LEN]>()),
                    iv: rng.gen::<[u8; HS_DESC_IV_LEN]>(),
                    encrypted_cookie: rng.gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(),
                };

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
        expect_bug, TEST_CURVE25519_PUBLIC1, TEST_DESCRIPTOR_COOKIE,
    };
    use crate::doc::hsdesc::build::ClientAuth;
    use tor_llcrypto::pk::curve25519;

    // Some dummy bytes, not actually encrypted.
    const TEST_ENCRYPTED_VALUE: &[u8] = &[1, 2, 3, 4];

    #[test]
    fn middle_hsdesc_encoding_no_client_auth() {
        let hs_desc = HsDescMiddleBuilder::default()
            .client_auth(None)
            .encrypted(TEST_ENCRYPTED_VALUE.into())
            .build_sign()
            .unwrap();

        let mut lines = hs_desc.splitn(4, '\n');

        assert_eq!(lines.next().unwrap(), "desc-auth-type x25519");
        // If client auth is disabled, HsDescMiddleBuilder will generate a dummy ephemeral key (a
        // different one each time), so this test checks it is present in the built document. It
        // does _not_ actually validate its value.
        assert!(lines
            .next()
            .unwrap()
            .starts_with("desc-auth-ephemeral-key "));
        // The above also applies to the auth-client line (since client auth is disabled, it's
        // going to have a different value on each run).
        assert!(lines.next().unwrap().starts_with("auth-client "));
        assert_eq!(
            lines.next().unwrap(),
            r#"encrypted
-----BEGIN MESSAGE-----
AQIDBA==
-----END MESSAGE-----
"#
        );
        assert!(lines.next().is_none());
    }

    #[test]
    fn middle_hsdesc_encoding_with_bad_client_auth() {
        let client_auth = ClientAuth {
            ephemeral_key: curve25519::PublicKey::from(TEST_CURVE25519_PUBLIC1).into(),
            auth_clients: vec![],
            descriptor_cookie: TEST_DESCRIPTOR_COOKIE,
        };

        let err = HsDescMiddleBuilder::default()
            .client_auth(Some(&client_auth))
            .encrypted(TEST_ENCRYPTED_VALUE.into())
            .build_sign()
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
            ephemeral_key: curve25519::PublicKey::from(TEST_CURVE25519_PUBLIC1).into(),
            auth_clients,
            descriptor_cookie: TEST_DESCRIPTOR_COOKIE,
        };

        let hs_desc = HsDescMiddleBuilder::default()
            .client_auth(Some(&client_auth))
            .encrypted(TEST_ENCRYPTED_VALUE.into())
            .build_sign()
            .unwrap();

        assert_eq!(
            hs_desc,
            r#"desc-auth-type x25519
desc-auth-ephemeral-key tnEhX8317Kk2N6hoacsCK0ir/LKE3DcPgYlDI5OKegg=
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
