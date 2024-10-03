//! Handle the middle document of an onion service descriptor.

use once_cell::sync::Lazy;
use subtle::ConstantTimeEq;
use tor_hscrypto::pk::{HsBlindId, HsClientDescEncSecretKey, HsSvcDescEncKey};
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::util::ct::CtByteArray;

use crate::doc::hsdesc::desc_enc::build_descriptor_cookie_key;
use crate::parse::tokenize::{Item, NetDocReader};
use crate::parse::{keyword::Keyword, parser::SectionRules};
use crate::types::misc::B64;
use crate::{Pos, Result};

use super::desc_enc::{
    HsDescEncNonce, HsDescEncryption, HS_DESC_CLIENT_ID_LEN, HS_DESC_ENC_NONCE_LEN, HS_DESC_IV_LEN,
};
use super::HsDescError;

/// The only currently recognized `desc-auth-type`.
//
// TODO: In theory this should be an enum, if we ever add a second value here.
pub(super) const HS_DESC_AUTH_TYPE: &str = "x25519";

/// A more-or-less verbatim representation of the middle document of an onion
/// service descriptor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
pub(super) struct HsDescMiddle {
    /// A public key used by authorized clients to decrypt the key used to
    /// decrypt the encryption layer and decode the inner document.  This is
    /// ignored if restricted discovery is not in use.
    ///
    /// This is `KP_hss_desc_enc`, and appears as `desc-auth-ephemeral-key` in
    /// the document format; It is used along with `KS_hsc_desc_enc` to perform
    /// a diffie-hellman operation and decrypt the encryption layer.
    svc_desc_enc_key: HsSvcDescEncKey,
    /// One or more authorized clients, and the key exchange information that
    /// they use to compute shared keys for decrypting the encryption layer.
    ///
    /// Each of these is parsed from a `auth-client` line.
    auth_clients: Vec<AuthClient>,
    /// The (encrypted) inner document of the onion service descriptor.
    encrypted: Vec<u8>,
}

impl HsDescMiddle {
    /// Decrypt the encrypted inner document contained within this middle
    /// document.
    ///
    /// If present, `key` is an authorization key, and we assume that the
    /// decryption is nontrivial.
    ///
    /// A failure may mean either that the encryption was corrupted, or that we
    /// didn't have the right key.
    #[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
    pub(super) fn decrypt_inner(
        &self,
        blinded_id: &HsBlindId,
        revision: RevisionCounter,
        subcredential: &Subcredential,
        key: Option<&HsClientDescEncSecretKey>,
    ) -> std::result::Result<Vec<u8>, super::HsDescError> {
        let desc_enc_nonce = key.and_then(|k| self.find_cookie(subcredential, k));
        let decrypt = HsDescEncryption {
            blinded_id,
            desc_enc_nonce: desc_enc_nonce.as_ref(),
            subcredential,
            revision,
            string_const: b"hsdir-encrypted-data",
        };

        match decrypt.decrypt(&self.encrypted) {
            Ok(mut v) => {
                // Work around a bug in an implementation we presume to be
                // OnionBalance: it doesn't NL-terminate the final line of the
                // inner document.
                if !v.ends_with(b"\n") {
                    v.push(b'\n');
                }
                Ok(v)
            }
            Err(_) => match (key, desc_enc_nonce) {
                (Some(_), None) => Err(HsDescError::WrongDecryptionKey),
                (Some(_), Some(_)) => Err(HsDescError::DecryptionFailed),
                (None, _) => Err(HsDescError::MissingDecryptionKey),
            },
        }
    }

    /// Use a `ClientDescAuthSecretKey` (`KS_hsc_desc_enc`) to see if there is any `auth-client`
    /// entry for us (a client who holds that secret key) in this descriptor.
    /// If so, decrypt it and return its
    /// corresponding "Descriptor Cookie" (`N_hs_desc_enc`)
    ///
    /// If no such `N_hs_desc_enc` is found, then either we do not have
    /// permission to decrypt the encryption layer, OR no permission is required.
    ///
    /// (The protocol makes it intentionally impossible to distinguish any error
    /// conditions here other than "no cookie for you.")
    fn find_cookie(
        &self,
        subcredential: &Subcredential,
        ks_hsc_desc_enc: &HsClientDescEncSecretKey,
    ) -> Option<HsDescEncNonce> {
        use cipher::{KeyIvInit, StreamCipher};
        use tor_llcrypto::cipher::aes::Aes256Ctr as Cipher;
        use tor_llcrypto::util::ct::ct_lookup;

        let (client_id, cookie_key) = build_descriptor_cookie_key(
            ks_hsc_desc_enc.as_ref(),
            &self.svc_desc_enc_key,
            subcredential,
        );
        // See whether there is any matching client_id in self.auth_ids.
        let auth_client = ct_lookup(&self.auth_clients, |c| c.client_id.ct_eq(&client_id))?;

        // We found an auth client entry: Take and decrypt the cookie `N_hs_desc_enc` at last.
        let mut cookie = auth_client.encrypted_cookie;
        let mut cipher = Cipher::new(&cookie_key.into(), &auth_client.iv.into());
        cipher.apply_keystream(&mut cookie);
        Some(cookie.into())
    }
}

/// Information that a single authorized client can use to decrypt the onion
/// service descriptor.
#[derive(Debug, Clone)]
pub(super) struct AuthClient {
    /// A check field that clients can use to see if this [`AuthClient`] entry corresponds to a key they hold.
    ///
    /// This is the first part of the `auth-client` line.
    pub(super) client_id: CtByteArray<HS_DESC_CLIENT_ID_LEN>,
    /// An IV used to decrypt `encrypted_cookie`.
    ///
    /// This is the second item on the `auth-client` line.
    pub(super) iv: [u8; HS_DESC_IV_LEN],
    /// An encrypted value used to find the descriptor cookie `N_hs_desc_enc`,
    /// which in turn is
    /// needed to decrypt the [HsDescMiddle]'s `encrypted_body`.
    ///
    /// This is the third item on the `auth-client` line.  When decrypted, it
    /// reveals a `DescEncEncryptionCookie` (`N_hs_desc_enc`, not yet so named
    /// in the spec).
    pub(super) encrypted_cookie: [u8; HS_DESC_ENC_NONCE_LEN],
}

impl AuthClient {
    /// Try to extract an AuthClient from a single AuthClient item.
    fn from_item(item: &Item<'_, HsMiddleKwd>) -> Result<Self> {
        use crate::NetdocErrorKind as EK;

        if item.kwd() != HsMiddleKwd::AUTH_CLIENT {
            return Err(EK::Internal.with_msg("called with invalid argument."));
        }
        let client_id = item.parse_arg::<B64>(0)?.into_array()?.into();
        let iv = item.parse_arg::<B64>(1)?.into_array()?;
        let encrypted_cookie = item.parse_arg::<B64>(2)?.into_array()?;
        Ok(AuthClient {
            client_id,
            iv,
            encrypted_cookie,
        })
    }
}

decl_keyword! {
    pub(crate) HsMiddleKwd {
        "desc-auth-type" => DESC_AUTH_TYPE,
        "desc-auth-ephemeral-key" => DESC_AUTH_EPHEMERAL_KEY,
        "auth-client" => AUTH_CLIENT,
        "encrypted" => ENCRYPTED,
    }
}

/// Rules about how keywords appear in the middle document of an onion service
/// descriptor.
static HS_MIDDLE_RULES: Lazy<SectionRules<HsMiddleKwd>> = Lazy::new(|| {
    use HsMiddleKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(DESC_AUTH_TYPE.rule().required().args(1..));
    rules.add(DESC_AUTH_EPHEMERAL_KEY.rule().required().args(1..));
    rules.add(AUTH_CLIENT.rule().required().may_repeat().args(3..));
    rules.add(ENCRYPTED.rule().required().obj_required());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());

    rules.build()
});

impl HsDescMiddle {
    /// Try to parse the middle document of an onion service descriptor from a provided
    /// string.
    #[cfg_attr(feature = "hsdesc-inner-docs", visibility::make(pub))]
    pub(super) fn parse(s: &str) -> Result<HsDescMiddle> {
        let mut reader = NetDocReader::new(s);
        let result = HsDescMiddle::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        Ok(result)
    }

    /// Extract an HsDescMiddle from a reader.
    ///
    /// The reader must contain a single HsDescOuter; we return an error if not.
    fn take_from_reader(reader: &mut NetDocReader<'_, HsMiddleKwd>) -> Result<HsDescMiddle> {
        use crate::NetdocErrorKind as EK;
        use HsMiddleKwd::*;

        let body = HS_MIDDLE_RULES.parse(reader)?;

        // Check for the only currently recognized `desc-auth-type`
        {
            let auth_type = body.required(DESC_AUTH_TYPE)?.required_arg(0)?;
            if auth_type != HS_DESC_AUTH_TYPE {
                return Err(EK::BadDocumentVersion
                    .at_pos(Pos::at(auth_type))
                    .with_msg(format!("Unrecognized desc-auth-type {auth_type:?}")));
            }
        }

        // Extract `KP_hss_desc_enc` from DESC_AUTH_EPHEMERAL_KEY
        let ephemeral_key: HsSvcDescEncKey = {
            let token = body.required(DESC_AUTH_EPHEMERAL_KEY)?;
            let key = curve25519::PublicKey::from(token.parse_arg::<B64>(0)?.into_array()?);
            key.into()
        };

        // Parse all the auth-client lines.
        let auth_clients: Vec<AuthClient> = body
            .slice(AUTH_CLIENT)
            .iter()
            .map(AuthClient::from_item)
            .collect::<Result<Vec<_>>>()?;

        // The encrypted body is taken verbatim.
        let encrypted_body: Vec<u8> = body.required(ENCRYPTED)?.obj("MESSAGE")?;

        Ok(HsDescMiddle {
            svc_desc_enc_key: ephemeral_key,
            auth_clients,
            encrypted: encrypted_body,
        })
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

    use hex_literal::hex;
    use tor_checkable::{SelfSigned, Timebound};

    use super::*;
    use crate::doc::hsdesc::{
        outer::HsDescOuter,
        test_data::{TEST_DATA, TEST_SUBCREDENTIAL},
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
        assert_eq!(
            middle.svc_desc_enc_key.as_bytes(),
            &hex!("161090571E6DB517C0C8591CE524A56DF17BAE3FF8DCD50735F9AEB89634073E")
        );
        assert_eq!(middle.auth_clients.len(), 16);

        // Here we make sure that decryption "works" minimally and returns some
        // bytes for a descriptor with no HsClientDescEncSecretKey.
        //
        // We make sure that the actual decrypted value is reasonable elsewhere,
        // in the tests in inner.rs.
        //
        // We test the case where a HsClientDescEncSecretKey is needed
        // elsewhere, in `hsdesc::test::parse_desc_auth_good`.
        let _inner_body = middle
            .decrypt_inner(&desc.blinded_id(), desc.revision_counter(), &subcred, None)
            .unwrap();

        Ok(())
    }
}
