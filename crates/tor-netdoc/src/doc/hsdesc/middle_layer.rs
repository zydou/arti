//! Handle the middle layer of an onion service descriptor.

use digest::XofReader;
use once_cell::sync::Lazy;
use tor_hscrypto::pk::{BlindedOnionId, ClientDescAuthSecretKey};
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::util::ct::CtByteArray;

use crate::parse::tokenize::{Item, NetDocReader};
use crate::parse::{keyword::Keyword, parser::SectionRules};
use crate::types::misc::B64;
use crate::{Pos, Result};

use super::desc_enc::{DescEncryptionCookie, HsDescEncryption};
use super::DecryptionError;

/// A more-or-less verbatim representation of the middle layer of an onion
/// service descriptor.
#[derive(Debug, Clone)]
pub(super) struct HsDescMiddle {
    /// A public key used by authorized clients to decrypt the key used to
    /// decrypt the inner layer.  This is ignored if client authorization is not
    /// in use.
    ///
    /// This is `KP_hss_desc_enc`, and appears as `desc-auth-ephemeral-key` in the document format;
    /// It is used along with `KS_hsc_desc_enc` to perform a
    /// diffie-hellman operation and decrypt the inner layer.
    ephemeral_key: curve25519::PublicKey,
    /// One or more authorized clients, and the key exchange information that
    /// they use to compute shared keys for decrypting inner layer.
    ///
    /// Each of these is parsed from a `auth-client` line.
    auth_clients: Vec<AuthClient>,
    /// The (encrypted) inner document of the onion service descriptor.
    encrypted: Vec<u8>,
}

impl HsDescMiddle {
    /// Decrypt the encrypted inner document contained within this middle layer
    /// document.
    ///
    /// If present, `key` is an authorization key, and we assume that the
    /// decryption is nontrivial.
    ///
    /// A failure may mean either that the encryption was corrupted, or that we
    /// didn't have the right key.
    pub(super) fn decrypt_inner(
        &self,
        blinded_id: &BlindedOnionId,
        revision: RevisionCounter,
        subcredential: &Subcredential,
        key: Option<&ClientDescAuthSecretKey>,
    ) -> std::result::Result<Vec<u8>, DecryptionError> {
        let descriptor_cookie = key.and_then(|k| self.find_cookie(subcredential, k));
        let decrypt = HsDescEncryption {
            blinded_id,
            descriptor_cookie: descriptor_cookie.as_ref(),
            subcredential,
            revision,
            string_const: b"hsdir-encrypted-data",
        };

        decrypt.decrypt(&self.encrypted)
    }

    /// Use a `ClientDescAuthSecretKey` (`KS_hsc_desc_enc`) to see if there is any `auth-client`
    /// entry for us (a client who holds that secret key) in this descriptor.  
    /// If so, decrypt it and return its
    /// corresponding "Descriptor Cookie" (`N_hs_desc_enc`)
    ///
    /// If no such `N_hs_desc_enc` is found, then either we do not have
    /// permission to decrypt this layer, OR no encryption is required.
    ///
    /// (The protocol makes it intentionally impossible to distinguish any error
    /// conditions here other than "no cookie for you.")
    fn find_cookie(
        &self,
        subcredential: &Subcredential,
        ks_hsc_desc_enc: &ClientDescAuthSecretKey,
    ) -> Option<DescEncryptionCookie> {
        use cipher::{KeyIvInit, StreamCipher};
        use digest::{ExtendableOutput, Update};
        use tor_llcrypto::cipher::aes::Aes256Ctr as Cipher;
        use tor_llcrypto::d::Shake256 as KDF;

        // Perform a diffie hellman handshake using `KS_hsc_desc_enc` and `KP_hss_desc_enc`,
        // and use it to find our client_id and cookie_key.
        //
        // The spec says:
        //
        //     SECRET_SEED = x25519(hs_y, client_X)
        //                 = x25519(client_y, hs_X)
        //     KEYS = KDF(N_hs_subcred | SECRET_SEED, 40)
        //     CLIENT-ID = fist 8 bytes of KEYS
        //     COOKIE-KEY = last 32 bytes of KEYS
        //
        // Where:
        //     hs_{X,y} = K{P,S}_hss_desc_enc
        //     client_{X,Y} = K{P,S}_hsc_desc_enc
        let secret_seed = ks_hsc_desc_enc.as_ref().diffie_hellman(&self.ephemeral_key);
        let mut kdf = KDF::default();
        kdf.update(subcredential.as_ref());
        kdf.update(secret_seed.as_bytes());
        let mut keys = kdf.finalize_xof();
        let mut client_id = CtByteArray::from([0_u8; 8]);
        let mut cookie_key = [0_u8; 32];
        keys.read(client_id.as_mut());
        keys.read(&mut cookie_key);

        // See whether there is any matching client_id in self.auth_ids.
        // TODO HS: Perhaps we should use `tor_proto::util::ct::lookup`.  We would
        // have to put it in a lower level module.
        let auth_client = self
            .auth_clients
            .iter()
            .find(|c| c.client_id == client_id)?;

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
struct AuthClient {
    /// A check field that clients can use to see if this [`AuthClient`] entry corresponds to a key they hold.
    ///
    /// This is the first part of the `auth-client` line.
    client_id: CtByteArray<8>,
    /// An IV used to decrypt `encrypted_cookie`.
    ///
    /// This is the second item on the `auth-client` line.
    iv: [u8; 16],
    /// An encrypted value used to find the descriptor cookie, which in turn is
    /// needed to decrypt the [HsDescMiddle]'s `encrypted_body`.
    ///
    /// This is the third item on the `auth-client` line.  When decrypted, it
    /// reveals a `DescEncEncryptionCookie` (`N_hs_desc_enc`, not yet so named
    /// in the spec).
    encrypted_cookie: [u8; 16],
}

impl AuthClient {
    /// Try to extract an AuthClient from a single AuthClient item.
    fn from_item(item: &Item<'_, HsMiddleKwd>) -> Result<Self> {
        use crate::ParseErrorKind as EK;

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
    HsMiddleKwd {
        "desc-auth-type" => DESC_AUTH_TYPE,
        "desc-auth-ephemeral-key" => DESC_AUTH_EPHEMERAL_KEY,
        "auth-client" => AUTH_CLIENT,
        "encrypted" => ENCRYPTED,
    }
}

/// Rules about how keywords appear in the outer layer of an onion service
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
    /// Try to parse the middle layer of an onion service descriptor from a provided
    /// string.
    pub(super) fn parse(s: &str) -> Result<HsDescMiddle> {
        let mut reader = NetDocReader::new(s);
        let result = HsDescMiddle::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        Ok(result)
    }

    /// Extract an HsDescOuter from a reader.  
    ///
    /// The reader must contain a single HsDescOuter; we return an error if not.
    fn take_from_reader(reader: &mut NetDocReader<'_, HsMiddleKwd>) -> Result<HsDescMiddle> {
        use crate::ParseErrorKind as EK;
        use HsMiddleKwd::*;

        let mut iter = reader.iter();
        let body = HS_MIDDLE_RULES.parse(&mut iter)?;

        // Check for the only currently recognized `desc-auth-type`
        {
            let auth_type = body.required(DESC_AUTH_TYPE)?.required_arg(0)?;
            if auth_type != "x25519" {
                return Err(EK::BadDocumentVersion
                    .at_pos(Pos::at(auth_type))
                    .with_msg(format!("Unrecognized desc-auth-type {auth_type:?}")));
            }
        }

        // Extract `KP_hss_desc_enc` from DESC_AUTH_EPHEMERAL_KEY
        let ephemeral_key: curve25519::PublicKey = {
            let token = body.required(DESC_AUTH_EPHEMERAL_KEY)?;
            let bytes = token.parse_arg::<B64>(0)?.into_array()?;
            bytes.into()
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
            ephemeral_key,
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_checkable::{SelfSigned, Timebound};

    use super::*;
    use crate::doc::hsdesc::{
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

        // TODO hs: assert that the fields here are expected.

        // TODO hs: write a test for the case where we _do_ have an encryption key.
        let inner_body = middle
            .decrypt_inner(&desc.blinded_id(), desc.revision_counter(), &subcred, None)
            .unwrap();

        // dbg!(std::str::from_utf8(&inner_body).unwrap());

        Ok(())
    }
}
