//! Implements the HS ntor key exchange, as used in v3 onion services.
//!
//! The Ntor protocol of this section is specified in section
//! [NTOR-WITH-EXTRA-DATA] of rend-spec-v3.txt.
//!
//! The main difference between this HS Ntor handshake and the regular Ntor
//! handshake in ./ntor.rs is that this one allows each party to encrypt data
//! (without forward secrecy) after it sends the first message. This
//! opportunistic encryption property is used by clients in the onion service
//! protocol to encrypt introduction data in the INTRODUCE1 cell, and by
//! services to encrypt data in the RENDEZVOUS1 cell.
//!
//! # Status
//!
//! This module is available only when the `hs-common` feature is enabled.  The
//! specific handshakes are enabled by `hs-client` and `hs-service`.

// We want to use the exact variable names from the rend-spec-v3.txt proposal.
// This means that we allow variables to be named x (privkey) and X (pubkey).
// FIXME: this particular allow is rather hazardous since it can stop warnings
//        about match statements containing bindings rather than variant names.
#![allow(non_snake_case)]

use crate::crypto::handshake::KeyGenerator;
use crate::crypto::ll::kdf::{Kdf, ShakeKdf};
use crate::{Error, Result};
use tor_bytes::{Reader, SecretBuf, Writer};
use tor_hscrypto::{
    ops::{hs_mac, HS_MAC_LEN},
    pk::{HsIntroPtSessionIdKey, HsSvcNtorKey},
    Subcredential,
};
use tor_llcrypto::pk::{curve25519, ed25519};
use tor_llcrypto::util::ct::CtByteArray;

use cipher::{KeyIvInit, StreamCipher};

use tor_error::into_internal;
use tor_llcrypto::cipher::aes::Aes256Ctr;
use zeroize::{Zeroize as _, Zeroizing};

#[cfg(any(test, feature = "hs-service"))]
use tor_hscrypto::pk::HsSvcNtorKeypair;

/// The ENC_KEY from the HS Ntor protocol
//
// TODO (nickm): Any move operations applied to this key could subvert the zeroizing.
type EncKey = Zeroizing<[u8; 32]>;
/// The MAC_KEY from the HS Ntor protocol
type MacKey = [u8; 32];
/// A generic 256-bit MAC tag
type MacTag = CtByteArray<HS_MAC_LEN>;
/// The AUTH_INPUT_MAC from the HS Ntor protocol
type AuthInputMac = MacTag;

/// The key generator used by the HS ntor handshake.  Implements the simple key
/// expansion protocol specified in section "Key expansion" of rend-spec-v3.txt .
pub struct HsNtorHkdfKeyGenerator {
    /// Secret data derived from the handshake, used as input to HKDF
    seed: SecretBuf,
}

impl HsNtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub fn new(seed: SecretBuf) -> Self {
        HsNtorHkdfKeyGenerator { seed }
    }
}

impl KeyGenerator for HsNtorHkdfKeyGenerator {
    /// Expand the seed into a keystream of 'keylen' size
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        ShakeKdf::new().derive(&self.seed[..], keylen)
    }
}

/*********************** Client Side Code ************************************/

/// Information about an onion service that is needed for a client to perform an
/// hs_ntor handshake with it.
#[derive(Clone)]
#[cfg(any(test, feature = "hs-client"))]
pub struct HsNtorServiceInfo {
    /// Introduction point encryption key (aka `B`, aka `KP_hss_ntor`)
    /// (found in the HS descriptor)
    B: HsSvcNtorKey,

    /// Introduction point authentication key (aka `AUTH_KEY`, aka `KP_hs_ipt_sid`)
    /// (found in the HS descriptor)
    ///
    /// TODO: This is needed to begin _and end_ the handshake, which makes
    /// things a little trickier if someday we want to have several of these
    /// handshakes in operation at once, so that we can make
    /// multiple introduction attempts simultaneously
    /// using the same renedezvous point.
    /// That's not something that C Tor supports, though, so neither do we (yet).
    auth_key: HsIntroPtSessionIdKey,

    /// Service subcredential
    subcredential: Subcredential,
}

#[cfg(any(test, feature = "hs-client"))]
impl HsNtorServiceInfo {
    /// Create a new `HsNtorServiceInfo`
    pub fn new(
        B: HsSvcNtorKey,
        auth_key: HsIntroPtSessionIdKey,
        subcredential: Subcredential,
    ) -> Self {
        HsNtorServiceInfo {
            B,
            auth_key,
            subcredential,
        }
    }
}

/// Client state for an ntor handshake.
#[cfg(any(test, feature = "hs-client"))]
pub struct HsNtorClientState {
    /// Information about the service we are connecting to.
    service_info: HsNtorServiceInfo,

    /// The temporary curve25519 secret that we generated for this handshake.
    x: curve25519::StaticSecret,
    /// The corresponding private key
    X: curve25519::PublicKey,

    /// A shared secret constructed from our secret key `x` and the service's
    /// public ntor key `B`.  (The service has a separate public ntor key
    /// associated with each intro point.)
    Bx: curve25519::SharedSecret,

    /// Target length for the generated Introduce1 messages.
    intro1_target_len: usize,
}

/// Default target length for our generated Introduce1 messages.
///
/// This value is chosen to be the maximum size of a single-cell message
/// after proposal 340 is implemented.  (509 bytes for cell data, minus 16 bytes
/// for relay encryption overhead, minus 1 byte for relay command, minus 2 bytes
/// for relay message length.)
#[cfg(any(test, feature = "hs-client"))]
const INTRO1_TARGET_LEN: usize = 490;

#[cfg(any(test, feature = "hs-client"))]
impl HsNtorClientState {
    /// Construct a new `HsNtorClientState` for connecting to a given onion
    /// service described in `service_info`.
    ///
    /// Once constructed, this `HsNtorClientState` can be used to construct an
    /// INTRODUCE1 bodies that can be sent to an introduction point.
    pub fn new<R>(rng: &mut R, service_info: HsNtorServiceInfo) -> Self
    where
        R: rand::RngCore + rand::CryptoRng,
    {
        let x = curve25519::StaticSecret::random_from_rng(rng);
        Self::new_no_keygen(service_info, x)
    }

    /// Override the default target length for the resulting introduce1 message.
    #[cfg(test)]
    fn set_intro1_target_len(&mut self, len: usize) {
        self.intro1_target_len = len;
    }

    /// As `new()`, but do not use an RNG to generate our ephemeral secret key x.
    fn new_no_keygen(service_info: HsNtorServiceInfo, x: curve25519::StaticSecret) -> Self {
        let X = curve25519::PublicKey::from(&x);
        let Bx = x.diffie_hellman(&service_info.B);
        Self {
            service_info,
            x,
            X,
            Bx,
            intro1_target_len: INTRO1_TARGET_LEN,
        }
    }

    /// Return the data that should be written as the encrypted part of and
    /// the data that should be written as the encrypted part of the INTRODUCE1
    /// message. The data that is
    /// written is:
    ///
    /// ```text
    ///  CLIENT_PK                [PK_PUBKEY_LEN bytes]
    ///  ENCRYPTED_DATA           [Padded to length of plaintext]
    ///  MAC                      [MAC_LEN bytes]
    /// ```
    pub fn client_send_intro(&self, intro_header: &[u8], plaintext_body: &[u8]) -> Result<Vec<u8>> {
        /// The number of bytes added by this encryption.
        const ENC_OVERHEAD: usize = 32 + 32;

        let state = self;
        let service = &state.service_info;

        // Compute keys required to finish this part of the handshake
        let (enc_key, mac_key) = get_introduce_key_material(
            &state.Bx,
            &service.auth_key,
            &state.X,
            &service.B,
            &service.subcredential,
        )?;

        let padded_body_target_len = self
            .intro1_target_len
            .saturating_sub(intro_header.len() + ENC_OVERHEAD);
        let mut padded_body = plaintext_body.to_vec();
        if padded_body.len() < padded_body_target_len {
            padded_body.resize(padded_body_target_len, 0);
        }
        debug_assert!(padded_body.len() >= padded_body_target_len);

        let (ciphertext, mac_tag) =
            encrypt_and_mac(&padded_body, intro_header, &state.X, &enc_key, mac_key);
        padded_body.zeroize();

        // Create the relevant parts of INTRO1
        let mut response: Vec<u8> = Vec::new();
        response
            .write(&state.X)
            .and_then(|_| response.write(&ciphertext))
            .and_then(|_| response.write(&mac_tag))
            .map_err(into_internal!("Can't encode hs-ntor client handshake."))?;

        Ok(response)
    }

    /// The introduction has been completed and the service has replied with a
    /// RENDEZVOUS1 message, whose body is in `msg`.
    ///
    /// Handle it by computing and verifying the MAC, and if it's legit return a
    /// key generator based on the result of the key exchange.
    pub fn client_receive_rend(&self, msg: &[u8]) -> Result<HsNtorHkdfKeyGenerator> {
        let state = self;

        // Extract the public key of the service from the message
        let mut cur = Reader::from_slice(msg);
        let Y: curve25519::PublicKey = cur
            .extract()
            .map_err(|e| Error::from_bytes_err(e, "hs_ntor handshake"))?;
        let mac_tag: MacTag = cur
            .extract()
            .map_err(|e| Error::from_bytes_err(e, "hs_ntor handshake"))?;

        // Get EXP(Y,x) and EXP(B,x)
        let xy = state.x.diffie_hellman(&Y);
        let xb = state.x.diffie_hellman(&state.service_info.B);

        let (keygen, my_mac_tag) = get_rendezvous_key_material(
            &xy,
            &xb,
            &state.service_info.auth_key,
            &state.service_info.B,
            &state.X,
            &Y,
        )?;

        // Validate the MAC!
        if my_mac_tag != mac_tag {
            return Err(Error::BadCircHandshakeAuth);
        }

        Ok(keygen)
    }
}

/// Encrypt the 'plaintext' using 'enc_key'. Then compute the intro cell MAC
/// using 'mac_key' over the text `(other_text, public_key, plaintext)`
/// and return (ciphertext, mac_tag).
#[cfg(any(test, feature = "hs-client"))]
fn encrypt_and_mac(
    plaintext: &[u8],
    other_data: &[u8],
    public_key: &curve25519::PublicKey,
    enc_key: &EncKey,
    mac_key: MacKey,
) -> (Vec<u8>, MacTag) {
    let mut ciphertext = plaintext.to_vec();
    // Encrypt the introduction data using 'enc_key'
    let zero_iv = Default::default();
    let mut cipher = Aes256Ctr::new(enc_key.as_ref().into(), &zero_iv);
    cipher.apply_keystream(&mut ciphertext);

    // Now staple the other INTRODUCE1 data right before the ciphertext to
    // create the body of the MAC tag
    let mut mac_body: Vec<u8> = Vec::new();
    mac_body.extend(other_data);
    mac_body.extend(public_key.as_bytes());
    mac_body.extend(&ciphertext);
    let mac_tag = hs_mac(&mac_key, &mac_body);

    (ciphertext, mac_tag)
}

/*********************** Server Side Code ************************************/

/// Conduct the HS Ntor handshake as the service.
///
/// Return a key generator which is the result of the key exchange, the
/// RENDEZVOUS1 response to send to the client, and the introduction plaintext that we decrypted.
///
/// The response to the client is:
/// ```text
///    SERVER_PK   Y                         [PK_PUBKEY_LEN bytes]
///    AUTH        AUTH_INPUT_MAC            [MAC_LEN bytes]
/// ```
#[cfg(any(test, feature = "hs-service"))]
pub fn server_receive_intro<R>(
    rng: &mut R,
    k_hss_ntor: &HsSvcNtorKeypair,
    auth_key: &HsIntroPtSessionIdKey,
    subcredential: &[Subcredential],
    intro_header: &[u8],
    msg: &[u8],
) -> Result<(HsNtorHkdfKeyGenerator, Vec<u8>, Vec<u8>)>
where
    R: rand::RngCore + rand::CryptoRng,
{
    let y = curve25519::StaticSecret::random_from_rng(rng);
    server_receive_intro_no_keygen(&y, k_hss_ntor, auth_key, subcredential, intro_header, msg)
}

/// Helper: Like server_receive_intro, but take an ephemeral key rather than a RNG.
#[cfg(any(test, feature = "hs-service"))]
fn server_receive_intro_no_keygen(
    // This should be an EphemeralSecret, but using a StaticSecret is necessary
    // so that we can make one from raw bytes in our test.
    y: &curve25519::StaticSecret,
    k_hss_ntor: &HsSvcNtorKeypair,
    auth_key: &HsIntroPtSessionIdKey,
    subcredential: &[Subcredential],
    intro_header: &[u8],
    msg: &[u8],
) -> Result<(HsNtorHkdfKeyGenerator, Vec<u8>, Vec<u8>)> {
    // Extract all the useful pieces from the message
    let mut cur = Reader::from_slice(msg);
    let X: curve25519::PublicKey = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "hs ntor handshake"))?;
    let remaining_bytes = cur.remaining();
    let ciphertext = &mut cur
        .take(remaining_bytes - HS_MAC_LEN)
        .map_err(|e| Error::from_bytes_err(e, "hs ntor handshake"))?
        .to_vec();
    let mac_tag: MacTag = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "hs ntor handshake"))?;

    // Now derive keys needed for handling the INTRO1 cell
    let bx = k_hss_ntor.secret().as_ref().diffie_hellman(&X);

    // We have to do this for every possible subcredential to find out which
    // one, if any, gives a valid encryption key.  We don't break on our first
    // success, to avoid a timing sidechannel.
    //
    // TODO SPEC: Document this behavior and explain why it's necessary and okay.
    let mut found_dec_key = None;

    for subcredential in subcredential {
        let (dec_key, mac_key) =
            get_introduce_key_material(&bx, auth_key, &X, k_hss_ntor.public(), subcredential)?; // This can only fail with a Bug, so it's okay to bail early.

        // Now validate the MAC: Staple the previous parts of the INTRODUCE2
        // message, along with the ciphertext, to create the body of the MAC tag.
        let mut mac_body: Vec<u8> = Vec::new();
        mac_body.extend(intro_header);
        mac_body.extend(X.as_bytes());
        mac_body.extend(&ciphertext[..]);
        let my_mac_tag = hs_mac(&mac_key, &mac_body);

        if my_mac_tag == mac_tag {
            // TODO: We could use CtOption here.
            found_dec_key = Some(dec_key);
        }
    }

    let Some(dec_key) = found_dec_key else {
        return Err(Error::BadCircHandshakeAuth);
    };

    // Decrypt the ENCRYPTED_DATA from the intro cell
    let zero_iv = Default::default();
    let mut cipher = Aes256Ctr::new(dec_key.as_ref().into(), &zero_iv);
    cipher.apply_keystream(ciphertext);
    let plaintext = ciphertext; // it's now decrypted

    // Generate ephemeral keys for this handshake
    let Y = curve25519::PublicKey::from(y);

    // Compute EXP(X,y) and EXP(X,b)
    let xy = y.diffie_hellman(&X);
    let xb = k_hss_ntor.secret().as_ref().diffie_hellman(&X);

    let (keygen, auth_input_mac) =
        get_rendezvous_key_material(&xy, &xb, auth_key, k_hss_ntor.public(), &X, &Y)?;

    // Set up RENDEZVOUS1 reply to the client
    let mut reply: Vec<u8> = Vec::new();
    reply
        .write(&Y)
        .and_then(|_| reply.write(&auth_input_mac))
        .map_err(into_internal!("Can't encode hs-ntor server handshake."))?;

    Ok((keygen, reply, plaintext.clone()))
}

/*********************** Helper functions ************************************/

/// Helper function: Compute the part of the HS ntor handshake that generates
/// key material for creating and handling INTRODUCE1 cells. Function used
/// by both client and service. Specifically, calculate the following:
///
/// ```pseudocode
///  intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
///  info = m_hsexpand | subcredential
///  hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
///  ENC_KEY = hs_keys[0:S_KEY_LEN]
///  MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]
/// ```
///
/// Return (ENC_KEY, MAC_KEY).
fn get_introduce_key_material(
    bx: &curve25519::SharedSecret,
    auth_key: &ed25519::PublicKey,
    X: &curve25519::PublicKey,
    B: &curve25519::PublicKey,
    subcredential: &Subcredential,
) -> std::result::Result<(EncKey, MacKey), tor_error::Bug> {
    let hs_ntor_protoid_constant = &b"tor-hs-ntor-curve25519-sha3-256-1"[..];
    let hs_ntor_key_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"[..];
    let hs_ntor_expand_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"[..];

    // Construct hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
    // Start by getting 'intro_secret_hs_input'
    let mut secret_input = SecretBuf::new();
    secret_input
        .write(bx) // EXP(B,x)
        .and_then(|_| secret_input.write(auth_key)) // AUTH_KEY
        .and_then(|_| secret_input.write(X)) // X
        .and_then(|_| secret_input.write(B)) // B
        .and_then(|_| secret_input.write(hs_ntor_protoid_constant)) // PROTOID
        // Now fold in the t_hsenc
        .and_then(|_| secret_input.write(hs_ntor_key_constant))
        // and fold in the 'info'
        .and_then(|_| secret_input.write(hs_ntor_expand_constant))
        .and_then(|_| secret_input.write(subcredential))
        .map_err(into_internal!("Can't generate hs-ntor kdf input."))?;

    let hs_keys = ShakeKdf::new()
        .derive(&secret_input[..], 32 + 32)
        .map_err(into_internal!("Can't compute SHAKE"))?;
    // Extract the keys into arrays
    let enc_key = Zeroizing::new(
        hs_keys[0..32]
            .try_into()
            .map_err(into_internal!("converting enc_key"))?,
    );
    let mac_key = hs_keys[32..64]
        .try_into()
        .map_err(into_internal!("converting mac_key"))?;

    Ok((enc_key, mac_key))
}

/// Helper function: Compute the last part of the HS ntor handshake which
/// derives key material necessary to create and handle RENDEZVOUS1
/// cells. Function used by both client and service. The actual calculations is
/// as follows:
///
///  rend_secret_hs_input = EXP(X,y) | EXP(X,b) | AUTH_KEY | B | X | Y | PROTOID
///  NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
///  verify = MAC(rend_secret_hs_input, t_hsverify)
///  auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
///  AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
///
/// Return (keygen, AUTH_INPUT_MAC), where keygen is a key generator based on
/// NTOR_KEY_SEED.
fn get_rendezvous_key_material(
    xy: &curve25519::SharedSecret,
    xb: &curve25519::SharedSecret,
    auth_key: &ed25519::PublicKey,
    B: &curve25519::PublicKey,
    X: &curve25519::PublicKey,
    Y: &curve25519::PublicKey,
) -> Result<(HsNtorHkdfKeyGenerator, AuthInputMac)> {
    let hs_ntor_protoid_constant = &b"tor-hs-ntor-curve25519-sha3-256-1"[..];
    let hs_ntor_mac_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac"[..];
    let hs_ntor_verify_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify"[..];
    let server_string_constant = &b"Server"[..];
    let hs_ntor_expand_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"[..];
    let hs_ntor_key_constant = &b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"[..];

    // Start with rend_secret_hs_input
    let mut secret_input = SecretBuf::new();
    secret_input
        .write(xy) // EXP(X,y)
        .and_then(|_| secret_input.write(xb)) // EXP(X,b)
        .and_then(|_| secret_input.write(auth_key)) // AUTH_KEY
        .and_then(|_| secret_input.write(B)) // B
        .and_then(|_| secret_input.write(X)) // X
        .and_then(|_| secret_input.write(Y)) // Y
        .and_then(|_| secret_input.write(hs_ntor_protoid_constant)) // PROTOID
        .map_err(into_internal!(
            "Can't encode input to hs-ntor key derivation."
        ))?;

    // Build NTOR_KEY_SEED and verify
    let ntor_key_seed = hs_mac(&secret_input, hs_ntor_key_constant);
    let verify = hs_mac(&secret_input, hs_ntor_verify_constant);

    // Start building 'auth_input'
    let mut auth_input = Vec::new();
    auth_input
        .write(&verify)
        .and_then(|_| auth_input.write(auth_key)) // AUTH_KEY
        .and_then(|_| auth_input.write(B)) // B
        .and_then(|_| auth_input.write(Y)) // Y
        .and_then(|_| auth_input.write(X)) // X
        .and_then(|_| auth_input.write(hs_ntor_protoid_constant)) // PROTOID
        .and_then(|_| auth_input.write(server_string_constant)) // "Server"
        .map_err(into_internal!("Can't encode auth-input for hs-ntor."))?;

    // Get AUTH_INPUT_MAC
    let auth_input_mac = hs_mac(&auth_input, hs_ntor_mac_constant);

    // Now finish up with the KDF construction
    let mut kdf_seed = SecretBuf::new();
    kdf_seed
        .write(&ntor_key_seed)
        .and_then(|_| kdf_seed.write(hs_ntor_expand_constant))
        .map_err(into_internal!("Can't encode kdf-input for hs-ntor."))?;
    let keygen = HsNtorHkdfKeyGenerator::new(kdf_seed);

    Ok((keygen, auth_input_mac))
}

/*********************** Unit Tests ******************************************/

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
    use hex_literal::hex;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    /// Basic HS Ntor test that does the handshake between client and service
    /// and makes sure that the resulting keys and KDF is legit.
    fn hs_ntor() -> Result<()> {
        let mut rng = testing_rng();

        // Let's initialize keys for the client (and the intro point)
        let intro_b_privkey = curve25519::StaticSecret::random_from_rng(&mut rng);
        let intro_b_pubkey = curve25519::PublicKey::from(&intro_b_privkey);
        let intro_auth_key_privkey = ed25519::Keypair::generate(&mut rng);
        let intro_auth_key_pubkey = ed25519::PublicKey::from(&intro_auth_key_privkey);
        drop(intro_auth_key_privkey); // not actually used in this part of the protocol.

        // Create keys for client and service
        let client_keys = HsNtorServiceInfo::new(
            intro_b_pubkey.into(),
            intro_auth_key_pubkey.into(),
            [5; 32].into(),
        );

        let k_hss_ntor = HsSvcNtorKeypair::from_secret_key(intro_b_privkey.into());
        let auth_key = intro_auth_key_pubkey.into();
        let subcredentials = vec![[5; 32].into()];

        // Client: Sends an encrypted INTRODUCE1 cell
        let state = HsNtorClientState::new(&mut rng, client_keys);
        let cmsg = state.client_send_intro(&[66; 10], &[42; 60])?;
        assert_eq!(cmsg.len() + 10, INTRO1_TARGET_LEN);

        // Service: Decrypt INTRODUCE1 cell, and reply with RENDEZVOUS1 cell
        let (skeygen, smsg, s_plaintext) = server_receive_intro(
            &mut rng,
            &k_hss_ntor,
            &auth_key,
            &subcredentials[..],
            &[66; 10],
            &cmsg,
        )?;

        // Check that the plaintext received by the service is the one that the
        // client sent
        assert_eq!(s_plaintext[0..60], vec![42; 60]);

        // Client: Receive RENDEZVOUS1 and create key material
        let ckeygen = state.client_receive_rend(&smsg)?;

        // Test that RENDEZVOUS1 key material match
        let skeys = skeygen.expand(128)?;
        let ckeys = ckeygen.expand(128)?;
        assert_eq!(skeys, ckeys);

        Ok(())
    }

    #[test]
    /// Test vectors generated with hs_ntor_ref.py from little-t-tor.
    fn ntor_mac() {
        let result = hs_mac("who".as_bytes(), b"knows?");
        assert_eq!(
            &result,
            &hex!("5e7da329630fdaa3eab7498bb1dc625bbb9ca968f10392b6af92d51d5db17473").into()
        );

        let result = hs_mac("gone".as_bytes(), b"by");
        assert_eq!(
            &result,
            &hex!("90071aabb06d3f7c777db41542f4790c7dd9e2e7b2b842f54c9c42bbdb37e9a0").into()
        );
    }

    /// A set of test vectors generated with C tor and chutney.
    #[test]
    fn testvec() {
        let kp_hs_ipt_sid =
            hex!("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
        let subcredential =
            hex!("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57");
        let kp_hss_ntor = hex!("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979");
        let ks_hss_ntor = hex!("A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A");
        let key_x = hex!("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341");
        let key_y = hex!("68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55");

        // Information about the service.
        let kp_hs_ipt_sid: HsIntroPtSessionIdKey = ed25519::PublicKey::from_bytes(&kp_hs_ipt_sid)
            .unwrap()
            .into();
        let subcredential: Subcredential = subcredential.into();
        let kp_hss_ntor: HsSvcNtorKey = curve25519::PublicKey::from(kp_hss_ntor).into();

        let service_info = HsNtorServiceInfo {
            B: kp_hss_ntor,
            auth_key: kp_hs_ipt_sid.clone(),
            subcredential: subcredential.clone(),
        };

        // The client has to generate an ephemeral keypair.
        let key_x: curve25519::StaticSecret = curve25519::StaticSecret::from(key_x);

        // Information about the message to be sent to the service in the
        // INTRODUCE1 cell.
        let intro_header = hex!(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF
            21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00"
        );
        let intro_body = hex!(
            "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA
             C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000
             0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B
             7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000
             0000000000000000000000000000000000000000000000000000000000000000
             000000000000000000000000000000000000000000000000000000000000"
        );
        // Now try to do the handshake...
        let mut client_state = HsNtorClientState::new_no_keygen(service_info, key_x);
        // (Do not pad, since C tor's padding algorithm didn't match ours when
        // these test vectors were generated.)
        client_state.set_intro1_target_len(0);
        let encrypted_body = client_state
            .client_send_intro(&intro_header, &intro_body)
            .unwrap();

        let mut cell_out = intro_header.to_vec();
        cell_out.extend(&encrypted_body);
        let expected = &hex!(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF
             21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED
             726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E37830
             4DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530
             563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E8
             3F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C
             7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E
             35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25D
             DEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2
             D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8"
        );
        assert_eq!(&cell_out, &expected);

        // ===
        // Okay, we have the message to send to the onion service.
        // ===

        // This corresponds to the public key above...
        let ks_hss_ntor = curve25519::StaticSecret::from(ks_hss_ntor).into();
        let k_hss_ntor = HsSvcNtorKeypair::from_secret_key(ks_hss_ntor);
        let key_y = curve25519::StaticSecret::from(key_y);
        let subcredentials = vec![subcredential];

        let (service_keygen, service_reply, service_plaintext) = server_receive_intro_no_keygen(
            &key_y,
            &k_hss_ntor,
            &kp_hs_ipt_sid,
            &subcredentials[..],
            &intro_header,
            &encrypted_body,
        )
        .unwrap();

        // Did we recover the plaintext correctly?
        assert_eq!(&service_plaintext, &intro_body);

        let expected_reply = hex!(
            "8fbe0db4d4a9c7ff46701e3e0ee7fd05cd28be4f302460addeec9e93354ee700
             4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208"
        );
        assert_eq!(&service_reply, &expected_reply);

        // Let's see if the client handles this reply!
        let client_keygen = client_state.client_receive_rend(&service_reply).unwrap();
        let bytes_client = client_keygen.expand(128).unwrap();
        let bytes_service = service_keygen.expand(128).unwrap();
        let mut key_seed =
            hex!("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB").to_vec();
        key_seed.extend(b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand");
        let bytes_expected = HsNtorHkdfKeyGenerator::new(key_seed.into())
            .expand(128)
            .unwrap();
        assert_eq!(&bytes_client, &bytes_service);
        assert_eq!(&bytes_client, &bytes_expected);
    }
}
