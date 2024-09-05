//! Implements the ntor v3 key exchange, as described in proposal 332.
//!
//! The main difference between the ntor v3r handshake and the
//! original ntor handshake is that this this one allows each party to
//! encrypt data (without forward secrecy) after it sends the first
//! message.

// TODO:
//    Remove the "allow" item for dead_code.
//    Make terminology and variable names consistent with spec.

// This module is still unused: so allow some dead code for now.
#![allow(dead_code)]

use std::borrow::Borrow;

use super::{RelayHandshakeError, RelayHandshakeResult};
use crate::util::ct;
use crate::{Error, Result};
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writeable, Writer};
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256, Shake256Reader};
use tor_llcrypto::pk::{curve25519, ed25519::Ed25519Identity};
use tor_llcrypto::util::ct::ct_lookup;

use cipher::{KeyIvInit, StreamCipher};

use crate::crypto::handshake::KeyGenerator;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_llcrypto::cipher::aes::Aes256Ctr;
use zeroize::Zeroizing;

/// The verification string to be used for circuit extension.
const NTOR3_CIRC_VERIFICATION: &[u8] = b"circuit extend";

/// The size of an encryption key in bytes.
const ENC_KEY_LEN: usize = 32;
/// The size of a MAC key in bytes.
const MAC_KEY_LEN: usize = 32;
/// The size of a curve25519 public key in bytes.
const PUB_KEY_LEN: usize = 32;
/// The size of a digest output in bytes.
const DIGEST_LEN: usize = 32;
/// The length of a MAC output in bytes.
const MAC_LEN: usize = 32;
/// The length of a node identity in bytes.
const ID_LEN: usize = 32;

/// The output of the digest, as an array.
type DigestVal = [u8; DIGEST_LEN];
/// The output of the MAC.
type MacVal = [u8; MAC_LEN];
/// A key for symmetric encryption or decryption.
//
// TODO (nickm): Any move operations applied to this key could subvert the zeroizing.
type EncKey = Zeroizing<[u8; ENC_KEY_LEN]>;
/// A key for message authentication codes.
type MacKey = [u8; MAC_KEY_LEN];

/// Opaque wrapper type for NtorV3's hash reader.
struct NtorV3XofReader(Shake256Reader);

impl digest::XofReader for NtorV3XofReader {
    fn read(&mut self, buffer: &mut [u8]) {
        self.0.read(buffer);
    }
}

/// An encapsulated value for passing as input to a MAC, digest, or
/// KDF algorithm.
///
/// This corresponds to the ENCAP() function in proposal 332.
struct Encap<'a>(&'a [u8]);

impl<'a> Writeable for Encap<'a> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_u64(self.0.len() as u64);
        b.write(self.0)
    }
}

impl<'a> Encap<'a> {
    /// Return the length of the underlying data in bytes.
    fn len(&self) -> usize {
        self.0.len()
    }
    /// Return the underlying data
    fn data(&self) -> &'a [u8] {
        self.0
    }
}

/// Helper to define a set of tweak values as instances of `Encap`.
macro_rules! define_tweaks {
    {
        $(#[$pid_meta:meta])*
        PROTOID = $protoid:expr;
        $( $(#[$meta:meta])* $name:ident <= $suffix:expr ; )*
    } => {
        $(#[$pid_meta])*
        const PROTOID: &'static [u8] = $protoid.as_bytes();
        $(
            $(#[$meta])*
            const $name : Encap<'static> =
                Encap(concat!($protoid, ":", $suffix).as_bytes());
        )*
    }
}

define_tweaks! {
    /// Protocol ID: concatenated with other things in the protocol to
    /// prevent hash confusion.
    PROTOID =  "ntor3-curve25519-sha3_256-1";

    /// Message MAC tweak: used to compute the MAC of an encrypted client
    /// message.
    T_MSGMAC <= "msg_mac";
    /// Message KDF tweak: used when deriving keys for encrypting and MACing
    /// client message.
    T_MSGKDF <= "kdf_phase1";
    /// Key seeding tweak: used to derive final KDF input from secret_input.
    T_KEY_SEED <= "key_seed";
    /// Verifying tweak: used to derive 'verify' value from secret_input.
    T_VERIFY <= "verify";
    /// Final KDF tweak: used to derive keys for encrypting relay message
    /// and for the actual tor circuit.
    T_FINAL <= "kdf_final";
    /// Authentication tweak: used to derive the final authentication
    /// value for the handshake.
    T_AUTH <= "auth_final";
}

/// Compute a tweaked hash.
fn hash(t: &Encap<'_>, data: &[u8]) -> DigestVal {
    use digest::Digest;
    let mut d = Sha3_256::new();
    d.update((t.len() as u64).to_be_bytes());
    d.update(t.data());
    d.update(data);
    d.finalize().into()
}

/// Perform a symmetric encryption operation and return the encrypted data.
///
/// (This isn't safe to do more than once with the same key, but we never
/// do that in this protocol.)
fn encrypt(key: &EncKey, m: &[u8]) -> Vec<u8> {
    let mut d = m.to_vec();
    let zero_iv = Default::default();
    let mut cipher = Aes256Ctr::new(key.as_ref().into(), &zero_iv);
    cipher.apply_keystream(&mut d);
    d
}
/// Perform a symmetric decryption operation and return the encrypted data.
fn decrypt(key: &EncKey, m: &[u8]) -> Vec<u8> {
    encrypt(key, m)
}

/// Wrapper around a Digest or ExtendedOutput object that lets us use it
/// as a tor_bytes::Writer.
struct DigestWriter<U>(U);
impl<U: digest::Update> tor_bytes::Writer for DigestWriter<U> {
    fn write_all(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
impl<U> DigestWriter<U> {
    /// Consume this wrapper and return the underlying object.
    fn take(self) -> U {
        self.0
    }
}

/// Hash tweaked with T_KEY_SEED
fn h_key_seed(d: &[u8]) -> DigestVal {
    hash(&T_KEY_SEED, d)
}
/// Hash tweaked with T_VERIFY
fn h_verify(d: &[u8]) -> DigestVal {
    hash(&T_VERIFY, d)
}

/// Helper: compute the encryption key and mac_key for the client's
/// encrypted message.
///
/// Takes as inputs `xb` (the shared secret derived from
/// diffie-hellman as Bx or Xb), the relay's public key information,
/// the client's public key (B), and the shared verification string.
fn kdf_msgkdf(
    xb: &curve25519::SharedSecret,
    relay_public: &NtorV3PublicKey,
    client_public: &curve25519::PublicKey,
    verification: &[u8],
) -> EncodeResult<(EncKey, DigestWriter<Sha3_256>)> {
    // secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
    // phase1_keys = KDF_msgkdf(secret_input_phase1)
    // (ENC_K1, MAC_K1) = PARTITION(phase1_keys, ENC_KEY_LEN, MAC_KEY_LEN
    use digest::{ExtendableOutput, XofReader};
    let mut msg_kdf = DigestWriter(Shake256::default());
    msg_kdf.write(&T_MSGKDF)?;
    msg_kdf.write(xb)?;
    msg_kdf.write(&relay_public.id)?;
    msg_kdf.write(client_public)?;
    msg_kdf.write(&relay_public.pk)?;
    msg_kdf.write(PROTOID)?;
    msg_kdf.write(&Encap(verification))?;
    let mut r = msg_kdf.take().finalize_xof();
    let mut enc_key = Zeroizing::new([0; ENC_KEY_LEN]);
    let mut mac_key = Zeroizing::new([0; MAC_KEY_LEN]);

    r.read(&mut enc_key[..]);
    r.read(&mut mac_key[..]);
    let mut mac = DigestWriter(Sha3_256::default());
    {
        mac.write(&T_MSGMAC)?;
        mac.write(&Encap(&mac_key[..]))?;
        mac.write(&relay_public.id)?;
        mac.write(&relay_public.pk)?;
        mac.write(client_public)?;
    }

    Ok((enc_key, mac))
}

/// Client side of the ntor v3 handshake.
pub(crate) struct NtorV3Client;

impl super::ClientHandshake for NtorV3Client {
    type KeyType = NtorV3PublicKey;
    type StateType = NtorV3HandshakeState;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    /// Generate a new client onionskin for a relay with a given onion key.
    /// If any `extensions` are provided, encode them into to the onionskin.
    ///
    /// On success, return a state object that will be used to complete the handshake, along
    /// with the message to send.
    fn client1<R: RngCore + CryptoRng, M: Borrow<[NtorV3Extension]>>(
        rng: &mut R,
        key: &NtorV3PublicKey,
        extensions: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let mut message = Vec::new();
        NtorV3Extension::write_many_onto(extensions.borrow(), &mut message)
            .map_err(|e| Error::from_bytes_enc(e, "ntor3 handshake extensions"))?;
        Ok(
            client_handshake_ntor_v3(rng, key, &message, NTOR3_CIRC_VERIFICATION)
                .map_err(into_internal!("Can't encode ntor3 client handshake."))?,
        )
    }

    /// Handle an onionskin from a relay, and produce a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(
        state: Self::StateType,
        msg: T,
    ) -> Result<(Vec<NtorV3Extension>, Self::KeyGen)> {
        let (message, xofreader) =
            client_handshake_ntor_v3_part2(&state, msg.as_ref(), NTOR3_CIRC_VERIFICATION)?;
        let extensions = NtorV3Extension::decode(&message).map_err(|err| Error::CellDecodeErr {
            object: "ntor v3 extensions",
            err,
        })?;
        let keygen = NtorV3KeyGenerator { reader: xofreader };

        Ok((extensions, keygen))
    }
}

/// Server side of the ntor v3 handshake.
pub(crate) struct NtorV3Server;

impl super::ServerHandshake for NtorV3Server {
    type KeyType = NtorV3SecretKey;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<R: RngCore + CryptoRng, REPLY: super::AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let mut bytes_reply_fn = |bytes: &[u8]| -> Option<Vec<u8>> {
            let client_exts = NtorV3Extension::decode(bytes).ok()?;
            let reply_exts = reply_fn.reply(&client_exts)?;
            let mut out = vec![];
            NtorV3Extension::write_many_onto(&reply_exts, &mut out).ok()?;
            Some(out)
        };

        let (res, reader) = server_handshake_ntor_v3(
            rng,
            &mut bytes_reply_fn,
            msg.as_ref(),
            key,
            NTOR3_CIRC_VERIFICATION,
        )?;
        Ok((NtorV3KeyGenerator { reader }, res))
    }
}

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug)]
pub(crate) struct NtorV3PublicKey {
    /// The relay's identity.
    pub(crate) id: Ed25519Identity,
    /// The relay's onion key.
    pub(crate) pk: curve25519::PublicKey,
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub(crate) struct NtorV3SecretKey {
    /// The relay's public key information
    pk: NtorV3PublicKey,
    /// The secret onion key.
    sk: curve25519::StaticSecret,
}

impl NtorV3SecretKey {
    /// Construct a new NtorV3SecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(
        sk: curve25519::StaticSecret,
        pk: curve25519::PublicKey,
        id: Ed25519Identity,
    ) -> Self {
        Self {
            pk: NtorV3PublicKey { id, pk },
            sk,
        }
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0_u8; 32];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let sk = curve25519::StaticSecret::random_from_rng(rng);

        let pk = NtorV3PublicKey {
            pk: (&sk).into(),
            id: id.into(),
        };
        Self { pk, sk }
    }

    /// Checks whether `id` and `pk` match this secret key.
    ///
    /// Used to perform a constant-time secret key lookup.
    fn matches(&self, id: Ed25519Identity, pk: curve25519::PublicKey) -> Choice {
        // TODO: use similar pattern in ntor_v1!
        id.as_bytes().ct_eq(self.pk.id.as_bytes()) & pk.as_bytes().ct_eq(self.pk.pk.as_bytes())
    }
}

/// Client state for the ntor v3 handshake.
///
/// The client needs to hold this state between when it sends its part
/// of the handshake and when it receives the relay's reply.
pub(crate) struct NtorV3HandshakeState {
    /// The public key of the relay we're communicating with.
    relay_public: NtorV3PublicKey, // B, ID.
    /// Our ephemeral secret key for this handshake.
    my_sk: curve25519::StaticSecret, // x
    /// Our ephemeral public key for this handshake.
    my_public: curve25519::PublicKey, // X

    /// The shared secret generated as Bx or Xb.
    shared_secret: curve25519::SharedSecret, // Bx
    /// The MAC of our original encrypted message.
    msg_mac: MacVal, // msg_mac
}

/// A key generator returned from an ntor v3 handshake.
pub(crate) struct NtorV3KeyGenerator {
    /// The underlying `digest::XofReader`.
    reader: NtorV3XofReader,
}

impl KeyGenerator for NtorV3KeyGenerator {
    fn expand(mut self, keylen: usize) -> Result<SecretBuf> {
        use digest::XofReader;
        let mut ret: SecretBuf = vec![0; keylen].into();
        self.reader.read(ret.as_mut());
        Ok(ret)
    }
}

/// Client-side Ntor version 3 handshake, part one.
///
/// Given a secure `rng`, a relay's public key, a secret message to send,
/// and a shared verification string, generate a new handshake state
/// and a message to send to the relay.
fn client_handshake_ntor_v3<R: RngCore + CryptoRng>(
    rng: &mut R,
    relay_public: &NtorV3PublicKey,
    client_msg: &[u8],
    verification: &[u8],
) -> EncodeResult<(NtorV3HandshakeState, Vec<u8>)> {
    let my_sk = curve25519::StaticSecret::random_from_rng(rng);
    client_handshake_ntor_v3_no_keygen(relay_public, client_msg, verification, my_sk)
}

/// As `client_handshake_ntor_v3`, but don't generate an ephemeral DH
/// key: instead take that key an arguments `my_sk`.
fn client_handshake_ntor_v3_no_keygen(
    relay_public: &NtorV3PublicKey,
    client_msg: &[u8],
    verification: &[u8],
    my_sk: curve25519::StaticSecret,
) -> EncodeResult<(NtorV3HandshakeState, Vec<u8>)> {
    let my_public = curve25519::PublicKey::from(&my_sk);
    let bx = my_sk.diffie_hellman(&relay_public.pk);

    let (enc_key, mut mac) = kdf_msgkdf(&bx, relay_public, &my_public, verification)?;

    //encrypted_msg = ENC(ENC_K1, CM)
    // msg_mac = MAC_msgmac(MAC_K1, ID | B | X | encrypted_msg)
    let encrypted_msg = encrypt(&enc_key, client_msg);
    let msg_mac: DigestVal = {
        use digest::Digest;
        mac.write(&encrypted_msg)?;
        mac.take().finalize().into()
    };

    let mut message = Vec::new();
    message.write(&relay_public.id)?;
    message.write(&relay_public.pk)?;
    message.write(&my_public)?;
    message.write(&encrypted_msg)?;
    message.write(&msg_mac)?;

    let state = NtorV3HandshakeState {
        relay_public: relay_public.clone(),
        my_sk,
        my_public,
        shared_secret: bx,
        msg_mac,
    };

    Ok((state, message))
}

/// Trait for an object that handle and incoming client message and
/// return a server's reply.
///
/// This is implemented for `FnMut(&[u8]) -> Option<Vec<u8>>` automatically.
pub(crate) trait MsgReply {
    /// Given a message received from a client, parse it and decide
    /// how (and whether) to reply.
    ///
    /// Return None if the handshake should fail.
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>>;
}

impl<F> MsgReply for F
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        self(msg)
    }
}

/// Complete an ntor v3 handshake as a server.
///
/// Use the provided `rng` to generate keys; use the provided
/// `reply_fn` to handle incoming client secret message and decide how
/// to reply.  The client's handshake is in `message`.  Our private
/// key(s) are in `keys`.  The `verification` string must match the
/// string provided by the client.
///
/// On success, return the server handshake message to send, and an XofReader
/// to use in generating circuit keys.
fn server_handshake_ntor_v3<RNG: CryptoRng + RngCore, REPLY: MsgReply>(
    rng: &mut RNG,
    reply_fn: &mut REPLY,
    message: &[u8],
    keys: &[NtorV3SecretKey],
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
    let secret_key_y = curve25519::StaticSecret::random_from_rng(rng);
    server_handshake_ntor_v3_no_keygen(reply_fn, &secret_key_y, message, keys, verification)
}

/// As `server_handshake_ntor_v3`, but take a secret key instead of an RNG.
fn server_handshake_ntor_v3_no_keygen<REPLY: MsgReply>(
    reply_fn: &mut REPLY,
    secret_key_y: &curve25519::StaticSecret,
    message: &[u8],
    keys: &[NtorV3SecretKey],
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
    // Decode the message.
    let mut r = Reader::from_slice(message);
    let id: Ed25519Identity = r.extract()?;
    let requested_pk: curve25519::PublicKey = r.extract()?;
    let client_pk: curve25519::PublicKey = r.extract()?;
    let client_msg = if let Some(msg_len) = r.remaining().checked_sub(MAC_LEN) {
        r.take(msg_len)?
    } else {
        let deficit = (MAC_LEN - r.remaining())
            .try_into()
            .expect("miscalculated!");
        return Err(tor_bytes::Error::Truncated { deficit }.into());
    };
    let msg_mac: MacVal = r.extract()?;
    r.should_be_exhausted()?;

    // See if we recognize the provided (id,requested_pk) pair.
    let keypair = ct_lookup(keys, |key| key.matches(id, requested_pk));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(RelayHandshakeError::MissingKey),
    };

    let xb = keypair.sk.diffie_hellman(&client_pk);
    let (enc_key, mut mac) = kdf_msgkdf(&xb, &keypair.pk, &client_pk, verification)
        .map_err(into_internal!("Can't apply ntor3 kdf."))?;
    // Verify the message we received.
    let computed_mac: DigestVal = {
        use digest::Digest;
        mac.write(client_msg)
            .map_err(into_internal!("Can't compute MAC input."))?;
        mac.take().finalize().into()
    };
    let y_pk: curve25519::PublicKey = (secret_key_y).into();
    let xy = secret_key_y.diffie_hellman(&client_pk);

    let mut okay = computed_mac.ct_eq(&msg_mac)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory());

    let plaintext_msg = decrypt(&enc_key, client_msg);

    // Handle the message and decide how to reply.
    let reply = reply_fn.reply(&plaintext_msg);

    // It's not exactly constant time to use is_some() and
    // unwrap_or_else() here, but that should be somewhat
    // hidden by the rest of the computation.
    okay &= ct::bool_to_choice(reply.is_some());
    let reply = reply.unwrap_or_default();

    // If we reach this point, we are actually replying, or pretending
    // that we're going to reply.

    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&xy)
            .and_then(|_| si.write(&xb))
            .and_then(|_| si.write(&keypair.pk.id))
            .and_then(|_| si.write(&keypair.pk.pk))
            .and_then(|_| si.write(&client_pk))
            .and_then(|_| si.write(&y_pk))
            .and_then(|_| si.write(PROTOID))
            .and_then(|_| si.write(&Encap(verification)))
            .map_err(into_internal!("can't derive ntor3 secret_input"))?;
        si
    };
    let ntor_key_seed = h_key_seed(&secret_input);
    let verify = h_verify(&secret_input);

    let (enc_key, keystream) = {
        use digest::{ExtendableOutput, XofReader};
        let mut xof = DigestWriter(Shake256::default());
        xof.write(&T_FINAL)
            .and_then(|_| xof.write(&ntor_key_seed))
            .map_err(into_internal!("can't generate ntor3 xof."))?;
        let mut r = xof.take().finalize_xof();
        let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        r.read(&mut enc_key[..]);
        (enc_key, r)
    };
    let encrypted_reply = encrypt(&enc_key, &reply);
    let auth: DigestVal = {
        use digest::Digest;
        let mut auth = DigestWriter(Sha3_256::default());
        auth.write(&T_AUTH)
            .and_then(|_| auth.write(&verify))
            .and_then(|_| auth.write(&keypair.pk.id))
            .and_then(|_| auth.write(&keypair.pk.pk))
            .and_then(|_| auth.write(&y_pk))
            .and_then(|_| auth.write(&client_pk))
            .and_then(|_| auth.write(&msg_mac))
            .and_then(|_| auth.write(&Encap(&encrypted_reply)))
            .and_then(|_| auth.write(PROTOID))
            .and_then(|_| auth.write(&b"Server"[..]))
            .map_err(into_internal!("can't derive ntor3 authentication"))?;
        auth.take().finalize().into()
    };

    let reply = {
        let mut reply = Vec::new();
        reply
            .write(&y_pk)
            .and_then(|_| reply.write(&auth))
            .and_then(|_| reply.write(&encrypted_reply))
            .map_err(into_internal!("can't encode ntor3 reply."))?;
        reply
    };

    if okay.into() {
        Ok((reply, NtorV3XofReader(keystream)))
    } else {
        Err(RelayHandshakeError::BadClientHandshake)
    }
}

/// Finalize the handshake on the client side.
///
/// Called after we've received a message from the relay: try to
/// complete the handshake and verify its correctness.
///
/// On success, return the server's reply to our original encrypted message,
/// and an `XofReader` to use in generating circuit keys.
fn client_handshake_ntor_v3_part2(
    state: &NtorV3HandshakeState,
    relay_handshake: &[u8],
    verification: &[u8],
) -> Result<(Vec<u8>, NtorV3XofReader)> {
    let mut reader = Reader::from_slice(relay_handshake);
    let y_pk: curve25519::PublicKey = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let auth: DigestVal = reader
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let encrypted_msg = reader.into_rest();

    // TODO: Some of this code is duplicated from the server handshake code!  It
    // would be better to factor it out.
    let yx = state.my_sk.diffie_hellman(&y_pk);
    let secret_input = {
        let mut si = SecretBuf::new();
        si.write(&yx)
            .and_then(|_| si.write(&state.shared_secret))
            .and_then(|_| si.write(&state.relay_public.id))
            .and_then(|_| si.write(&state.relay_public.pk))
            .and_then(|_| si.write(&state.my_public))
            .and_then(|_| si.write(&y_pk))
            .and_then(|_| si.write(PROTOID))
            .and_then(|_| si.write(&Encap(verification)))
            .map_err(into_internal!("error encoding ntor3 secret_input"))?;
        si
    };
    let ntor_key_seed = h_key_seed(&secret_input);
    let verify = h_verify(&secret_input);

    let computed_auth: DigestVal = {
        use digest::Digest;
        let mut auth = DigestWriter(Sha3_256::default());
        auth.write(&T_AUTH)
            .and_then(|_| auth.write(&verify))
            .and_then(|_| auth.write(&state.relay_public.id))
            .and_then(|_| auth.write(&state.relay_public.pk))
            .and_then(|_| auth.write(&y_pk))
            .and_then(|_| auth.write(&state.my_public))
            .and_then(|_| auth.write(&state.msg_mac))
            .and_then(|_| auth.write(&Encap(encrypted_msg)))
            .and_then(|_| auth.write(PROTOID))
            .and_then(|_| auth.write(&b"Server"[..]))
            .map_err(into_internal!("error encoding ntor3 authentication input"))?;
        auth.take().finalize().into()
    };

    let okay = computed_auth.ct_eq(&auth)
        & ct::bool_to_choice(yx.was_contributory())
        & ct::bool_to_choice(state.shared_secret.was_contributory());

    let (enc_key, keystream) = {
        use digest::{ExtendableOutput, XofReader};
        let mut xof = DigestWriter(Shake256::default());
        xof.write(&T_FINAL)
            .and_then(|_| xof.write(&ntor_key_seed))
            .map_err(into_internal!("error encoding ntor3 xof input"))?;
        let mut r = xof.take().finalize_xof();
        let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
        r.read(&mut enc_key[..]);
        (enc_key, r)
    };
    let server_reply = decrypt(&enc_key, encrypted_msg);

    if okay.into() {
        Ok((server_reply, NtorV3XofReader(keystream)))
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}

#[cfg(test)]
#[allow(non_snake_case)] // to enable variable names matching the spec.
#[allow(clippy::many_single_char_names)] // ibid
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
    use crate::crypto::handshake::{ClientHandshake, ServerHandshake};

    use super::*;
    use hex_literal::hex;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn test_ntor3_roundtrip() {
        let mut rng = rand::thread_rng();
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let verification = &b"shared secret"[..];
        let client_message = &b"Hello. I am a client. Let's be friends!"[..];
        let relay_message = &b"Greetings, client. I am a robot. Beep boop."[..];

        let (c_state, c_handshake) =
            client_handshake_ntor_v3(&mut rng, &relay_private.pk, client_message, verification)
                .unwrap();

        struct Rep(Vec<u8>, Vec<u8>);
        impl MsgReply for Rep {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                self.0 = msg.to_vec();
                Some(self.1.clone())
            }
        }
        let mut rep = Rep(Vec::new(), relay_message.to_vec());

        let (s_handshake, mut s_keygen) = server_handshake_ntor_v3(
            &mut rng,
            &mut rep,
            &c_handshake,
            &[relay_private],
            verification,
        )
        .unwrap();

        let (s_msg, mut c_keygen) =
            client_handshake_ntor_v3_part2(&c_state, &s_handshake, verification).unwrap();

        assert_eq!(rep.0[..], client_message[..]);
        assert_eq!(s_msg[..], relay_message[..]);
        use digest::XofReader;
        let mut s_keys = [0_u8; 100];
        let mut c_keys = [0_u8; 1000];
        s_keygen.read(&mut s_keys);
        c_keygen.read(&mut c_keys);
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but use the higher-level APIs instead.
    #[test]
    fn test_ntor3_roundtrip_highlevel() {
        let mut rng = rand::thread_rng();
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let (c_state, c_handshake) =
            NtorV3Client::client1(&mut rng, &relay_private.pk, &[]).unwrap();

        let mut rep = |_: &[NtorV3Extension]| Some(vec![]);

        let (s_keygen, s_handshake) =
            NtorV3Server::server(&mut rng, &mut rep, &[relay_private], &c_handshake).unwrap();

        let (extensions, keygen) = NtorV3Client::client2(c_state, s_handshake).unwrap();

        assert!(extensions.is_empty());
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    // Same as previous test, but encode some congestion control extensions.
    #[test]
    fn test_ntor3_roundtrip_highlevel_cc() {
        let mut rng = rand::thread_rng();
        let relay_private = NtorV3SecretKey::generate_for_test(&mut testing_rng());

        let client_exts = vec![NtorV3Extension::RequestCongestionControl];
        let reply_exts = vec![NtorV3Extension::AckCongestionControl { sendme_inc: 42 }];

        let (c_state, c_handshake) = NtorV3Client::client1(
            &mut rng,
            &relay_private.pk,
            &[NtorV3Extension::RequestCongestionControl],
        )
        .unwrap();

        let mut rep = |msg: &[NtorV3Extension]| -> Option<Vec<NtorV3Extension>> {
            assert_eq!(msg, client_exts);
            Some(reply_exts.clone())
        };

        let (s_keygen, s_handshake) =
            NtorV3Server::server(&mut rng, &mut rep, &[relay_private], &c_handshake).unwrap();

        let (extensions, keygen) = NtorV3Client::client2(c_state, s_handshake).unwrap();

        assert_eq!(extensions, reply_exts);
        let c_keys = keygen.expand(1000).unwrap();
        let s_keys = s_keygen.expand(100).unwrap();
        assert_eq!(s_keys[..], c_keys[..100]);
    }

    #[test]
    fn test_ntor3_testvec() {
        let b = hex!("4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a");
        let id = hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");
        let x = hex!("b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49");
        let y = hex!("4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053");
        let b: curve25519::StaticSecret = b.into();
        let B: curve25519::PublicKey = (&b).into();
        let id: Ed25519Identity = id.into();
        let x: curve25519::StaticSecret = x.into();
        //let X = (&x).into();
        let y: curve25519::StaticSecret = y.into();

        let client_message = hex!("68656c6c6f20776f726c64");
        let verification = hex!("78797a7a79");
        let server_message = hex!("486f6c61204d756e646f");

        let relay_public = NtorV3PublicKey { pk: B, id };
        let relay_private = NtorV3SecretKey {
            sk: b,
            pk: relay_public.clone(),
        };

        let (state, client_handshake) =
            client_handshake_ntor_v3_no_keygen(&relay_public, &client_message, &verification, x)
                .unwrap();

        assert_eq!(client_handshake[..], hex!("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")[..]);

        struct Replier(Vec<u8>, Vec<u8>, bool);
        impl MsgReply for Replier {
            fn reply(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
                assert_eq!(msg, &self.0);
                self.2 = true;
                Some(self.1.clone())
            }
        }
        let mut rep = Replier(client_message.to_vec(), server_message.to_vec(), false);

        let (server_handshake, mut server_keygen) = server_handshake_ntor_v3_no_keygen(
            &mut rep,
            &y,
            &client_handshake,
            &[relay_private],
            &verification,
        )
        .unwrap();
        assert!(rep.2);

        assert_eq!(server_handshake[..], hex!("4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")[..]);

        let (server_msg_received, mut client_keygen) =
            client_handshake_ntor_v3_part2(&state, &server_handshake, &verification).unwrap();
        assert_eq!(&server_msg_received, &server_message);

        let (c_keys, s_keys) = {
            use digest::XofReader;
            let mut c = [0_u8; 256];
            let mut s = [0_u8; 256];
            client_keygen.read(&mut c);
            server_keygen.read(&mut s);
            (c, s)
        };
        assert_eq!(c_keys, s_keys);
        assert_eq!(c_keys[..], hex!("9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a")[..]);
    }
}
