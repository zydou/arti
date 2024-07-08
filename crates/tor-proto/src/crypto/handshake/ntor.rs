//! Implements the ntor handshake, as used in modern Tor.

use std::borrow::Borrow;

use super::{AuxDataReply, KeyGenerator, RelayHandshakeError, RelayHandshakeResult};
use crate::util::ct;
use crate::{Error, Result};
use tor_bytes::{EncodeResult, Reader, SecretBuf, Writer};
use tor_error::into_internal;
use tor_llcrypto::d;
use tor_llcrypto::pk::curve25519::*;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_llcrypto::util::ct::ct_lookup;

use digest::Mac;
use rand_core::{CryptoRng, RngCore};

/// Client side of the Ntor handshake.
pub(crate) struct NtorClient;

impl super::ClientHandshake for NtorClient {
    type KeyType = NtorPublicKey;
    type StateType = NtorHandshakeState;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn client1<R: RngCore + CryptoRng, M: Borrow<()>>(
        rng: &mut R,
        key: &Self::KeyType,
        _client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        client_handshake_ntor_v1(rng, key)
    }

    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<((), Self::KeyGen)> {
        let keygen = client_handshake2_ntor_v1(msg, &state)?;
        Ok(((), keygen))
    }
}

/// Server side of the ntor handshake.
#[allow(dead_code)] // TODO #1467
pub(crate) struct NtorServer;

impl super::ServerHandshake for NtorServer {
    type KeyType = NtorSecretKey;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn server<R: RngCore + CryptoRng, REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let _reply_msg = reply_fn
            .reply(&())
            .ok_or(RelayHandshakeError::BadClientHandshake)?;

        server_handshake_ntor_v1(rng, msg, key)
    }
}

/// A set of public keys used by a client to initiate an ntor handshake.
#[derive(Clone, Debug)]
pub(crate) struct NtorPublicKey {
    /// Public RSA identity fingerprint for the relay; used in authentication
    /// calculation.
    pub(crate) id: RsaIdentity,
    /// Public curve25519 ntor key for the relay.
    pub(crate) pk: PublicKey,
}

/// A secret key used by a relay to answer an ntor request
#[allow(dead_code)] // TODO #1467
pub(crate) struct NtorSecretKey {
    /// Public key components; must match those held by the client.
    pk: NtorPublicKey,
    /// Secret curve25519 ntor key for the relay; must correspond to
    /// the public key in pk.pk.
    sk: StaticSecret,
}

use subtle::{Choice, ConstantTimeEq};
impl NtorSecretKey {
    /// Construct a new NtorSecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(sk: StaticSecret, pk: PublicKey, id: RsaIdentity) -> Self {
        NtorSecretKey {
            pk: NtorPublicKey { id, pk },
            sk,
        }
    }
    /// Return true if the curve25519 public key in `self` matches `pk`.
    ///
    /// Used for looking up keys in an array.
    #[allow(dead_code)] // TODO #1467
    fn matches_pk(&self, pk: &PublicKey) -> Choice {
        self.pk.pk.as_bytes().ct_eq(pk.as_bytes())
    }
}

/// Client state for an ntor handshake.
pub(crate) struct NtorHandshakeState {
    /// The relay's public key.  We need to remember this since it is
    /// used to finish the handshake.
    relay_public: NtorPublicKey,
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: StaticSecret,
    /// The public key `X` corresponding to my_sk.
    my_public: PublicKey,
}

/// KeyGenerator for use with ntor circuit handshake.
pub(crate) struct NtorHkdfKeyGenerator {
    /// Secret key information derived from the handshake, used as input
    /// to HKDF
    seed: SecretBuf,
}

impl NtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub(crate) fn new(seed: SecretBuf) -> Self {
        NtorHkdfKeyGenerator { seed }
    }
}

impl KeyGenerator for NtorHkdfKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        let ntor1_key = &b"ntor-curve25519-sha256-1:key_extract"[..];
        let ntor1_expand = &b"ntor-curve25519-sha256-1:key_expand"[..];
        use crate::crypto::ll::kdf::{Kdf, Ntor1Kdf};
        Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
    }
}

/// Alias for an HMAC output, used to validate correctness of a handshake.
type Authcode = digest::CtOutput<hmac::Hmac<d::Sha256>>;

/// Perform a client handshake, generating an onionskin and a state object
fn client_handshake_ntor_v1<R>(
    rng: &mut R,
    relay_public: &NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let my_sk = StaticSecret::random_from_rng(rng);
    let my_public = PublicKey::from(&my_sk);

    client_handshake_ntor_v1_no_keygen(my_public, my_sk, relay_public)
}

/// Helper: client handshake _without_ generating  new keys.
fn client_handshake_ntor_v1_no_keygen(
    my_public: PublicKey,
    my_sk: StaticSecret,
    relay_public: &NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)> {
    let mut v: Vec<u8> = Vec::new();

    v.write(&relay_public.id)
        .and_then(|_| v.write(&relay_public.pk))
        .and_then(|_| v.write(&my_public))
        .map_err(|e| Error::from_bytes_enc(e, "Can't encode client handshake."))?;

    assert_eq!(v.len(), 20 + 32 + 32);

    let state = NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_public,
        my_sk,
    };

    Ok((state, v))
}

/// Complete a client handshake, returning a key generator on success.
fn client_handshake2_ntor_v1<T>(msg: T, state: &NtorHandshakeState) -> Result<NtorHkdfKeyGenerator>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk: PublicKey = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let auth: Authcode = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    let (keygen, authcode) =
        ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk)
            .map_err(into_internal!("Error deriving keys"))?;

    let okay = authcode.ct_eq(&auth)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory());

    if okay.into() {
        Ok(keygen)
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}

/// helper: compute a key generator and an authentication code from a set
/// of ntor parameters.
///
/// These parameter names are as described in tor-spec.txt
fn ntor_derive(
    xy: &SharedSecret,
    xb: &SharedSecret,
    server_pk: &NtorPublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
    let ntor1_protoid = &b"ntor-curve25519-sha256-1"[..];
    let ntor1_mac = &b"ntor-curve25519-sha256-1:mac"[..];
    let ntor1_verify = &b"ntor-curve25519-sha256-1:verify"[..];
    let server_string = &b"Server"[..];

    let mut secret_input = SecretBuf::new();
    secret_input.write(xy)?; // EXP(X,y)
    secret_input.write(xb)?; // EXP(X,b)
    secret_input.write(&server_pk.id)?; // ID
    secret_input.write(&server_pk.pk)?; // B
    secret_input.write(x)?; // X
    secret_input.write(y)?; // Y
    secret_input.write(ntor1_protoid)?; // PROTOID

    use hmac::Hmac;
    use tor_llcrypto::d::Sha256;
    let verify = {
        let mut m =
            Hmac::<Sha256>::new_from_slice(ntor1_verify).expect("Hmac allows keys of any size");
        m.update(&secret_input[..]);
        m.finalize()
    };
    let mut auth_input = Vec::new();
    auth_input.write_and_consume(verify)?; // verify
    auth_input.write(&server_pk.id)?; // ID
    auth_input.write(&server_pk.pk)?; // B
    auth_input.write(y)?; // Y
    auth_input.write(x)?; // X
    auth_input.write(ntor1_protoid)?; // PROTOID
    auth_input.write(server_string)?; // "Server"

    let auth_mac = {
        let mut m =
            Hmac::<Sha256>::new_from_slice(ntor1_mac).expect("Hmac allows keys of any size");
        m.update(&auth_input[..]);
        m.finalize()
    };

    let keygen = NtorHkdfKeyGenerator::new(secret_input);
    Ok((keygen, auth_mac))
}

/// Perform a server-side ntor handshake.
///
/// On success returns a key generator and a server onionskin.
#[allow(dead_code)] // TODO #1467
fn server_handshake_ntor_v1<R, T>(
    rng: &mut R,
    msg: T,
    keys: &[NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    R: RngCore + CryptoRng,
    T: AsRef<[u8]>,
{
    // TODO(nickm): we generate this key whether or not we are
    // actually going to find our nodeid or keyid. Perhaps we should
    // delay that till later?  It shouldn't matter for most cases,
    // though.
    let ephem = EphemeralSecret::random_from_rng(rng);
    let ephem_pub = PublicKey::from(&ephem);

    server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, msg, keys)
}

/// Helper: perform a server handshake without generating any new keys.
fn server_handshake_ntor_v1_no_keygen<T>(
    ephem_pub: PublicKey,
    ephem: EphemeralSecret,
    msg: T,
    keys: &[NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());

    let my_id: RsaIdentity = cur.extract()?;
    let my_key: PublicKey = cur.extract()?;
    let their_pk: PublicKey = cur.extract()?;

    let keypair = ct_lookup(keys, |key| key.matches_pk(&my_key));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(RelayHandshakeError::MissingKey),
    };

    if my_id != keypair.pk.id {
        return Err(RelayHandshakeError::MissingKey);
    }

    let xy = ephem.diffie_hellman(&their_pk);
    let xb = keypair.sk.diffie_hellman(&their_pk);

    let okay =
        ct::bool_to_choice(xy.was_contributory()) & ct::bool_to_choice(xb.was_contributory());

    let (keygen, authcode) = ntor_derive(&xy, &xb, &keypair.pk, &their_pk, &ephem_pub)
        .map_err(into_internal!("Error deriving keys"))?;

    let mut reply: Vec<u8> = Vec::new();
    reply
        .write(&ephem_pub)
        .and_then(|_| reply.write_and_consume(authcode))
        .map_err(into_internal!(
            "Generated relay handshake we couldn't encode"
        ))?;

    if okay.into() {
        Ok((keygen, reply))
    } else {
        Err(RelayHandshakeError::BadClientHandshake)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::crypto::testing::FakePRNG;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn simple() -> Result<()> {
        use crate::crypto::handshake::{ClientHandshake, ServerHandshake};
        let mut rng = testing_rng();
        let relay_secret = StaticSecret::random_from_rng(&mut rng);
        let relay_public = PublicKey::from(&relay_secret);
        let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
        let relay_ntpk = NtorPublicKey {
            id: relay_identity,
            pk: relay_public,
        };
        let (state, cmsg) = NtorClient::client1(&mut rng, &relay_ntpk, &())?;

        let relay_ntsk = NtorSecretKey {
            pk: relay_ntpk,
            sk: relay_secret,
        };
        let relay_ntsks = [relay_ntsk];

        let (skeygen, smsg) =
            NtorServer::server(&mut rng, &mut |_: &()| Some(()), &relay_ntsks, &cmsg).unwrap();

        let (_extensions, ckeygen) = NtorClient::client2(state, smsg)?;

        let skeys = skeygen.expand(55)?;
        let ckeys = ckeygen.expand(55)?;

        assert_eq!(skeys, ckeys);

        Ok(())
    }

    fn make_fake_ephem_key(bytes: &[u8]) -> EphemeralSecret {
        assert_eq!(bytes.len(), 32);
        let rng = FakePRNG::new(bytes);
        EphemeralSecret::random_from_rng(rng)
    }

    #[test]
    fn testvec() -> Result<()> {
        use hex_literal::hex;

        let b_sk = hex!("4820544f4c4420594f5520444f474954204b454550532048415050454e494e47");
        let b_pk = hex!("ccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471");
        let x_sk = hex!("706f6461792069207075742e2e2e2e2e2e2e2e4a454c4c59206f6e2074686973");
        let x_pk = hex!("e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
        let y_sk = hex!("70686520737175697272656c2e2e2e2e2e2e2e2e686173206869732067616d65");
        let y_pk = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a37");
        let id = hex!("69546f6c64596f7541626f75745374616972732e");
        let client_handshake = hex!("69546f6c64596f7541626f75745374616972732eccbc8541904d18af08753eae967874749e6149f873de937f57f8fd903a21c471e65dfdbef8b2635837fe2cebc086a8096eae3213e6830dc407516083d412b078");
        let server_handshake = hex!("390480a14362761d6aec1fea840f6e9e928fb2adb7b25c670be1045e35133a371cbdf68b89923e1f85e8e18ee6e805ea333fe4849c790ffd2670bd80fec95cc8");
        let keys = hex!("0c62dee7f48893370d0ef896758d35729867beef1a5121df80e00f79ed349af39b51cae125719182f19d932a667dae1afbf2e336e6910e7822223e763afad0a13342157969dc6b79");

        let relay_pk = NtorPublicKey {
            id: RsaIdentity::from_bytes(&id).unwrap(),
            pk: b_pk.into(),
        };
        let relay_sk = NtorSecretKey {
            pk: relay_pk.clone(),
            sk: b_sk.into(),
        };

        let (state, create_msg) =
            client_handshake_ntor_v1_no_keygen(x_pk.into(), x_sk.into(), &relay_pk).unwrap();
        assert_eq!(&create_msg[..], &client_handshake[..]);

        let ephem = make_fake_ephem_key(&y_sk[..]);
        let ephem_pub = y_pk.into();
        let (s_keygen, created_msg) =
            server_handshake_ntor_v1_no_keygen(ephem_pub, ephem, &create_msg[..], &[relay_sk])
                .unwrap();
        assert_eq!(&created_msg[..], &server_handshake[..]);

        let c_keygen = client_handshake2_ntor_v1(created_msg, &state)?;

        let c_keys = c_keygen.expand(keys.len())?;
        let s_keys = s_keygen.expand(keys.len())?;
        assert_eq!(&c_keys[..], &keys[..]);
        assert_eq!(&s_keys[..], &keys[..]);

        Ok(())
    }

    #[test]
    fn failing_handshakes() {
        use crate::crypto::handshake::{ClientHandshake, ServerHandshake};
        let mut rng = testing_rng();

        // Set up keys.
        let relay_secret = StaticSecret::random_from_rng(&mut rng);
        let relay_public = PublicKey::from(&relay_secret);
        let wrong_public = PublicKey::from([16_u8; 32]);
        let relay_identity = RsaIdentity::from_bytes(&[12; 20]).unwrap();
        let wrong_identity = RsaIdentity::from_bytes(&[13; 20]).unwrap();
        let relay_ntpk = NtorPublicKey {
            id: relay_identity,
            pk: relay_public,
        };
        let relay_ntsk = NtorSecretKey {
            pk: relay_ntpk.clone(),
            sk: relay_secret,
        };
        let relay_ntsks = &[relay_ntsk];
        let wrong_ntpk1 = NtorPublicKey {
            id: wrong_identity,
            pk: relay_public,
        };
        let wrong_ntpk2 = NtorPublicKey {
            id: relay_identity,
            pk: wrong_public,
        };

        // If the client uses the wrong keys, the relay should reject the
        // handshake.
        let (_, handshake1) = NtorClient::client1(&mut rng, &wrong_ntpk1, &()).unwrap();
        let (_, handshake2) = NtorClient::client1(&mut rng, &wrong_ntpk2, &()).unwrap();
        let (st3, handshake3) = NtorClient::client1(&mut rng, &relay_ntpk, &()).unwrap();

        let ans1 = NtorServer::server(&mut rng, &mut |_: &()| Some(()), relay_ntsks, &handshake1);
        let ans2 = NtorServer::server(&mut rng, &mut |_: &()| Some(()), relay_ntsks, &handshake2);

        assert!(ans1.is_err());
        assert!(ans2.is_err());

        // If the relay's message is tampered with, the client will
        // reject the handshake.
        let (_, mut smsg) =
            NtorServer::server(&mut rng, &mut |_: &()| Some(()), relay_ntsks, &handshake3).unwrap();
        smsg[60] ^= 7;
        let ans3 = NtorClient::client2(st3, smsg);
        assert!(ans3.is_err());
    }
}
