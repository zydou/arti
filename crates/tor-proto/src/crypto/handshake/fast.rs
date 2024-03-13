//! Implementation for the (deprecated) CreateFast handshake.
//!

use std::borrow::Borrow;

use super::{RelayHandshakeError, RelayHandshakeResult};
use crate::crypto::ll::kdf::{Kdf, LegacyKdf};
use crate::util::ct::bytes_eq;
use crate::{Error, Result};

use rand::{CryptoRng, RngCore};
use tor_bytes::SecretBuf;
use tor_error::into_internal;

/// Number of bytes used for a "CREATE_FAST" handshake by the initiator.
pub(crate) const FAST_C_HANDSHAKE_LEN: usize = 20;
/// Number of bytes used for a "CREATE_FAST" handshake by the responder
pub(crate) const FAST_S_HANDSHAKE_LEN: usize = 20 * 2;

/// State for a CREATE_FAST client handshake.
pub(crate) struct CreateFastClientState([u8; FAST_C_HANDSHAKE_LEN]);

/// Client-handshake for CREATE_FAST.
///
/// See module documentation; you probably don't want to use this.
pub(crate) struct CreateFastClient;

/// How many bytes does this handshake use for its input seed?
const SECRET_INPUT_LEN: usize = 40;

impl super::ClientHandshake for CreateFastClient {
    type KeyType = ();
    type StateType = CreateFastClientState;
    type KeyGen = super::TapKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn client1<R: RngCore + CryptoRng, M: Borrow<()>>(
        rng: &mut R,
        _key: &Self::KeyType,
        _client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        let mut state = [0_u8; FAST_C_HANDSHAKE_LEN];
        rng.fill_bytes(&mut state);
        Ok((CreateFastClientState(state), state.into()))
    }

    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<((), Self::KeyGen)> {
        let msg = msg.as_ref();
        if msg.len() != FAST_S_HANDSHAKE_LEN {
            return Err(Error::BadCircHandshakeAuth);
        }
        // There is not necessarily much point here (and below) in using a
        // SecretBuf, since the data at issue are already in a cell that
        // _wasn't_ marked with Zeroize.  Still, for consistency, we use it
        // here.
        let mut inp = SecretBuf::with_capacity(SECRET_INPUT_LEN);
        inp.extend_from_slice(&state.0[..]);
        inp.extend_from_slice(&msg[0..20]);

        let kh_expect = LegacyKdf::new(0).derive(&inp[..], 20)?;

        if !bytes_eq(&kh_expect, &msg[20..40]) {
            return Err(Error::BadCircHandshakeAuth);
        }

        Ok(((), super::TapKeyGenerator::new(inp)))
    }
}

/// Relay-handshake for CREATE_FAST.
///
/// See module documentation; you probably don't want to use this.
pub(crate) struct CreateFastServer;

impl super::ServerHandshake for CreateFastServer {
    type KeyType = ();
    type KeyGen = super::TapKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn server<R: RngCore + CryptoRng, REPLY: super::AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        _key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let _reply_extensions: () = reply_fn
            .reply(&())
            .ok_or(RelayHandshakeError::BadClientHandshake)?;

        let msg = msg.as_ref();
        if msg.len() != FAST_C_HANDSHAKE_LEN {
            return Err(RelayHandshakeError::BadClientHandshake);
        }
        let mut reply = vec![0_u8; FAST_S_HANDSHAKE_LEN];
        rng.fill_bytes(&mut reply[0..20]);

        let mut inp = SecretBuf::with_capacity(SECRET_INPUT_LEN);
        inp.extend_from_slice(msg);
        inp.extend_from_slice(&reply[0..20]);
        let kh = LegacyKdf::new(0)
            .derive(&inp[..], 20)
            .map_err(into_internal!("Can't expand key"))?;
        reply[20..].copy_from_slice(&kh);

        Ok((super::TapKeyGenerator::new(inp), reply))
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
    use crate::crypto::handshake::{ClientHandshake, KeyGenerator, ServerHandshake};
    use hex_literal::hex;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn roundtrip() {
        let mut rng = testing_rng();

        let (state, cmsg) = CreateFastClient::client1(&mut rng, &(), &()).unwrap();
        let (s_kg, smsg) =
            CreateFastServer::server(&mut rng, &mut |_: &()| Some(()), &[()], cmsg).unwrap();
        let (_msg, c_kg) = CreateFastClient::client2(state, smsg).unwrap();

        let s_key = s_kg.expand(200).unwrap();
        let c_key = c_kg.expand(200).unwrap();

        assert_eq!(s_key, c_key);
    }

    #[test]
    fn failure() {
        let mut rng = testing_rng();

        // badly formatted client message.
        let cmsg = [6_u8; 19];
        let ans = CreateFastServer::server(&mut rng, &mut |_: &()| Some(()), &[()], cmsg);
        assert!(ans.is_err());

        // corrupt/ incorrect server reply.
        let (state, cmsg) = CreateFastClient::client1(&mut rng, &(), &()).unwrap();
        let (_, mut smsg) =
            CreateFastServer::server(&mut rng, &mut |_: &()| Some(()), &[()], cmsg).unwrap();
        smsg[35] ^= 16;
        let ans = CreateFastClient::client2(state, smsg);
        assert!(ans.is_err());
    }

    fn test_one_handshake(cmsg: [u8; 20], smsg: [u8; 40], keys: [u8; 100]) {
        use crate::crypto::testing::FakePRNG;

        let mut rng = FakePRNG::new(&cmsg);
        let (state, cmsg) = CreateFastClient::client1(&mut rng, &(), &()).unwrap();

        let mut rng = FakePRNG::new(&smsg);
        let (s_kg, smsg) =
            CreateFastServer::server(&mut rng, &mut |_: &()| Some(()), &[()], cmsg).unwrap();
        let (_msg, c_kg) = CreateFastClient::client2(state, smsg).unwrap();

        let s_key = s_kg.expand(100).unwrap();
        let c_key = c_kg.expand(100).unwrap();

        assert_eq!(s_key, c_key);
        assert_eq!(&s_key[..], &keys[..]);
    }

    #[test]
    fn testvec() {
        // Generated from Tor.
        test_one_handshake(
            hex!("080E247DF7C252FCD2DC10F459703480C223E3A6"),
            hex!("BA95C0D092335428BF80093BBED0B7A26C49E1E8696FBF9C8D6BE26504219C000D26AFE370FCEF04"),
            hex!("AFA89B4FC8CF882335A582C52478B5FCB1E08DAF707E2C2D23B8C27D30BD461F3DF98A3AF82221CB658AD0AA8680B99067E4F7DBC546970EA9A56B26433C71DA867BDD09C14A1308BC327D6A448D71D2382B3AB6AF0BB4E19649A8DFF607DB9C57A04AC3"));

        test_one_handshake(
            hex!("5F786C724C2F5978474A04FA63772057AD896A03"),
            hex!("6210B037001405742FE78B6F5B34E6DB3C9F2F7E24239498613E0ED872E110A00774A3FCB37A7507"),
            hex!("D41B65D83FB4B34A322B658BE4D706EDCD8B62813757E719118C394E1F22E1C8EA8959BAB30E856A914C3054946F547397094DE031F5BCA384C65C8880BF7AAB9CE7BEE33971F9DE8C22A23366F46BF8B5E5112321E216B0E02C62EEA3ABB72A0E062592"));
    }
}
