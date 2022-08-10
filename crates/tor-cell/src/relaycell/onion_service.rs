//! Encoding and decoding for relay messages
//!
//! Relay messages are sent along circuits, inside RELAY or RELAY_EARLY
//! cells.

use super::msg;
use caret::caret_int;
use tor_bytes::{EncodeResult, Error, Result};
use tor_bytes::{Reader, Writer};

caret_int! {
    /// The type of the introduction point auth key
    pub struct AuthKeyType(u8) {
        /// Ed25519; SHA3-256
        ED25519_SHA3_256 = 2,
    }
}

/// A hidden services establishes a new introduction point,
/// by sending an EstablishIntro message.
#[derive(Debug, Clone)]
pub struct EstablishIntro {
    /// Introduction point auth key type and the type of
    /// the MAC used in `handshake_auth`.
    auth_key_type: AuthKeyType,
    /// The public introduction point auth key.
    auth_key: Vec<u8>,
    /// the MAC of all earlier fields in the cell.
    handshake_auth: [u8; 32],
    /// A signature using `auth_key` of all contents
    /// of the cell.
    sig: Vec<u8>,
}

impl msg::Body for EstablishIntro {
    fn into_message(self) -> msg::RelayMsg {
        msg::RelayMsg::EstablishIntro(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let auth_key_type = r.take_u8()?.into();
        let auth_key_len = r.take_u16()?;
        let auth_key = r.take(auth_key_len as usize)?.into();
        if r.take_u8()? != 0 {
            // TODO: Support ESTABLISH_INTRO extensions
            return Err(Error::BadMessage(
                "ESTABLISH_INTRO extension not supported.",
            ));
        }
        let handshake_auth = r.extract()?;
        let sig_len = r.take_u16()?;
        let sig = r.take(sig_len as usize)?.into();
        Ok(EstablishIntro {
            auth_key_type,
            auth_key,
            handshake_auth,
            sig,
        })
    }
    fn encode_onto(self, w: &mut Vec<u8>) -> EncodeResult<()> {
        w.write_u8(self.auth_key_type.get());
        // TODO: This should fail when auth_key is too long,
        // but `as` truncates the value silently. This depends on
        // `tor_bytes::Writer::write` to return a `Result`.
        w.write_u16(self.auth_key.len() as u16);
        w.write_all(&self.auth_key[..]);
        // N_EXTENSIONS is zero for now
        w.write_u8(0_u8);
        w.write_all(&self.handshake_auth[..]);
        w.write_u16(self.sig.len() as u16);
        w.write_all(&self.sig[..]);
        Ok(())
    }
}

/// A message sent from client to rendezvous point.
#[derive(Debug, Clone)]
pub struct EstablishRendezvous {
    /// A rendezvous cookie is an arbitrary 20-byte value,
    /// chosen randomly by the client.
    cookie: [u8; EstablishRendezvous::COOKIE_LEN],
}
impl EstablishRendezvous {
    /// The only acceptable length of a rendezvous cookie.
    pub const COOKIE_LEN: usize = 20;

    /// Construct a new establish rendezvous cell.
    pub fn new(cookie: [u8; Self::COOKIE_LEN]) -> Self {
        Self { cookie }
    }
}
impl msg::Body for EstablishRendezvous {
    fn into_message(self) -> msg::RelayMsg {
        msg::RelayMsg::EstablishRendezvous(self)
    }
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        r.take_rest();
        Ok(Self { cookie })
    }
    fn encode_onto(self, w: &mut Vec<u8>) -> EncodeResult<()> {
        w.write(&self.cookie)
    }
}
