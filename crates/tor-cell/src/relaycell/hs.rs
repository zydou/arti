//! Encoding and decoding for relay messages related to onion services.

#![allow(dead_code, unused_variables)] // TODO hs: remove.

// TODO hs: we'll need accessors for the useful fields in all these types.

use self::ext::{decl_extension_group, ExtGroup, ExtList};

use super::msg::{self, Body};
use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Error as BytesError, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_hscrypto::RendCookie;
use tor_llcrypto::pk::rsa::RsaIdentity;

pub mod est_intro;
mod ext;

pub use ext::UnrecognizedExt;

caret_int! {
    /// The type of the introduction point auth key
    pub struct AuthKeyType(u8) {
        /// Ed25519; SHA3-256
        ED25519_SHA3_256 = 2,
    }
}

/// A message sent from client to rendezvous point.
#[derive(Debug, Clone)]
pub struct EstablishRendezvous {
    /// A rendezvous cookie is an arbitrary 20-byte value,
    /// chosen randomly by the client.
    cookie: [u8; EstablishRendezvous::COOKIE_LEN], // TODO hs: Make this a RendCookie.
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
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        r.take_rest();
        Ok(Self { cookie })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.cookie)
    }
}

#[derive(Debug, Clone)]
/// A message sent from client to introduction point.
pub struct Introduce1(Introduce);

impl msg::Body for Introduce1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(Introduce::decode_from_reader(r)?))
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

impl Introduce1 {
    /// All arguments constructor
    pub fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self(Introduce::new(auth_key_type, auth_key, encrypted))
    }
}

#[derive(Debug, Clone)]
/// A message sent from introduction point to hidden service host.
pub struct Introduce2(Introduce);

impl msg::Body for Introduce2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(Introduce::decode_from_reader(r)?))
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

impl Introduce2 {
    /// All arguments constructor
    pub fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self(Introduce::new(auth_key_type, auth_key, encrypted))
    }
}

#[derive(Debug, Clone)]
/// A message body shared by Introduce1 and Introduce2
struct Introduce {
    /// Introduction point auth key type and the type of
    /// the MAC used in `handshake_auth`.
    auth_key_type: AuthKeyType,
    /// The public introduction point auth key.
    auth_key: Vec<u8>,
    /// Up to end of relay payload.
    encrypted: Vec<u8>,
}

impl Introduce {
    /// All arguments constructor
    fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self {
            auth_key_type,
            auth_key,
            encrypted,
        }
    }
    /// Decode an Introduce message body from the given reader
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let legacy_key_id: RsaIdentity = r.extract()?;
        if !legacy_key_id.is_zero() {
            return Err(BytesError::InvalidMessage(
                "legacy key id in Introduce1.".into(),
            ));
        }
        let auth_key_type = r.take_u8()?.into();
        let auth_key_len = r.take_u16()?;
        let auth_key = r.take(auth_key_len as usize)?.into();
        let n_ext = r.take_u8()?;
        for _ in 0..n_ext {
            let _ext_type = r.take_u8()?;
            r.read_nested_u8len(|r| {
                r.take_rest();
                Ok(())
            })?;
        }
        let encrypted = r.take_rest().into();
        Ok(Self {
            auth_key_type,
            auth_key,
            encrypted,
        })
    }
    /// Encode an Introduce message body onto the given writer
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&[0_u8; 20]);
        w.write_u8(self.auth_key_type.get());
        w.write_u16(u16::try_from(self.auth_key.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.auth_key[..]);
        // No Introduce1 extension for now.
        w.write_u8(0_u8);
        w.write_all(&self.encrypted[..]);
        Ok(())
    }
}

/// A message sent from an onion service to a rendezvous point, telling it to
/// make a connection to the client.
#[derive(Debug, Clone)]
pub struct Rendezvous1 {
    /// The cookie originally sent by the client in its ESTABLISH_REND message.
    cookie: RendCookie,
    /// The message to send the client.
    message: Vec<u8>,
}

impl Body for Rendezvous1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        let message = r.take_rest().into();
        Ok(Self { cookie, message })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.cookie)?;
        w.write_all(&self.message[..]);
        Ok(())
    }
}

impl Rendezvous1 {
    /// Create a new Rendezvous1 message, to handshake with a client identified
    /// by a given RendCookie, and send it a given message.
    pub fn new(cookie: RendCookie, message: impl Into<Vec<u8>>) -> Self {
        Self {
            cookie,
            message: message.into(),
        }
    }
}

/// A message sent from the rendezvous point to the client, telling it about the
/// onion service's message.
#[derive(Debug, Clone)]
pub struct Rendezvous2 {
    /// The message from the onion service.
    message: Vec<u8>,
}

impl Rendezvous2 {
    /// Construct a new Rendezvous2 cell containing a given message.
    pub fn new(message: impl Into<Vec<u8>>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<Rendezvous1> for Rendezvous2 {
    fn from(value: Rendezvous1) -> Self {
        Self {
            message: value.message,
        }
    }
}

impl Body for Rendezvous2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let message = r.take_rest().into();
        Ok(Self { message })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.message[..]);
        Ok(())
    }
}

caret_int! {
    /// The recognized extension types for an `IntroEstablished` message.
    #[derive(Ord, PartialOrd)]
    pub struct IntroEstablishedExtType(u8) {
    }
}

decl_extension_group! {
    /// An extension to an IntroEstablished message.
    ///
    /// (Currently, no extensions of this type are recognized)
    #[derive(Debug,Clone)]
    enum IntroEstablishedExt [ IntroEstablishedExtType ] {
    }
}

/// Reply sent from the introduction point to the onion service, telling it that
/// an introduction point is now established.
#[derive(Debug, Clone, Default)]
pub struct IntroEstablished {
    /// The extensions included in this cell.
    extensions: ExtList<IntroEstablishedExt>,
}

impl IntroEstablished {
    /// Create a new IntroEstablished message.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Body for IntroEstablished {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let extensions = r.extract()?;
        Ok(Self { extensions })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.extensions)?;
        Ok(())
    }
}

caret_int! {
    /// A status code returned in response to an INTRODUCE1 message.
    pub struct IntroduceAckStatus(u16) {
        /// The message was relayed successfully.
        SUCCESS = 0x0000,
        /// The introduction point does not have a live circuit from the
        /// identified service.
        NOT_RECOGNIZED = 0x0001,
        /// There was a failure while parsing the INTRODUCE1 message.
        BAD_MESSAGE_FORMAT = 0x0002,
        /// The introduction point was unable to deliver the message to the service.
        CANT_RELAY = 0x0003,
    }
}
caret_int! {
    /// The recognized extension types for an `IntroEstablished` message.
    #[derive(Ord, PartialOrd)]
    pub struct IntroduceAckExtType(u8) {
    }
}
decl_extension_group! {
    /// An extension to an IntroduceAct message.
    ///
    /// (Currently, no extensions of this type are recognized.)
    #[derive(Debug,Clone)]
    enum IntroduceAckExt [ IntroduceAckExtType ] {
    }
}

/// A reply from the introduction point to the client, telling it that its
/// introduce1 was received.
#[derive(Clone, Debug)]
pub struct IntroduceAck {
    /// The status reported for the Introduce1 message.
    status_code: IntroduceAckStatus,
    /// The extensions on this message.
    extensions: ExtList<IntroduceAckExt>,
}
impl IntroduceAck {
    /// Create a new IntroduceAck message with a provided status code.
    pub fn new(status_code: IntroduceAckStatus) -> Self {
        Self {
            status_code,
            extensions: Default::default(),
        }
    }

    /// Return the status code from this message.
    pub fn status(&self) -> IntroduceAckStatus {
        self.status_code
    }
}

impl Body for IntroduceAck {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let status_code = r.take_u16()?.into();
        let extensions = r.extract()?;
        Ok(IntroduceAck {
            status_code,
            extensions,
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u16(self.status_code.into());
        w.write(&self.extensions)?;
        Ok(())
    }
}

super::msg::empty_body! {
    /// Acknowledges an EstablishRendezvous message.
    pub struct RendezvousEstablished {}
}
