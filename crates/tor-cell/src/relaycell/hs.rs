//! Encoding and decoding for relay messages related to onion services.

use self::ext::{decl_extension_group, ExtGroup, ExtList};

use super::msg::{self, Body};
use caret::caret_int;
use derive_deftly::Deftly;
use tor_bytes::{EncodeError, EncodeResult, Error as BytesError, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_hscrypto::RendCookie;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::derive_deftly_template_HasMemoryCost;

pub mod est_intro;
mod ext;
pub mod intro_payload;

pub use ext::UnrecognizedExt;

caret_int! {
    /// The type of the introduction point auth key
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct AuthKeyType(u8) {
        /// Ed25519; SHA3-256
        ED25519_SHA3_256 = 2,
    }
}

/// A message sent from client to rendezvous point.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct EstablishRendezvous {
    /// A rendezvous cookie is an arbitrary 20-byte value,
    /// chosen randomly by the client.
    cookie: RendCookie,
}
impl EstablishRendezvous {
    /// Construct a new establish rendezvous cell.
    pub fn new(cookie: RendCookie) -> Self {
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

#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
/// A message sent from client to introduction point.
pub struct Introduce1(Introduce);

impl msg::Body for Introduce1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let (intro, _) = Introduce::decode_from_reader(r)?;
        Ok(Self(intro))
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

#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
/// A message sent from introduction point to hidden service host.
pub struct Introduce2 {
    /// A copy of the encoded header that we'll use to finish the hs_ntor handshake.
    encoded_header: Vec<u8>,
    /// The decoded message itself.
    msg: Introduce,
}

impl msg::Body for Introduce2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let (msg, header) = Introduce::decode_from_reader(r)?;
        let encoded_header = header.to_vec();

        Ok(Self {
            encoded_header,
            msg,
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.msg.encode_onto(w)
    }
}

impl Introduce2 {
    /// All arguments constructor.
    ///
    /// This is only useful for testing, since in reality the only time this
    /// message type is created is when an introduction point is forwarding an
    /// INTRODUCE1 message.
    #[cfg(test)] // Don't expose this generally without dealing somehow with the `expect` below
    pub fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        let msg = Introduce::new(auth_key_type, auth_key, encrypted);
        let mut encoded_header = Vec::new();
        msg.header
            .write_onto(&mut encoded_header)
            .expect("Generated a header that we could not encode");
        Self {
            encoded_header,
            msg,
        }
    }

    /// Return the bytes used to transmit `header`.
    ///
    /// (This data is used as part of the handshake.)
    pub fn encoded_header(&self) -> &[u8] {
        &self.encoded_header[..]
    }
    /// Return the parsed header of this message.
    pub fn header(&self) -> &IntroduceHeader {
        &self.msg.header
    }
    /// Return the encrypted body of this message.
    ///
    /// (This body is decrypted as part of the handshake.)
    pub fn encrypted_body(&self) -> &[u8] {
        &self.msg.encrypted[..]
    }
}

caret_int! {
    /// The recognized extension types for an `Introduce1` or `Introduce2 message.
    #[derive(Ord,PartialOrd)]
    pub struct IntroduceExtType(u8) {
    }
}

decl_extension_group! {
    /// An extension to an IntroEstablished message.
    ///
    /// (Currently, no extensions of this type are recognized)
    #[derive(Debug,Clone,Deftly)]
    #[derive_deftly(HasMemoryCost)]
    enum IntroduceExt [ IntroduceExtType ] {
    }
}

/// The unencrypted header portion of an `Introduce1` or `Introduce2` message.
///
/// This is a separate type because the `hs_ntor` handshake requires access to the
/// encoded format of the header, only.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct IntroduceHeader {
    /// Introduction point auth key type and the type of
    /// the MAC used in `handshake_auth`.
    auth_key_type: AuthKeyType,
    /// The public introduction point auth key.
    auth_key: Vec<u8>,
    /// A list of extensions
    extensions: ExtList<IntroduceExt>,
}

impl tor_bytes::Readable for IntroduceHeader {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let legacy_key_id: RsaIdentity = r.extract()?;
        if !legacy_key_id.is_zero() {
            return Err(BytesError::InvalidMessage(
                "legacy key id in Introduce1.".into(),
            ));
        }
        let auth_key_type = r.take_u8()?.into();
        let auth_key_len = r.take_u16()?;
        let auth_key = r.take(auth_key_len as usize)?.into();
        let extensions = r.extract()?;
        Ok(Self {
            auth_key_type,
            auth_key,
            extensions,
        })
    }
}

impl tor_bytes::Writeable for IntroduceHeader {
    fn write_onto<W: Writer + ?Sized>(&self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&[0_u8; 20]);
        w.write_u8(self.auth_key_type.get());
        w.write_u16(u16::try_from(self.auth_key.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.auth_key[..]);
        w.write(&self.extensions)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
/// A message body shared by Introduce1 and Introduce2
struct Introduce {
    /// The unencrypted header portion of the message.
    header: IntroduceHeader,
    /// Up to end of relay payload.
    encrypted: Vec<u8>,
}

impl Introduce {
    /// All arguments constructor
    fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self {
            header: IntroduceHeader {
                auth_key_type,
                auth_key,
                extensions: Default::default(),
            },
            encrypted,
        }
    }
    /// Decode an Introduce message body from the given reader.
    ///
    /// Return the Introduce message body itself, and the text of the body's header.
    fn decode_from_reader<'a>(r: &mut Reader<'a>) -> Result<(Self, &'a [u8])> {
        let header_start = r.cursor();
        let header = r.extract()?;
        let header_end = r.cursor();
        let encrypted = r.take_rest().into();
        Ok((
            Self { header, encrypted },
            r.range(header_start, header_end),
        ))
    }
    /// Encode an Introduce message body onto the given writer
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.header)?;
        w.write_all(&self.encrypted[..]);
        Ok(())
    }
}

/// A message sent from an onion service to a rendezvous point, telling it to
/// make a connection to the client.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Rendezvous1 {
    /// The cookie originally sent by the client in its ESTABLISH_REND message.
    cookie: RendCookie,
    /// The message to send the client.
    handshake_info: Vec<u8>,
}

impl Body for Rendezvous1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        let handshake_info = r.take_rest().into();
        Ok(Self {
            cookie,
            handshake_info,
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.cookie)?;
        w.write_all(&self.handshake_info[..]);
        Ok(())
    }
}

impl Rendezvous1 {
    /// Create a new Rendezvous1 message, to handshake with a client identified
    /// by a given RendCookie, and send it a given message.
    pub fn new(cookie: RendCookie, handshake_info: impl Into<Vec<u8>>) -> Self {
        Self {
            cookie,
            handshake_info: handshake_info.into(),
        }
    }
}

/// A message sent from the rendezvous point to the client, telling it about the
/// onion service's message.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Rendezvous2 {
    /// The handshake message from the onion service.
    handshake_info: Vec<u8>,
}

impl Rendezvous2 {
    /// Construct a new Rendezvous2 cell containing a given handshake message.
    pub fn new(handshake_info: impl Into<Vec<u8>>) -> Self {
        Self {
            handshake_info: handshake_info.into(),
        }
    }

    /// Return the body of this Rendezvous2 cell. (That is, the handshake
    /// message from the onion service.)
    pub fn handshake_info(&self) -> &[u8] {
        &self.handshake_info
    }
}

impl From<Rendezvous1> for Rendezvous2 {
    fn from(value: Rendezvous1) -> Self {
        Self {
            handshake_info: value.handshake_info,
        }
    }
}

impl Body for Rendezvous2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake_info = r.take_rest().into();
        Ok(Self { handshake_info })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.handshake_info[..]);
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
    #[derive(Debug,Clone,Deftly)]
    #[derive_deftly(HasMemoryCost)]
    #[non_exhaustive]
    pub enum IntroEstablishedExt [ IntroEstablishedExtType ] {
    }
}

/// Reply sent from the introduction point to the onion service, telling it that
/// an introduction point is now established.
#[derive(Debug, Clone, Default, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct IntroEstablished {
    /// The extensions included in this cell.
    extensions: ExtList<IntroEstablishedExt>,
}

impl IntroEstablished {
    /// Create a new IntroEstablished message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return an iterator over the extensions declared in this message.
    pub fn iter_extensions(&self) -> impl Iterator<Item = &IntroEstablishedExt> {
        self.extensions.iter()
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
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
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
    #[derive(Ord, PartialOrd, Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct IntroduceAckExtType(u8) {
    }
}
decl_extension_group! {
    /// An extension to an IntroduceAct message.
    ///
    /// (Currently, no extensions of this type are recognized.)
    #[derive(Debug,Clone,Deftly)]
    #[derive_deftly(HasMemoryCost)]
    enum IntroduceAckExt [ IntroduceAckExtType ] {
    }
}

/// A reply from the introduction point to the client, telling it that its
/// introduce1 was received.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
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

    /// Checks whether the introduction was a success
    ///
    /// If introduction was forwarded successfully,
    /// returns an `Ok<IntroduceAck>`, whose `.status()` can safely be ignored.
    /// (The extension list may still be of interest.)
    ///
    /// Otherwise, returns `Err<IntroduceAckStatus>`,
    /// which is suitable for error reporting purposes.
    pub fn success(self) -> std::result::Result<IntroduceAck, IntroduceAckStatus> {
        if self.status() == IntroduceAckStatus::SUCCESS {
            Ok(self)
        } else {
            Err(self.status())
        }
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

/// When to maybe retry introduction to the *same service* at the *same introduction point*.
///
/// (Using this on `IntroduceAckStatus::SUCCESS` is a mistake;
/// if you do that you'll not get a meaningful retry time, but it won't panic.)
impl tor_error::HasRetryTime for IntroduceAckStatus {
    fn retry_time(&self) -> tor_error::RetryTime {
        use tor_error::RetryTime as RT;
        use IntroduceAckStatus as S;
        match *self {
            S::SUCCESS => RT::Never, // this is a bug
            S::NOT_RECOGNIZED => RT::AfterWaiting,
            S::BAD_MESSAGE_FORMAT => RT::Never,
            S::CANT_RELAY => RT::AfterWaiting,
            _ => RT::AfterWaiting, // who knows?
        }
    }
}

super::msg::empty_body! {
    /// Acknowledges an EstablishRendezvous message.
    pub struct RendezvousEstablished {}
}
