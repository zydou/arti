//! Encoding and decoding for relay messages related to onion services.

#![allow(dead_code, unused_variables)] // TODO hs: remove.

// TODO hs design: We need to discuss how we want to handle extensions in these
// cells: extensions are used all over the protocol, and it would be nice to be
// more clever about them.
//
// It would be neat if recognized extension types were decoded into recognized
// structures. On the other hand, it would be good to retain unrecognized
// extension types, so that other code  can use them in the future without having to
// add support here.

// TODO hs: we'll need accessors for the useful fields in all these types.

use super::msg::{self, Body};
use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Error as BytesError, Readable, Result, Writeable};
use tor_bytes::{Reader, Writer};
use tor_hscrypto::RendCookie;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_units::BoundedInt32;

caret_int! {
    /// The type of the introduction point auth key
    pub struct AuthKeyType(u8) {
        /// Ed25519; SHA3-256
        ED25519_SHA3_256 = 2,
    }
}

caret_int! {
    /// The introduction protocol extension type
    pub struct EstIntroExtType(u8) {
        /// The extension used to send DoS parameters
        EST_INTRO_DOS_EXT = 1,
    }
}

caret_int! {
    /// The recognized parameter types in an establish intro
    /// DoS extension.
    pub struct EstIntroExtDosParamType(u8) {
        /// The rate per second of INTRODUCE2 cell relayed
        /// to the service.
        DOS_INTRODUCE2_RATE_PER_SEC = 1,
        /// The burst per second of INTRODUCE2 cell relayed
        /// to the service
        DOS_INTRODUCE2_BURST_PER_SEC = 2,
    }
}

/// An establish Introduction protocol extension
#[derive(Debug, Clone)]
pub struct EstIntroExtDoS {
    /// An optional parameter indicates the rate per second of
    /// INTRODUCE2 cell relayed to the service.
    ///
    /// Min: 0, Max: 2147483647
    rate_per_sec: Option<BoundedInt32<0, { i32::MAX }>>,
    /// An optional parameter indicates the burst per second of
    /// INTRODUCE2 cell relayed to the service
    ///
    /// Min: 0, Max: 2147483647
    burst_per_sec: Option<BoundedInt32<0, { i32::MAX }>>,
}

impl EstIntroExtDoS {
    /// Create a new establish intro DoS extension.
    pub fn new(rate_per_sec: Option<i32>, burst_per_sec: Option<i32>) -> crate::Result<Self> {
        let normalize = |supplied: Option<i32>| -> crate::Result<_> {
            supplied
                .map(|val| {
                    BoundedInt32::checked_new(val).map_err(|_| {
                        crate::err::Error::CantEncode(
                            "EST_INTRO_DOS_EXT parameter value out of bound.",
                        )
                    })
                })
                .transpose()
        };
        Ok(Self {
            rate_per_sec: normalize(rate_per_sec)?,
            burst_per_sec: normalize(burst_per_sec)?,
        })
    }
}

impl Readable for EstIntroExtDoS {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let n_prams = b.take_u8()?;
        let mut rate_per_sec = None;
        let mut burst_per_sec = None;
        for _i in 0..n_prams {
            let param_to_store = match b.take_u8()?.into() {
                EstIntroExtDosParamType::DOS_INTRODUCE2_RATE_PER_SEC => Some(&mut rate_per_sec),
                EstIntroExtDosParamType::DOS_INTRODUCE2_BURST_PER_SEC => Some(&mut burst_per_sec),
                _ => None,
            };
            if let Some(param) = param_to_store {
                if let Ok(rate) = i32::try_from(b.take_u64()?) {
                    *param = BoundedInt32::checked_new(rate).ok();
                }
            }
        }
        Ok(Self {
            rate_per_sec,
            burst_per_sec,
        })
    }
}

impl Writeable for EstIntroExtDoS {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        let mut params = vec![];
        let mut push_params = |ty, value| {
            if let Some(value) = value {
                params.push((ty, value));
            }
        };
        push_params(
            EstIntroExtDosParamType::DOS_INTRODUCE2_RATE_PER_SEC,
            self.rate_per_sec,
        );
        push_params(
            EstIntroExtDosParamType::DOS_INTRODUCE2_BURST_PER_SEC,
            self.burst_per_sec,
        );
        b.write_u8(u8::try_from(params.len()).map_err(|_| EncodeError::BadLengthValue)?);
        for (t, v) in params {
            b.write_u8(t.get());
            b.write_u64(v.get() as u64);
        }
        Ok(())
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
    /// An optional denial-of-service extension.
    //
    // TODO hs: we may want to consider making this a vector of extensions instead,
    // to allow unrecognized extensions?
    extension_dos: Option<EstIntroExtDoS>,
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
        let n_ext = r.take_u8()?;
        let mut extension_dos = None;
        for _ in 0..n_ext {
            let ext_type: EstIntroExtType = r.take_u8()?.into();
            r.read_nested_u8len(|r| {
                if ext_type == EstIntroExtType::EST_INTRO_DOS_EXT {
                    extension_dos.get_or_insert(r.extract()?);
                } else {
                    r.take_rest();
                }
                Ok(())
            })?;
        }
        let handshake_auth = r.extract()?;
        let sig_len = r.take_u16()?;
        let sig = r.take(sig_len as usize)?.into();
        Ok(EstablishIntro {
            auth_key_type,
            auth_key,
            extension_dos,
            handshake_auth,
            sig,
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(self.auth_key_type.get());
        w.write_u16(u16::try_from(self.auth_key.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.auth_key[..]);

        let mut extensions: Vec<(EstIntroExtType, Vec<u8>)> = vec![];
        if let Some(extension_dos) = self.extension_dos {
            let mut extension = vec![];
            extension.write(&extension_dos)?;
            extensions.push((EstIntroExtType::EST_INTRO_DOS_EXT, extension));
        }
        w.write_u8(u8::try_from(extensions.len()).map_err(|_| EncodeError::BadLengthValue)?);
        for (t, v) in extensions {
            w.write_u8(t.get());
            let mut w = w.write_nested_u8len();
            w.write(&v)?;
            w.finish()?;
        }

        w.write_all(&self.handshake_auth[..]);
        w.write_u16(u16::try_from(self.sig.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.sig[..]);
        Ok(())
    }
}

impl EstablishIntro {
    /// All arguments constructor
    pub fn new(
        auth_key_type: AuthKeyType,
        auth_key: Vec<u8>,
        handshake_auth: [u8; 32],
        sig: Vec<u8>,
    ) -> Self {
        Self {
            auth_key_type,
            auth_key,
            handshake_auth,
            sig,
            extension_dos: None,
        }
    }

    /// Set EST_INTRO_DOS_EXT with given `extension_dos`.
    pub fn set_extension_dos(&mut self, extension_dos: EstIntroExtDoS) {
        self.extension_dos = Some(extension_dos);
    }

    // TODO hs: we'll need accessors.
    //
    // TODO hs: we will need some way to ensure that the mac is valid and well-signed.  Possibly
    // we should look into using a SignatureGated (if we can reasonably do so?)
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
    fn into_message(self) -> msg::RelayMsg {
        msg::RelayMsg::EstablishRendezvous(self)
    }
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
    fn into_message(self) -> msg::RelayMsg {
        msg::RelayMsg::Introduce1(self)
    }
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
    fn into_message(self) -> msg::RelayMsg {
        msg::RelayMsg::Introduce2(self)
    }
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
            return Err(BytesError::BadMessage("legacy key id in Introduce1."));
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
    fn into_message(self) -> msg::RelayMsg {
        todo!()
    }

    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// A message sent from the rendezvous point to the client, telling it about the
/// onion service's message.
#[derive(Debug, Clone)]
pub struct Rendezvous2 {
    /// The message from the onion service.
    message: Vec<u8>,
}

impl Body for Rendezvous2 {
    fn into_message(self) -> msg::RelayMsg {
        todo!()
    }

    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// Reply sent from the introduction point to the onion service, telling it that
/// an introduction point is now established.
#[derive(Debug, Clone)]
pub struct IntroEstablished {
    /// The extensions included in this cell.
    //
    // TODO hs: we should extract this with any DOS related extensions, depending on what we
    // decide to do with extension in general.
    extensions: Vec<IntroEstExtension>,
}

impl Body for IntroEstablished {
    fn into_message(self) -> msg::RelayMsg {
        todo!()
    }

    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// An extension included in an [`IntroEstablished`] message.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IntroEstExtension {
    /// An unrecognized extension.
    Unrecognized(Vec<u8>),
}

/// A reply from the introduction point to the client, telling it that its
/// introduce1 was received.
#[derive(Clone, Debug)]
pub struct IntroduceAck {
    // TODO hs: use a caret enum for this.
    /// The status reported for the Introduce1 message.
    status_code: u16,
    // TODO hs: add extensions.
}

impl Body for IntroduceAck {
    fn into_message(self) -> msg::RelayMsg {
        todo!()
    }

    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

super::msg::empty_body! {
    /// Acknowledges an EstablishRendezvous message.
    pub struct RendezvousEstablished {}
}
