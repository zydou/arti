//! Define the ESTABLISH_INTRO message and related types.

use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Readable, Reader, Result, Writeable, Writer};
use tor_units::BoundedInt32;

use crate::relaycell::{hs::ext::*, hs::AuthKeyType, msg};

caret_int! {
    /// The introduction protocol extension type
    #[derive(Ord, PartialOrd)]
    pub struct EstIntroExtType(u8) {
        /// The extension used to send DoS parameters
        DOS_PARAMS = 1,
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
pub struct DosParams {
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

impl DosParams {
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

impl Ext for DosParams {
    type Id = EstIntroExtType;
    fn type_id(&self) -> EstIntroExtType {
        EstIntroExtType::DOS_PARAMS
    }
    fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
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
    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
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

decl_extension_group! {
    /// An extension to an EstablishIntro cell.
    #[derive(Debug,Clone)]
    enum EstablishIntroExt [ EstIntroExtType ] {
        DosParams,
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
    /// A list of extensions on this cell.
    extensions: ExtList<EstablishIntroExt>,
    /// the MAC of all earlier fields in the cell.
    handshake_auth: [u8; 32],
    /// A signature using `auth_key` of all contents
    /// of the cell.
    sig: Vec<u8>,
}

impl msg::Body for EstablishIntro {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let auth_key_type = r.take_u8()?.into();
        let auth_key_len = r.take_u16()?;
        let auth_key = r.take(auth_key_len as usize)?.into();
        let extensions = r.extract()?;
        let handshake_auth = r.extract()?;
        let sig_len = r.take_u16()?;
        let sig = r.take(sig_len as usize)?.into();
        Ok(EstablishIntro {
            auth_key_type,
            auth_key,
            extensions,
            handshake_auth,
            sig,
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(self.auth_key_type.get());
        w.write_u16(u16::try_from(self.auth_key.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.auth_key[..]);
        w.write(&self.extensions)?;
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
            extensions: Default::default(),
        }
    }

    /// Set EST_INTRO_DOS_EXT with given `extension_dos`.
    pub fn set_extension_dos(&mut self, extension_dos: DosParams) {
        self.extensions.replace_by_type(extension_dos.into());
    }

    /// Add an extension of some other type.
    pub fn set_extension_other(&mut self, other: UnrecognizedExt<EstIntroExtType>) {
        self.extensions.replace_by_type(other.into());
    }

    // TODO hs: we'll need accessors.
    //
    // TODO hs: we will need some way to ensure that the mac is valid and well-signed.  Possibly
    // we should look into using a SignatureGated (if we can reasonably do so?)
}
