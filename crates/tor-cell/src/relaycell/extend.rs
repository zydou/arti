//! Types and encodings used during circuit extension.

use crate::{Error, Result};
use caret::caret_int;
use tor_bytes::{EncodeResult, Readable, Reader, Writeable, Writer};

caret_int! {
    /// A type of ntor v3 extension data (`EXT_FIELD_TYPE`).
    pub struct CircRequestExtType(u8) {
        /// Request congestion control be enabled for a circuit.
        CC_REQUEST = 1,
        /// Acknowledge a congestion control request.
        CC_RESPONSE = 2
    }
}

/// A piece of extension data, to be encoded as the message in an circuit
/// extension (CREATE2) handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CircRequestExt {
    /// Request congestion control be enabled for this circuit (client → exit node).
    ///
    /// (`EXT_FIELD_TYPE` = 01)
    RequestCongestionControl,
    /// Acknowledge a congestion control request (exit node → client).
    ///
    /// (`EXT_FIELD_TYPE` = 02)
    AckCongestionControl {
        /// The exit's current view of the `cc_sendme_inc` consensus parameter.
        sendme_inc: u8,
    },
    /// An unknown piece of extension data.
    Unrecognized {
        /// The extension type (`EXT_FIELD_TYPE`).
        field_type: CircRequestExtType,
        /// The raw bytes of unrecognized extension data.
        data: Vec<u8>,
    },
}

impl CircRequestExt {
    /// Encode a set of extensions into a "message" for an ntor v3 handshake.
    pub fn write_many_onto<W: Writer>(exts: &[CircRequestExt], out: &mut W) -> EncodeResult<()> {
        let n_extensions =
            u8::try_from(exts.len()).map_err(|_| tor_bytes::EncodeError::BadLengthValue)?;
        out.write_u8(n_extensions);
        exts.iter().try_for_each(|x| x.write_onto(out))
    }

    /// Decode a slice of bytes representing the "message" of an ntor v3 handshake into a set of
    /// extensions.
    pub fn decode(message: &[u8]) -> Result<Vec<Self>> {
        let mut reader = Reader::from_slice(message);
        let mut ret = vec![];
        let n_extensions = reader.take_u8().map_err(|e| Error::BytesErr {
            err: e,
            parsed: "n_extensions",
        })?;
        for _ in 0..n_extensions {
            ret.push(
                CircRequestExt::take_from(&mut reader).map_err(|err| Error::BytesErr {
                    err,
                    parsed: "an ntor extension",
                })?,
            );
        }
        if reader.remaining() > 0 {
            return Err(Error::BytesErr {
                err: tor_bytes::Error::ExtraneousBytes,
                parsed: "ntor extensions set",
            });
        }
        Ok(ret)
    }
}

impl Writeable for CircRequestExt {
    fn write_onto<W: Writer + ?Sized>(&self, out: &mut W) -> EncodeResult<()> {
        match self {
            CircRequestExt::RequestCongestionControl => {
                out.write_all(&[1, 0]);
            }
            CircRequestExt::AckCongestionControl { sendme_inc } => {
                out.write_all(&[2, 1, *sendme_inc]);
            }
            CircRequestExt::Unrecognized { field_type, data } => {
                // FIXME(eta): This will break if you try and fill `data` with more than 255 bytes.
                //             This is only a problem if you construct your own `Unrecognized`, though.
                out.write_all(&[field_type.get(), data.len() as u8]);
                out.write_all(data);
            }
        }
        Ok(())
    }
}

impl Readable for CircRequestExt {
    fn take_from(reader: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let tag: CircRequestExtType = reader.take_u8()?.into();
        let len = reader.take_u8()?;
        Ok(match tag {
            CircRequestExtType::CC_REQUEST => {
                if len != 0 {
                    return Err(tor_bytes::Error::InvalidMessage(
                        "invalid length for RequestCongestionControl".into(),
                    ));
                }
                CircRequestExt::RequestCongestionControl
            }
            CircRequestExtType::CC_RESPONSE => {
                if len != 1 {
                    return Err(tor_bytes::Error::InvalidMessage(
                        "invalid length for AckCongestionControl".into(),
                    ));
                }
                let sendme_inc = reader.take_u8()?;
                CircRequestExt::AckCongestionControl { sendme_inc }
            }
            x => {
                let mut data = vec![0; len as usize];
                reader.take_into(&mut data)?;
                CircRequestExt::Unrecognized {
                    field_type: x,
                    data,
                }
            }
        })
    }
}
