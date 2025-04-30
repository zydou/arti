//! Types and encodings used during circuit extension.

use super::extlist::{decl_extension_group, Ext, ExtList, ExtListRef};
use caret::caret_int;
use tor_bytes::{EncodeResult, Reader, Writeable as _, Writer};

caret_int! {
    /// A type of ntor v3 extension data (`EXT_FIELD_TYPE`).
    #[derive(PartialOrd,Ord)]
    pub struct CircRequestExtType(u8) {
        /// Request congestion control be enabled for a circuit.
        CC_REQUEST = 1,
        /// Acknowledge a congestion control request.
        CC_RESPONSE = 2
    }
}

/// Request congestion control be enabled for this circuit (client → exit node).
///
/// (`EXT_FIELD_TYPE` = 01)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CcRequest {}

impl Ext for CcRequest {
    type Id = CircRequestExtType;
    fn type_id(&self) -> Self::Id {
        CircRequestExtType::CC_REQUEST
    }
    fn take_body_from(_b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        Ok(Self {})
    }
    fn write_body_onto<B: Writer + ?Sized>(&self, _b: &mut B) -> EncodeResult<()> {
        Ok(())
    }
}

/// Acknowledge a congestion control request (exit node → client).
///
/// (`EXT_FIELD_TYPE` = 02)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcResponse {
    /// The exit's current view of the `cc_sendme_inc` consensus parameter.
    sendme_inc: u8,
}

impl CcResponse {
    /// Create a new AckCongestionControl with a given value for the
    /// `sendme_inc` parameter.
    pub fn new(sendme_inc: u8) -> Self {
        CcResponse { sendme_inc }
    }

    /// Return the value of the `sendme_inc` parameter for this extension.
    pub fn sendme_inc(&self) -> u8 {
        self.sendme_inc
    }
}

impl Ext for CcResponse {
    type Id = CircRequestExtType;
    fn type_id(&self) -> Self::Id {
        CircRequestExtType::CC_RESPONSE
    }

    fn take_body_from(b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let sendme_inc = b.take_u8()?;
        Ok(Self { sendme_inc })
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_u8(self.sendme_inc);
        Ok(())
    }
}

decl_extension_group! {
    /// An extension to be sent along with a circuit extension request
    /// (CREATE2, EXTEND2, or INTRODUCE.)
    #[derive(Debug,Clone,Eq,PartialEq)]
    #[non_exhaustive]
    pub enum CircRequestExt [ CircRequestExtType ] {
        /// Request to enable congestion control.
        CcRequest,
        /// Response indicating that congestion control is enabled.
        CcResponse,
    }
}

impl CircRequestExt {
    /// Encode a set of extensions into a "message" for a circuit request.
    pub fn write_many_onto<W: Writer>(exts: &[CircRequestExt], out: &mut W) -> EncodeResult<()> {
        ExtListRef::from(exts).write_onto(out)?;
        Ok(())
    }
    /// Decode a slice of bytes representing the "message" of a circuit request into a set of
    /// extensions.
    pub fn decode(message: &[u8]) -> crate::Result<Vec<Self>> {
        let err_cvt = |err| crate::Error::BytesErr {
            err,
            parsed: "CREATE extension list",
        };
        let mut r = tor_bytes::Reader::from_slice(message);
        let list: ExtList<CircRequestExt> = r.extract().map_err(err_cvt)?;
        r.should_be_exhausted().map_err(err_cvt)?;
        Ok(list.into_vec())
    }
}
