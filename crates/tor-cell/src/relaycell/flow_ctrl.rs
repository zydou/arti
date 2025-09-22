//! Cells for flow control (excluding "sendme" cells).

use std::num::NonZero;

use derive_deftly::Deftly;
use tor_bytes::{EncodeResult, Error, Reader, Writer};
use tor_memquota::derive_deftly_template_HasMemoryCost;

use crate::relaycell::msg::Body;

/// An `XON` relay message.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Xon {
    /// Cell `version` field.
    version: FlowCtrlVersion,
    /// Cell `kbps_ewma` field.
    kbps_ewma: XonKbpsEwma,
}

/// An `XOFF` relay message.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Xoff {
    /// Cell `version` field.
    version: FlowCtrlVersion,
}

impl Xon {
    /// Construct a new [`Xon`] cell.
    pub fn new(version: FlowCtrlVersion, kbps_ewma: XonKbpsEwma) -> Self {
        Self { version, kbps_ewma }
    }

    /// Return the version.
    pub fn version(&self) -> FlowCtrlVersion {
        self.version
    }

    /// Return the rate limit in kbps.
    pub fn kbps_ewma(&self) -> XonKbpsEwma {
        self.kbps_ewma
    }
}

impl Body for Xon {
    fn decode_from_reader(r: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let version = r.take_u8()?;

        let version = match FlowCtrlVersion::new(version) {
            Ok(x) => x,
            Err(UnrecognizedVersionError) => {
                return Err(Error::InvalidMessage("Unrecognized XON version.".into()));
            }
        };

        let kbps_ewma = XonKbpsEwma::decode(r.take_u32()?);

        Ok(Self::new(version, kbps_ewma))
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(*self.version);
        w.write_u32(self.kbps_ewma.encode());
        Ok(())
    }
}

impl Xoff {
    /// Construct a new [`Xoff`] cell.
    pub fn new(version: FlowCtrlVersion) -> Self {
        Self { version }
    }

    /// Return the version.
    pub fn version(&self) -> FlowCtrlVersion {
        self.version
    }
}

impl Body for Xoff {
    fn decode_from_reader(r: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let version = r.take_u8()?;

        let version = match FlowCtrlVersion::new(version) {
            Ok(x) => x,
            Err(UnrecognizedVersionError) => {
                return Err(Error::InvalidMessage("Unrecognized XOFF version.".into()));
            }
        };

        Ok(Self::new(version))
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(*self.version);
        Ok(())
    }
}

/// A recognized flow control version.
#[derive(Copy, Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct FlowCtrlVersion(u8);

impl FlowCtrlVersion {
    /// Version 0, which is currently the only known version.
    pub const V0: Self = Self(0);

    /// If `version` is a recognized XON/XOFF version, returns a new [`FlowCtrlVersion`].
    pub const fn new(version: u8) -> Result<Self, UnrecognizedVersionError> {
        if version != 0 {
            return Err(UnrecognizedVersionError);
        }

        Ok(Self(version))
    }
}

impl TryFrom<u8> for FlowCtrlVersion {
    type Error = UnrecognizedVersionError;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        Self::new(x)
    }
}

impl std::ops::Deref for FlowCtrlVersion {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The XON/XOFF cell version was not recognized.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UnrecognizedVersionError;

/// The `kbps_ewma` field of an XON cell.
#[derive(Copy, Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[allow(clippy::exhaustive_enums)]
pub enum XonKbpsEwma {
    /// Stream is rate limited to the value in kbps.
    Limited(NonZero<u32>),
    /// Stream is not rate limited.
    Unlimited,
}

impl XonKbpsEwma {
    /// Decode the `kbps_ewma` field of an XON cell.
    fn decode(kbps_ewma: u32) -> Self {
        // prop-324:
        // > In `xon_cell`, a zero value for `kbps_ewma` means that the stream's rate is unlimited.
        match NonZero::new(kbps_ewma) {
            Some(x) => Self::Limited(x),
            None => Self::Unlimited,
        }
    }

    /// Encode as the `kbps_ewma` field of an XON cell.
    fn encode(&self) -> u32 {
        // prop-324:
        // > In `xon_cell`, a zero value for `kbps_ewma` means that the stream's rate is unlimited.
        match self {
            Self::Limited(x) => x.get(),
            Self::Unlimited => 0,
        }
    }
}

impl std::fmt::Display for XonKbpsEwma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limited(rate) => write!(f, "{rate} kbps"),
            Self::Unlimited => write!(f, "unlimited"),
        }
    }
}
