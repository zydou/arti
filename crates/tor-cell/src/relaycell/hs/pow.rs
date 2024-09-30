//! Support for the proof-of-work intro payload extension

#[cfg(feature = "hs-pow-v1")]
pub mod v1;

use super::ext::Ext;
use super::intro_payload::IntroPayloadExtType;
use caret::caret_int;
use tor_bytes::{EncodeResult, Reader, Result, Writer};

/// Extention to provide a proof of work for denial of service mitigation
///
/// Documented at <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO1_POW_EXT>
///
/// The extension has a variable format depending on the specific scheme that was chosen.
///
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProofOfWork {
    /// A potential solution using the `v1` scheme
    #[cfg(feature = "hs-pow-v1")]
    V1(v1::ProofOfWorkV1),
    /// A potential solution with unrecognized scheme
    Unknown(u8),
}

impl Ext for ProofOfWork {
    type Id = IntroPayloadExtType;

    fn type_id(&self) -> IntroPayloadExtType {
        IntroPayloadExtType::PROOF_OF_WORK
    }

    fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
        let version = b.take_u8()?;
        #[cfg(feature = "hs-pow-v1")]
        if version == ProofOfWorkType::V1.get() {
            return Ok(ProofOfWork::V1(v1::ProofOfWorkV1::take_body_from(b)?));
        }
        Ok(ProofOfWork::Unknown(version))
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        match self {
            #[cfg(feature = "hs-pow-v1")]
            ProofOfWork::V1(v1) => {
                b.write_u8(ProofOfWorkType::V1.get());
                v1.write_body_onto(b)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

caret_int! {
    /// Recognized numeric codes for the scheme-specific [`ProofOfWork`] formats
    #[non_exhaustive]
    pub struct ProofOfWorkType(u8) {
        /// Solution for the `v1` scheme
        V1 = 1,
    }
}
