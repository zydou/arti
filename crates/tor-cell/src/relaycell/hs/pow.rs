//! Support for the proof-of-work intro payload extension

use super::ext::Ext;
use super::intro_payload::IntroPayloadExtType;
use caret::caret_int;
use tor_bytes::{EncodeResult, Readable, Reader, Result, Writeable, Writer};

/// Extention to provide a proof of work for denial of service mitigation
///
/// Documented at <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO1_POW_EXT>
///
/// The extension has a variable format depending on the specific scheme that was chosen.
///
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ProofOfWork {
    /// A potential solution using the `v1` scheme
    V1(ProofOfWorkV1),
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
        if version == ProofOfWorkType::V1.get() {
            Ok(ProofOfWork::V1(ProofOfWorkV1::take_body_from(b)?))
        } else {
            Ok(ProofOfWork::Unknown(version))
        }
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        match self {
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

/// Proof of work using the `v1` scheme
///
/// Specified as part of <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO1_POW_EXT>
#[derive(derive_more::Constructor, amplify::Getters)] //
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)] //
pub struct ProofOfWorkV1 {
    /// Nonce value chosen by the client
    #[getter(as_ref)]
    nonce: [u8; 16],
    /// Effort chosen by the client
    #[getter(as_copy)]
    effort: u32,
    /// Header with which to identify the applicable service-provided seed
    #[getter(as_copy)]
    seed: [u8; 4],
    /// Proposed solution proof, not validated
    #[getter(as_ref)]
    solution: [u8; 16],
}

impl ProofOfWorkV1 {
    /// Read the scheme-specific portion of a v1 Proof Of Work intro payload extension
    fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            nonce: Readable::take_from(b)?,
            effort: Readable::take_from(b)?,
            seed: Readable::take_from(b)?,
            solution: Readable::take_from(b)?,
        })
    }

    /// Write the scheme-specific portion of a v1 Proof Of Work intro payload extension
    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        self.nonce.write_onto(b)?;
        self.effort.write_onto(b)?;
        self.seed.write_onto(b)?;
        self.solution.write_onto(b)?;
        Ok(())
    }
}
