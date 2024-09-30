//! Support for the `v1` proof of work scheme's intro payload extension

use tor_bytes::{EncodeResult, Reader, Result, Writeable, Writer};
use tor_hscrypto::pow::v1::{Effort, Nonce, SeedHead, SolutionByteArray};

/// Proof of work using the `v1` scheme
///
/// Specified as part of <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO1_POW_EXT>
#[derive(derive_more::Constructor, amplify::Getters)] //
#[derive(Debug, Clone, Eq, PartialEq)] //
pub struct ProofOfWorkV1 {
    /// Nonce value chosen by the client
    #[getter(as_ref)]
    nonce: Nonce,
    /// Effort chosen by the client
    #[getter(as_copy)]
    effort: Effort,
    /// Header with which to identify the applicable service-provided seed
    #[getter(as_copy)]
    seed: SeedHead,
    /// Proposed solution proof, not validated
    ///
    /// This byte array still needs to be validated first as a well-formed
    /// Equix solution, and then as a proof for a particular puzzle.
    #[getter(as_ref)]
    solution: SolutionByteArray,
}

impl ProofOfWorkV1 {
    /// Read the scheme-specific portion of a v1 Proof Of Work intro payload extension
    pub(super) fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            nonce: b.extract()?,
            effort: b.extract()?,
            seed: b.extract()?,
            solution: b.extract()?,
        })
    }

    /// Write the scheme-specific portion of a v1 Proof Of Work intro payload extension
    pub(super) fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        self.nonce.write_onto(b)?;
        self.effort.write_onto(b)?;
        self.seed.write_onto(b)?;
        self.solution.write_onto(b)?;
        Ok(())
    }
}
