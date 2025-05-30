//! Support for the `v1` proof of work scheme's intro payload extension

use crate::relaycell::hs::pow::ProofOfWorkType;
use tor_bytes::{EncodeResult, Reader, Result, Writeable, Writer};
use tor_hscrypto::pow::v1::{Effort, Nonce, SeedHead, SolutionByteArray};

/// Proof of work using the `v1` scheme
///
/// Specified as part of <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO1_POW_EXT>
#[derive(derive_more::Constructor, amplify::Getters, Debug, Clone, PartialEq)]
pub struct ProofOfWorkV1 {
    /// Nonce value chosen by the client
    #[getter(as_ref)]
    nonce: Nonce,
    /// Effort chosen by the client
    #[getter(as_copy)]
    effort: Effort,
    /// Header with which to identify the applicable service-provided seed
    #[getter(as_copy)]
    seed_head: SeedHead,
    /// Proposed solution proof, not validated
    ///
    /// This byte array still needs to be validated first as a well-formed
    /// Equix solution, and then as a proof for a particular puzzle.
    #[getter(as_ref)]
    solution: SolutionByteArray,
}

impl ProofOfWorkV1 {
    /// Construct by reading the scheme-specific data, if the scheme ID is correct for [`ProofOfWorkV1`]
    pub(super) fn try_take_body_from(scheme: u8, b: &mut Reader<'_>) -> Result<Option<Self>> {
        if scheme == ProofOfWorkType::V1.get() {
            Ok(Some(Self {
                nonce: b.extract()?,
                effort: b.extract()?,
                seed_head: b.extract()?,
                solution: b.extract()?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Write the scheme and scheme-specific portion the v1 Proof Of Work
    pub(super) fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_u8(ProofOfWorkType::V1.get());
        self.nonce.write_onto(b)?;
        self.effort.write_onto(b)?;
        self.seed_head.write_onto(b)?;
        self.solution.write_onto(b)?;
        Ok(())
    }
}
