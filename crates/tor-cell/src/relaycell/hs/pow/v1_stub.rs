//! Stub; `v1` proof of work scheme has been disabled at compile time

use tor_bytes::{EncodeResult, Reader, Result, Writer};
use void::Void;

/// Proof of work using the `v1` scheme, disabled at compile time
///
/// When disabled, the type can be named but it will never be constructed.
/// The reader will generate an [`super::UnrecognizedProofOfWork`] instead.
///
#[derive(Debug, Clone)]
pub struct ProofOfWorkV1(Void);

impl ProofOfWorkV1 {
    /// Stub reader implementation; never matches
    pub(super) fn try_take_body_from(_scheme: u8, _b: &mut Reader<'_>) -> Result<Option<Self>> {
        Ok(None)
    }

    /// Stub writer implementation; uncallable due to void type
    pub(super) fn write_onto<B: Writer + ?Sized>(&self, _b: &mut B) -> EncodeResult<()> {
        void::unreachable(self.0)
    }
}
