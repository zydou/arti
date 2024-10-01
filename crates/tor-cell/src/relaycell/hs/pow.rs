//! Support for the proof-of-work intro payload extension

#[cfg_attr(not(feature = "hs-pow-v1"), path = "pow/v1_stub.rs")]
pub mod v1;

use self::v1::ProofOfWorkV1;
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProofOfWork {
    /// A potential solution with unrecognized scheme
    Unrecognized(UnrecognizedProofOfWork),
    /// A potential solution using the `v1` scheme
    V1(v1::ProofOfWorkV1),
}

impl Ext for ProofOfWork {
    type Id = IntroPayloadExtType;

    fn type_id(&self) -> IntroPayloadExtType {
        IntroPayloadExtType::PROOF_OF_WORK
    }

    fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
        let scheme = b.take_u8()?;
        if let Some(v1) = ProofOfWorkV1::try_take_body_from(scheme, b)? {
            return Ok(ProofOfWork::V1(v1));
        }
        Ok(ProofOfWork::Unrecognized(
            UnrecognizedProofOfWork::take_body_from(scheme, b),
        ))
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        match self {
            ProofOfWork::V1(v1) => v1.write_onto(b),
            ProofOfWork::Unrecognized(unrecognized) => {
                unrecognized.write_onto(b);
                Ok(())
            }
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

/// A proof of work with unknown scheme
///
/// The reader needs a way to represent future schemes when we can't fail to parse.
/// This is similar to [`super::UnrecognizedExt`], but specific to an unrecognized scheme
/// within a known type of extension.
///
#[derive(Debug, Clone, Eq, PartialEq, amplify::Getters, derive_more::Constructor)]
pub struct UnrecognizedProofOfWork {
    /// The `scheme` byte
    ///
    /// Intended usage is that this won't be any of the known `ProofOfWorkType`
    /// values. We don't strictly verify this, to avoid breaking the API every
    /// time a new type is added.
    ///
    #[getter(as_copy)]
    scheme: u8,
    /// Arbitrary contents with an unknown format
    #[getter(as_ref)]
    data: Vec<u8>,
}

impl UnrecognizedProofOfWork {
    /// Construct by taking the remaining scheme-specific unknown data
    pub(super) fn take_body_from(scheme: u8, b: &mut Reader<'_>) -> Self {
        Self::new(scheme, b.take_rest().to_vec())
    }

    /// Write the unrecognized proof's scheme and data
    pub(super) fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_u8(self.scheme());
        b.write_all(self.data());
    }
}
