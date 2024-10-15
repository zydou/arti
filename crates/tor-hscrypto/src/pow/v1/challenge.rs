//! Implement the `v1` scheme's challenge string format
//!
//! This is a packed byte-string which encodes our puzzle's parameters
//! as inputs for Equi-X. We need to construct challenge strings both to
//! solve and to verify puzzles.

use crate::pow::v1::{
    err::SolutionErrorV1, types::Effort, types::Instance, types::Nonce, types::Seed,
    types::NONCE_LEN, types::SEED_LEN,
};
use arrayvec::{ArrayVec, CapacityError};
use blake2::{digest::consts::U4, Blake2b, Digest};

/// Algorithm personalization string (P)
///
/// This becomes part of the challenge string, binding a puzzle solution to
/// this particular algorithm even if other similar protocols exist using
/// the same building blocks.
const P_STRING: &[u8] = b"Tor hs intro v1\0";

/// Length of the personalization string, in bytes
const P_STRING_LEN: usize = 16;

/// Length of the HsBlindId
const ID_LEN: usize = 32;

/// Location of the [`Seed`] within a [`Challenge`]
const SEED_OFFSET: usize = P_STRING_LEN + ID_LEN;

/// Location of the [`Nonce`] within a [`Challenge`]
const NONCE_OFFSET: usize = SEED_OFFSET + SEED_LEN;

/// Location of the [`Effort`] within a [`Challenge`]
const EFFORT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// Packed length of an [`Effort`], in bytes
const EFFORT_LEN: usize = 4;

/// Total length of our Equi-X challenge string
const CHALLENGE_LEN: usize = EFFORT_OFFSET + EFFORT_LEN;

/// A fully assembled challenge string, with some access to inner fields
///
/// This is the combined input to Equi-X. Defined by Proposal 327
/// as `(P || ID || C || N || INT_32(E))`
#[derive(derive_more::AsRef, Debug, Clone, Eq, PartialEq)]
pub(super) struct Challenge([u8; CHALLENGE_LEN]);

impl Challenge {
    /// Build a new [`Challenge`].
    ///
    /// Copies [`Instance`], [`Effort`], and [`Nonce`] values into
    /// a new byte array.
    pub(super) fn new(instance: &Instance, effort: Effort, nonce: &Nonce) -> Self {
        let mut result = ArrayVec::<u8, CHALLENGE_LEN>::new();
        (|| -> Result<(), CapacityError> {
            result.try_extend_from_slice(P_STRING)?;
            result.try_extend_from_slice(instance.service().as_ref())?;
            assert_eq!(result.len(), SEED_OFFSET);
            result.try_extend_from_slice(instance.seed().as_ref())?;
            assert_eq!(result.len(), NONCE_OFFSET);
            result.try_extend_from_slice(nonce.as_ref())?;
            assert_eq!(result.len(), EFFORT_OFFSET);
            result.try_extend_from_slice(&effort.as_ref().to_be_bytes())
        })()
        .expect("CHALLENGE_LEN holds a full challenge string");
        Self(
            result
                .into_inner()
                .expect("challenge buffer is fully written"),
        )
    }

    /// Clone the [`Seed`] portion of this challenge.
    pub(super) fn seed(&self) -> Seed {
        let array: [u8; SEED_LEN] = self.0[SEED_OFFSET..(SEED_OFFSET + SEED_LEN)]
            .try_into()
            .expect("slice length correct");
        array.into()
    }

    /// Clone the [`Nonce`] portion of this challenge.
    pub(super) fn nonce(&self) -> Nonce {
        let array: [u8; NONCE_LEN] = self.0[NONCE_OFFSET..(NONCE_OFFSET + NONCE_LEN)]
            .try_into()
            .expect("slice length correct");
        array.into()
    }

    /// Return the [`Effort`] used in this challenge.
    pub(super) fn effort(&self) -> Effort {
        u32::from_be_bytes(
            self.0[EFFORT_OFFSET..(EFFORT_OFFSET + EFFORT_LEN)]
                .try_into()
                .expect("slice length correct"),
        )
        .into()
    }

    /// Increment the [`Nonce`] value inside this challenge.
    ///
    /// Note that this will take a different amount of time depending on the
    /// number of bytes affected. There's no timing side channel here: The
    /// timing variation here is swamped by variation in the solver itself,
    /// and the nonce is not a secret value.
    pub(super) fn increment_nonce(&mut self) {
        /// Wrapping increment for a serialized little endian value of arbitrary width.
        fn inc_le_bytes(slice: &mut [u8]) {
            for byte in slice {
                let (value, overflow) = (*byte).overflowing_add(1);
                *byte = value;
                if !overflow {
                    break;
                }
            }
        }
        inc_le_bytes(&mut self.0[NONCE_OFFSET..(NONCE_OFFSET + NONCE_LEN)]);
    }

    /// Verify that a solution proof passes the effort test.
    ///
    /// This computes a Blake2b hash of the challenge and the serialized
    /// Equi-X solution, and tests the result against the effort encoded
    /// in the challenge string.
    ///
    /// Used by both the [`crate::pow::v1::Solver`] and the [`crate::pow::v1::Verifier`].
    pub(super) fn check_effort(
        &self,
        proof: &equix::SolutionByteArray,
    ) -> Result<(), SolutionErrorV1> {
        let mut hasher = Blake2b::<U4>::new();
        hasher.update(self.as_ref());
        hasher.update(proof.as_ref());
        let value = u32::from_be_bytes(hasher.finalize().into());
        match value.checked_mul(*self.effort().as_ref()) {
            Some(_) => Ok(()),
            None => Err(SolutionErrorV1::Effort),
        }
    }
}
