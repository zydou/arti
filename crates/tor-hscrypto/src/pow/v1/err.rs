//! Error types local to the `v1` protocol implementation

/// Protocol-specific ways a solution can fail verification
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SolutionErrorV1 {
    /// Mismatch between [`super::SeedHead`] and [`super::Instance`]
    #[error("Solution has an unrecognized Seed value")]
    Seed,
    /// The effort constraint `H(challenge | proof) * effort` failed.
    #[error("Failed to verify solution effort")]
    Effort,
    /// The Equi-X proof is not well-formed, it failed at least one order test.
    #[error("Failed to verify order of Equi-X proof")]
    Order,
    /// The Equi-X proof does not apply to this particular challenge.
    #[error("Failed to verify hash sums for Equi-X proof")]
    HashSum,
    /// Couldn't construct the HashX function
    ///
    /// A working solver should have rejected this [`super::Nonce`] value.
    #[error("Solution requires a challenge string that fails HashX constraints")]
    ChallengeConstraints,
}

/// Protocol-specific runtime errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeErrorV1 {
    /// Unexpected error or runtime compiler error from the Equi-X layer
    #[error("Equi-X error, {0}")]
    EquiX(#[from] equix::Error),
}
