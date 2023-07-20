//! Error types for the `equix` crate

pub use hashx::Error as HashError;

/// Errors applicable to constructing and verifying Equi-X puzzles
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Errors inherited from [`hashx`]
    ///
    /// Notably, [`HashError::ProgramConstraints`] needs to be handled
    /// by any program which generates new challenge strings, and
    /// [`HashError::Compiler`] may show up if you've chosen
    /// [`crate::RuntimeOption::CompileOnly`] via [`crate::EquiXBuilder`].
    #[error("hash construction error: {0}")]
    Hash(#[from] HashError),

    /// A solution does not meet Equi-X's ordering requirements.
    ///
    /// This error occurs independently of the specific challenge
    /// string. The lexicographic ordering constraints of a well
    /// formed Equi-X solution were not met.
    #[error("failed order constraint, Equi-X solution is not well formed")]
    Order,

    /// Failed hash sum verification of a challenge and solution.
    ///
    /// The tree of hash sums computed from the solution and challenge
    /// are required to have a number of low bits zeroed on each level.
    /// One of these tests failed, and the solution is not valid.
    #[error("failed to verify hash sum constraints for a specific Equi-X challenge and solution")]
    HashSum,
}
