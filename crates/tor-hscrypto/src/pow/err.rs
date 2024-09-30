//! Combined error types for any proof of work scheme

#[cfg(feature = "pow-v1")]
use crate::pow::v1::{RuntimeErrorV1, SolutionErrorV1};

/// Error type for the onion service proof of work subsystem
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Solution was incorrect
    ///
    /// In general the detailed reason for failure should be ignored,
    /// and it certainly should not be shared with clients. It's useful
    /// for unit testing and possibly debugging. A particular type of flaw
    /// in a solution could be exposed at a variety of layers in the
    /// verification process depending on luck and algorithm parameters.
    #[error("Incorrect solution to a client puzzle")]
    BadSolution(#[source] SolutionError),

    /// Runtime error while solving a proof of work puzzle
    ///
    /// Something went wrong in the environment to prevent the
    /// solver from completing.
    #[error("Runtime error while solving a client puzzle: {0}")]
    SolveRuntime(#[source] RuntimeError),

    /// Runtime error while verifying a proof of work puzzle
    ///
    /// Something went wrong in the environment to prevent the
    /// verifier from coming to any conclusion.
    #[error("Runtime error while verifying a client puzzle: {0}")]
    VerifyRuntime(#[source] RuntimeError),
}

/// Detailed errors for ways a solution can fail verification
///
/// These errors must not be exposed to clients, who might
/// use them to gain an advantage in computing solutions.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SolutionError {
    /// Solution errors from the `v1` proof of work scheme
    #[cfg(feature = "pow-v1")]
    #[error("V1, {0}")]
    V1(#[from] SolutionErrorV1),
}

/// Detailed runtime errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// Runtime errors from the `v1` proof of work scheme
    #[cfg(feature = "pow-v1")]
    #[error("V1, {0}")]
    V1(#[from] RuntimeErrorV1),
}
