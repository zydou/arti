//! Verifier implementation for v1 client puzzles

use crate::v1::challenge::Challenge;
use crate::v1::{Instance, RuntimeError, RuntimeOption, Solution, SolutionError};
use crate::Error;
use equix::{EquiXBuilder, HashError};

/// Checker for potential [`Solution`]s to a particular puzzle [`Instance`]
///
/// Holds information about the puzzle instance, and optional configuration
/// settings.
pub struct Verifier {
    /// The puzzle instance we're verifying
    instance: Instance,
    /// Configuration settings for Equi-X, as an [`EquiXBuilder`] instance
    equix: EquiXBuilder,
}

impl Verifier {
    /// Construct a new [`Verifier`] by wrapping an [`Instance`]
    pub fn new(instance: Instance) -> Self {
        Self {
            instance,
            equix: Default::default(),
        }
    }

    /// Select the HashX runtime to use for this verifier.
    ///
    /// By default, uses [`RuntimeOption::TryCompile`]
    pub fn runtime(&mut self, option: RuntimeOption) -> &mut Self {
        self.equix.runtime(option);
        self
    }

    /// Check whether a solution is valid for this puzzle instance
    ///
    /// May return a [`SolutionError`] or a [`RuntimeError`]
    pub fn check(&self, solution: &Solution) -> Result<(), Error> {
        match self.check_seed(solution) {
            Err(e) => Err(Error::BadSolution(e.into())),
            Ok(()) => {
                let challenge = Challenge::new(&self.instance, solution.effort(), solution.nonce());
                match challenge.check_effort(&solution.proof_to_bytes()) {
                    Err(e) => Err(Error::BadSolution(e.into())),
                    Ok(()) => match self.equix.verify(challenge.as_ref(), solution.proof()) {
                        Ok(()) => Ok(()),
                        Err(equix::Error::HashSum) => {
                            Err(Error::BadSolution(SolutionError::HashSum.into()))
                        }
                        Err(equix::Error::Hash(HashError::ProgramConstraints)) => Err(
                            Error::BadSolution(SolutionError::ChallengeConstraints.into()),
                        ),
                        Err(e) => Err(Error::VerifyRuntime(RuntimeError::EquiX(e).into())),
                    },
                }
            }
        }
    }

    /// Check the [`super::SeedHead`] of a solution against an [`Instance`].
    ///
    /// This is a very cheap test, this should come first so a service
    /// can verify every [`Solution`] against its last two [`Instance`]s.
    fn check_seed(&self, solution: &Solution) -> Result<(), SolutionError> {
        if solution.seed_head() == self.instance.seed().head() {
            Ok(())
        } else {
            Err(SolutionError::Seed)
        }
    }
}
