//! Solver implementation for v1 client puzzles

use crate::v1::challenge::Challenge;
use crate::v1::{
    err::RuntimeErrorV1, types::Effort, types::Instance, types::Nonce, types::Solution,
    types::NONCE_LEN,
};
use equix::{EquiXBuilder, HashError, RuntimeOption, SolverMemory};
use rand::{CryptoRng, Rng, RngCore};

/// All inputs necessary to run the [`Solver`]
#[derive(Debug, Clone)]
pub struct SolverInput {
    /// The puzzle instance we're solving
    instance: Instance,
    /// Effort chosen by the client for this solver run
    effort: Effort,
    /// Configuration settings for Equi-X, as an [`EquiXBuilder`] instance
    equix: EquiXBuilder,
}

impl SolverInput {
    /// Construct a [`SolverInput`] by wrapping an [`Instance`].
    pub fn new(instance: Instance, effort: Effort) -> Self {
        SolverInput {
            instance,
            effort,
            equix: Default::default(),
        }
    }

    /// Select the HashX runtime to use for this Solver input.
    ///
    /// By default, uses [`RuntimeOption::TryCompile`].
    pub fn runtime(&mut self, option: RuntimeOption) -> &mut Self {
        self.equix.runtime(option);
        self
    }

    /// Begin solving with this input and a new random [`Nonce`].
    ///
    /// Generates a new random [`Nonce`] using the provided [`Rng`].
    /// May be parallelized if desired, by cloning the [`SolverInput`] first.
    pub fn solve<R: RngCore + CryptoRng>(self, rng: &mut R) -> Solver {
        self.solve_with_nonce(&rng.gen::<[u8; NONCE_LEN]>().into())
    }

    /// Begin solving with a specified [`Nonce`].
    ///
    /// This is not generally useful, but it's great for unit tests if you'd
    /// like to skip to a deterministic location in the search.
    pub fn solve_with_nonce(self, nonce: &Nonce) -> Solver {
        Solver {
            challenge: Challenge::new(&self.instance, self.effort, nonce),
            equix: self.equix,
            mem: SolverMemory::new(),
        }
    }
}

/// Make progress toward finding a [`Solution`].
///
/// Each [`Solver`] instance will own about 1.8 MB of temporary memory until
/// it is dropped. This interface supports cancelling an ongoing solve and it
/// supports multithreaded use, but it requires an external thread pool
/// implementation.
pub struct Solver {
    /// The next assembled [`Challenge`] to try
    challenge: Challenge,
    /// Configuration settings for Equi-X, as an [`EquiXBuilder`] instance
    equix: EquiXBuilder,
    /// Temporary memory for Equi-X to use
    mem: SolverMemory,
}

impl Solver {
    /// Run the solver until it produces a [`Solution`].
    ///
    /// This takes a random amount of time to finish, with no possibility
    /// to cancel early. If you need cancellation, use [`Self::run_step()`]
    /// instead.
    pub fn run(&mut self) -> Result<Solution, RuntimeErrorV1> {
        loop {
            if let Some(solution) = self.run_step()? {
                return Ok(solution);
            }
        }
    }

    /// Run the solver algorithm, returning when we are at a good stopping point.
    ///
    /// Typical durations would be very roughly 10ms with the compiled hash
    /// implementation or 250ms with the interpreted implementation.
    ///
    /// These durations are far too long to include in any event loop
    /// that's not built specifically for blocking operations, but they're
    /// short enough that we still have a chance of cancelling a high-effort
    /// solve. Step duration does not depend on effort choice.
    ///
    /// Internally, this checks only one [`Nonce`] value. That's the only good
    /// stopping point we have in Equi-X right now. If we really need finer
    /// grained cancellation the equix crate could be modified to support
    /// this but at a performance penalty.
    ///
    /// It's possible to call this again after a solution has already
    /// been returned, but the resulting solutions will have nearby [`Nonce`]
    /// values so this is not recommended except for benchmarking.
    pub fn run_step(&mut self) -> Result<Option<Solution>, RuntimeErrorV1> {
        match self.equix.build(self.challenge.as_ref()) {
            Ok(equix) => {
                for candidate in equix.solve_with_memory(&mut self.mem) {
                    if self.challenge.check_effort(&candidate.to_bytes()).is_ok() {
                        return Ok(Some(Solution::new(
                            self.challenge.nonce(),
                            self.challenge.effort(),
                            self.challenge.seed().head(),
                            candidate,
                        )));
                    }
                }
            }
            Err(equix::Error::Hash(HashError::ProgramConstraints)) => (),
            Err(e) => {
                return Err(e.into());
            }
        };
        self.challenge.increment_nonce();
        Ok(None)
    }
}
