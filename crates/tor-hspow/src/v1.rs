//! Version 1 client puzzle from [Proposal 327], using [`equix`]
//!
//! [Proposal 327]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/327-pow-over-intro.txt

mod challenge;
mod err;
mod solve;
mod types;
mod verify;

pub use equix::{RuntimeOption, SolutionByteArray};
pub use err::{RuntimeError, SolutionError};
pub use solve::{Solver, SolverInput};
pub use types::*;
pub use verify::Verifier;
