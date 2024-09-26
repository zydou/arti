//! `v1` client puzzle using [`equix`]
//!
//! This was the first proof-of-work scheme defined for Tor, and currently it's the only one we
//! have.
//!
//! Originally defined in proposal 327, and now part of the main specification:
//! <https://spec.torproject.org/hspow-spec/index.html>

mod challenge;
mod err;
mod solve;
mod types;
mod verify;

pub use equix::{RuntimeOption, SolutionByteArray};
pub use err::{RuntimeErrorV1, SolutionErrorV1};
pub use solve::{Solver, SolverInput};
pub use types::*;
pub use verify::Verifier;
