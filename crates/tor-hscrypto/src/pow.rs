//! Proof of Work schemes for onion services
//!
//! Tor supports optional proof-of-work client puzzles, for mitigating denial of
//! service attacks on onion services. This crate implements the specific puzzle
//! algorithms we use, and components for client and service integration.
//!
//! There is infrastructure to support new algorithms over time, but right now
//! only a single algorithm is defined, named [`v1`] and implemented via the
//! [`equix`] crate.
//!
//! Specification at: <https://spec.torproject.org/hspow-spec/index.html>
//!
//! Disabled with default crate features. All schemes can be included
//! with the `pow` feature, or schemes can be selected individually (`pow-v1`).

mod err;

pub use err::{Error, RuntimeError, SolutionError};

#[cfg(feature = "pow-v1")]
pub mod v1;
