#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod bucket_array;
mod collision;
mod err;
mod solution;
mod solver;

// Export bucket_array::mem API only to the fuzzer.
// (This is not stable; you should not use it except for testing.)
#[cfg(feature = "bucket-array")]
pub use bucket_array::mem::{BucketArray, BucketArrayMemory, BucketArrayPair, Count, Uninit};

use hashx::{HashX, HashXBuilder};

pub use hashx::{Runtime, RuntimeOption};

pub use err::{Error, HashError};
pub use solution::{Solution, SolutionArray, SolutionByteArray, SolutionItem, SolutionItemArray};
pub use solver::SolverMemory;

/// One Equi-X instance, customized for a challenge string
///
/// This includes pre-computed state that depends on the
/// puzzle's challenge as well as any options set via [`EquiXBuilder`].
#[derive(Debug)]
pub struct EquiX {
    /// HashX instance generated for this puzzle's challenge string
    hash: HashX,
}

impl EquiX {
    /// Make a new [`EquiX`] instance with a challenge string and
    /// default options.
    ///
    /// It's normal for this to fail with a [`HashError::ProgramConstraints`]
    /// for a small fraction of challenge values. Those challenges must be
    /// skipped by solvers and rejected by verifiers.
    pub fn new(challenge: &[u8]) -> Result<Self, Error> {
        EquiXBuilder::new().build(challenge)
    }

    /// Check which actual program runtime is in effect.
    ///
    /// By default we try to generate machine code at runtime to accelerate the
    /// hash function, but we fall back to an interpreter if this fails. The
    /// compiler can be disabled entirely using [`RuntimeOption::InterpretOnly`]
    /// and [`EquiXBuilder`].
    pub fn runtime(&self) -> Runtime {
        self.hash.runtime()
    }

    /// Check a [`Solution`] against this particular challenge.
    ///
    /// Having a [`Solution`] instance guarantees that the order of items
    /// has already been checked. This only needs to check hash tree sums.
    /// Returns either `Ok` or [`Error::HashSum`].
    pub fn verify(&self, solution: &Solution) -> Result<(), Error> {
        solution::check_all_tree_sums(&self.hash, solution)
    }

    /// Search for solutions using this particular challenge.
    ///
    /// Returns a buffer with a variable number of solutions.
    /// Memory for the solver is allocated dynamically and not reused.
    pub fn solve(&self) -> SolutionArray {
        let mut mem = SolverMemory::new();
        self.solve_with_memory(&mut mem)
    }

    /// Search for solutions, using the provided [`SolverMemory`].
    ///
    /// Returns a buffer with a variable number of solutions.
    ///
    /// Allows re-use of solver memory. Preferred for callers which may perform
    /// several solve operations in rapid succession, such as in the common case
    /// of layering an effort adjustment protocol above Equi-X.
    pub fn solve_with_memory(&self, mem: &mut SolverMemory) -> SolutionArray {
        let mut result = Default::default();
        solver::find_solutions(&self.hash, mem, &mut result);
        result
    }
}

/// Builder for creating [`EquiX`] instances with custom settings
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EquiXBuilder {
    /// Inner [`HashXBuilder`] for options related to our hash function
    hash: HashXBuilder,
}

impl EquiXBuilder {
    /// Create a new [`EquiXBuilder`] with default settings.
    ///
    /// Immediately calling [`Self::build()`] would be equivalent to using
    /// [`EquiX::new()`].
    pub fn new() -> Self {
        Self {
            hash: HashXBuilder::new(),
        }
    }

    /// Select a new [`RuntimeOption`].
    pub fn runtime(&mut self, runtime: RuntimeOption) -> &mut Self {
        self.hash.runtime(runtime);
        self
    }

    /// Build an [`EquiX`] instance with a challenge string and the
    /// selected options.
    ///
    /// It's normal for this to fail with a [`HashError::ProgramConstraints`]
    /// for a small fraction of challenge values. Those challenges must be
    /// skipped by solvers and rejected by verifiers.
    pub fn build(&self, challenge: &[u8]) -> Result<EquiX, Error> {
        match self.hash.build(challenge) {
            Err(e) => Err(Error::Hash(e)),
            Ok(hash) => Ok(EquiX { hash }),
        }
    }

    /// Search for solutions to a particular challenge.
    ///
    /// Each solve invocation returns zero or more solutions.
    /// Memory for the solver is allocated dynamically and not reused.
    ///
    /// It's normal for this to fail with a [`HashError::ProgramConstraints`]
    /// for a small fraction of challenge values. Those challenges must be
    /// skipped by solvers and rejected by verifiers.
    pub fn solve(&self, challenge: &[u8]) -> Result<SolutionArray, Error> {
        Ok(self.build(challenge)?.solve())
    }

    /// Check a [`Solution`] against a particular challenge string.
    ///
    /// Having a [`Solution`] instance guarantees that the order of items
    /// has already been checked. This only needs to check hash tree sums.
    /// Returns either `Ok` or [`Error::HashSum`].
    pub fn verify(&self, challenge: &[u8], solution: &Solution) -> Result<(), Error> {
        self.build(challenge)?.verify(solution)
    }

    /// Check a [`SolutionItemArray`].
    ///
    /// Returns an error if the array is not a well formed [`Solution`] or it's
    /// not suitable for the given challenge.
    pub fn verify_array(&self, challenge: &[u8], array: &SolutionItemArray) -> Result<(), Error> {
        // Check Solution validity before we even construct the instance
        self.verify(challenge, &Solution::try_from_array(array)?)
    }

    /// Check a [`SolutionByteArray`].
    ///
    /// Returns an error if the array is not a well formed [`Solution`] or it's
    /// not suitable for the given challenge.
    pub fn verify_bytes(&self, challenge: &[u8], array: &SolutionByteArray) -> Result<(), Error> {
        self.verify(challenge, &Solution::try_from_bytes(array)?)
    }
}

impl Default for EquiXBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Search for solutions, using default [`EquiXBuilder`] options.
///
/// Each solve invocation returns zero or more solutions.
/// Memory for the solver is allocated dynamically and not reused.
///
/// It's normal for this to fail with a [`HashError::ProgramConstraints`] for
/// a small fraction of challenge values. Those challenges must be skipped
/// by solvers and rejected by verifiers.
pub fn solve(challenge: &[u8]) -> Result<SolutionArray, Error> {
    Ok(EquiX::new(challenge)?.solve())
}

/// Check a [`Solution`] against a particular challenge.
///
/// Having a [`Solution`] instance guarantees that the order of items
/// has already been checked. This only needs to check hash tree sums.
/// Returns either `Ok` or [`Error::HashSum`].
///
/// Uses default [`EquiXBuilder`] options.
pub fn verify(challenge: &[u8], solution: &Solution) -> Result<(), Error> {
    EquiX::new(challenge)?.verify(solution)
}

/// Check a [`SolutionItemArray`].
///
/// Returns an error if the array is not a well formed [`Solution`] or it's
/// not suitable for the given challenge.
///
/// Uses default [`EquiXBuilder`] options.
pub fn verify_array(challenge: &[u8], array: &SolutionItemArray) -> Result<(), Error> {
    // Check Solution validity before we even construct the instance
    verify(challenge, &Solution::try_from_array(array)?)
}

/// Check a [`SolutionByteArray`].
///
/// Returns an error if the array is not a well formed [`Solution`] or it's
/// not suitable for the given challenge.
///
/// Uses default [`EquiXBuilder`] options.
pub fn verify_bytes(challenge: &[u8], array: &SolutionByteArray) -> Result<(), Error> {
    // Check Solution validity before we even construct the instance
    verify(challenge, &Solution::try_from_bytes(array)?)
}
