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
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod compiler;
mod constraints;
mod err;
mod generator;
mod program;
mod rand;
mod register;
mod scheduler;
mod siphash;

use crate::compiler::{Architecture, Executable};
use crate::program::Program;
use rand_core::RngCore;

pub use crate::err::{CompilerError, Error};
pub use crate::rand::SipRand;
pub use crate::siphash::SipState;

/// Option for selecting a HashX runtime
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuntimeOption {
    /// Choose the interpreted runtime, without trying the compiler at all.
    InterpretOnly,
    /// Choose the compiled runtime only, and fail if it experiences any errors.
    CompileOnly,
    /// Always try the compiler first but fall back to the interpreter on error.
    /// (This is the default)
    #[default]
    TryCompile,
}

/// Effective HashX runtime for a constructed program
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Runtime {
    /// The interpreted runtime is active.
    Interpret,
    /// The compiled runtime is active.
    Compiled,
}

/// Pre-built hash program that can be rapidly computed with different inputs
///
/// The program and initial state representation are not specified in this
/// public interface, but [`std::fmt::Debug`] can describe program internals.
#[derive(Debug)]
pub struct HashX {
    /// Keys used to generate an initial register state from the hash input
    ///
    /// Half of the key material generated from seed bytes go into the random
    /// program generator, and the other half are saved here for use in each
    /// hash invocation.
    register_key: SipState,

    /// A prepared randomly generated hash program
    ///
    /// In compiled runtimes this will be executable code, and in the
    /// interpreter it's a list of instructions. There is no stable API for
    /// program information, but the Debug trait will list programs in either
    /// format.
    program: RuntimeProgram,
}

/// Combination of [`Runtime`] and the actual program info used by that runtime
///
/// All variants of [`RuntimeProgram`] use some kind of inner heap allocation
/// to store the program data.
#[derive(Debug)]
enum RuntimeProgram {
    /// Select the interpreted runtime, and hold a Program for it to run.
    Interpret(Program),
    /// Select the compiled runtime, and hold an executable code page.
    Compiled(Executable),
}

impl HashX {
    /// The maximum available output size for [`Self::hash_to_bytes()`]
    pub const FULL_SIZE: usize = 32;

    /// Generate a new hash function with the supplied seed.
    pub fn new(seed: &[u8]) -> Result<Self, Error> {
        HashXBuilder::new().build(seed)
    }

    /// Check which actual program runtime is in effect.
    ///
    /// By default we try to generate code at runtime to accelerate the hash
    /// function, but we fall back to an interpreter if this fails. The compiler
    /// can be disabled entirely using [`RuntimeOption::InterpretOnly`] and
    /// [`HashXBuilder`].
    pub fn runtime(&self) -> Runtime {
        match &self.program {
            RuntimeProgram::Interpret(_) => Runtime::Interpret,
            RuntimeProgram::Compiled(_) => Runtime::Compiled,
        }
    }

    /// Calculate the first 64-bit word of the hash, without converting to bytes.
    pub fn hash_to_u64(&self, input: u64) -> u64 {
        self.hash_to_regs(input).digest(self.register_key)[0]
    }

    /// Calculate the hash function at its full output width, returning a fixed
    /// size byte array.
    pub fn hash_to_bytes(&self, input: u64) -> [u8; Self::FULL_SIZE] {
        let words = self.hash_to_regs(input).digest(self.register_key);
        let mut bytes = [0_u8; Self::FULL_SIZE];
        for word in 0..words.len() {
            bytes[word * 8..(word + 1) * 8].copy_from_slice(&words[word].to_le_bytes());
        }
        bytes
    }

    /// Common setup for hashes with any output format
    #[inline(always)]
    fn hash_to_regs(&self, input: u64) -> register::RegisterFile {
        let mut regs = register::RegisterFile::new(self.register_key, input);
        match &self.program {
            RuntimeProgram::Interpret(program) => program.interpret(&mut regs),
            RuntimeProgram::Compiled(executable) => executable.invoke(&mut regs),
        }
        regs
    }
}

/// Builder for creating [`HashX`] instances with custom settings
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HashXBuilder {
    /// Current runtime() setting for this builder
    runtime: RuntimeOption,
}

impl HashXBuilder {
    /// Create a new [`HashXBuilder`] with default settings.
    ///
    /// Immediately calling [`Self::build()`] would be equivalent to using
    /// [`HashX::new()`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Select a new [`RuntimeOption`].
    pub fn runtime(&mut self, runtime: RuntimeOption) -> &mut Self {
        self.runtime = runtime;
        self
    }

    /// Build a [`HashX`] instance with a seed and the selected options.
    pub fn build(&self, seed: &[u8]) -> Result<HashX, Error> {
        let (key0, key1) = SipState::pair_from_seed(seed);
        let mut rng = SipRand::new(key0);
        self.build_from_rng(&mut rng, key1)
    }

    /// Build a [`HashX`] instance from an arbitrary [`RngCore`] and
    /// a [`SipState`] key used for initializing the register file.
    pub fn build_from_rng<R: RngCore>(
        &self,
        rng: &mut R,
        register_key: SipState,
    ) -> Result<HashX, Error> {
        let program = Program::generate(rng)?;
        self.build_from_program(program, register_key)
    }

    /// Build a [`HashX`] instance from an already-generated [`Program`] and
    /// [`SipState`] key.
    ///
    /// The program is either stored as-is or compiled, depending on the current
    /// [`RuntimeOption`]. Requires a program as well as a [`SipState`] to be
    /// used for initializing the register file.
    fn build_from_program(&self, program: Program, register_key: SipState) -> Result<HashX, Error> {
        Ok(HashX {
            register_key,
            program: match self.runtime {
                RuntimeOption::InterpretOnly => RuntimeProgram::Interpret(program),
                RuntimeOption::CompileOnly => {
                    RuntimeProgram::Compiled(Architecture::compile((&program).into())?)
                }
                RuntimeOption::TryCompile => match Architecture::compile((&program).into()) {
                    Ok(exec) => RuntimeProgram::Compiled(exec),
                    Err(_) => RuntimeProgram::Interpret(program),
                },
            },
        })
    }
}
