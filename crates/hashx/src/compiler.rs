//! Architecture-specific compiled implementations for HashX
//!
//! This module provides a consistent interface across configurations and
//! targets via the [`Executable`] struct and the [`Architecture`] trait.
//! When the compiler is unavailable, an `Executable` is empty and the
//! `Architecture` is defined here as a stub implementation. Otherwise, the
//! `Executable` wraps a mmap buffer from the `dynasmrt` crate and the
//! `Architecture` is implemented in a CPU-specific way.

use crate::{CompilerError, program::InstructionArray, register::RegisterFile};

#[cfg(all(feature = "compiler", target_arch = "x86_64"))]
mod x86_64;

#[cfg(all(feature = "compiler", target_arch = "aarch64"))]
mod aarch64;

#[cfg(all(
    feature = "compiler",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod util;

/// Wrapper for a compiled program, empty when compiler support is disabled
pub(crate) struct Executable {
    /// Mapped memory, read-only and executable
    ///
    /// On platforms with compiler support, this item is present.
    /// If the compiler is unavailable, Executable will be empty.
    #[cfg(all(
        feature = "compiler",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    buffer: util::ExecutableBuffer,
}

/// Default implementation for [`Architecture`], used
/// when the compiler is disabled or the target architecture is unsupported
#[cfg(any(
    not(feature = "compiler"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
impl Architecture for Executable {
    fn compile(_program: &InstructionArray) -> Result<Self, CompilerError> {
        Err(CompilerError::NotAvailable)
    }

    fn invoke(&self, _regs: &mut RegisterFile) {
        unreachable!();
    }
}

/// Default implementation for [`Debug`] on [`Executable`], when the compiler
/// is currently disabled or unsupported on the target
///
/// There should never be an [`Executable`] instance in these cases.
/// Always panics.
#[cfg(any(
    not(feature = "compiler"),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
impl std::fmt::Debug for Executable {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

/// Trait that adds architecture-specific functionality to Executable
pub(crate) trait Architecture
where
    Self: Sized,
{
    /// Compile an array of instructions into an Executable
    fn compile(program: &InstructionArray) -> Result<Self, CompilerError>;

    /// Run the compiled code, with a RegisterFile for input and output
    fn invoke(&self, regs: &mut RegisterFile);
}
