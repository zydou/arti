//! Error types for the `hashx` crate

/// Errors that could occur while building a hash function
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A whole-program constraint in HashX failed, and this particular
    /// seed should be considered unusable and skipped.
    #[error("HashX program can't be constructed for this specific seed")]
    ProgramConstraints,

    /// [`crate::RuntimeOption::CompileOnly`] is in use and the compiler failed
    #[error("HashX compiler failed and no fallback was enabled: {0}")]
    Compiler(#[from] CompilerError),
}

/// Details about a compiler error
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CompilerError {
    /// The compiler was not available for this build configuration
    #[error("There is no HashX compiler implementation available in this configuration")]
    NotAvailable,

    /// Failed to set up the runtime environment, with a [`std::io::Error`]
    #[error("Runtime error while preparing the hash program: {0}")]
    Runtime(#[from] std::io::Error),
}
