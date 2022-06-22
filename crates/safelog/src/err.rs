//! Declare an error type.

/// An error returned when attempting to enforce or disable safe logging.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Tried to call [`disable_safe_logging`](crate::disable_safe_logging), but
    /// `enforce_safe_logging` was already called.
    #[error("Cannot enable unsafe logging: safe logging is already enforced")]
    AlreadySafe,

    /// Tried to call [`enforce_safe_logging`](crate::enforce_safe_logging), but
    /// `disable_safe_logging` was already called.
    #[error("Cannot enforce safe logging: unsafe logging is already enabled")]
    AlreadyUnsafe,

    /// One of the `enable`/`disable` functions was called so many times that we
    /// could not keep count of how many guards there were.
    ///
    /// This should generally be impossible, and probably represents an error in
    /// your program.
    #[error("Too many calls to enforce or disable safe logging")]
    Overflow,
}
