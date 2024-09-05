//! Declare tor relay specific errors.

use std::fmt::{self, Display};

use thiserror::Error;
use tor_error::{ErrorKind, HasKind};

/// Main high-level error type for the Arti Tor relay.
///
/// If you need to handle different types of errors differently, use the
/// [`kind`](`tor_error::HasKind::kind`) trait method to check what kind of
/// error it is.
///
/// Note that although this type implements that standard
/// [`Error`](trait@std::error::Error) trait, the output of that trait's methods are
/// not covered by semantic versioning.  Specifically: you should not rely on
/// the specific output of `Display`, `Debug`, or `Error::source()` when run on
/// this type; it may change between patch versions without notification.
#[derive(Error, Clone, Debug)]
pub struct Error {
    /// The actual error.
    #[source]
    detail: Box<ErrorDetail>,
}

impl From<ErrorDetail> for Error {
    fn from(detail: ErrorDetail) -> Error {
        Error {
            detail: detail.into(),
        }
    }
}

/// Represents errors that can occur while doing Tor operations.
///
/// This enumeration is the inner view of a [`arti_relay::Error`](crate::Error).
///
/// Instead of looking at the type, you should try to use the [`kind`](`tor_error::HasKind::kind`)
/// trait method to distinguish among different kinds of [`Error`](struct@crate::Error).
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(vis(pub(crate))))]
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub(crate) enum ErrorDetail {
    /// A programming problem, either in our code or the code calling it.
    #[error("Programming problem")]
    Bug(#[from] tor_error::Bug),
}

impl Error {
    /// Consume this error and return the underlying error detail object.
    // TODO RELAY: remove
    #[allow(unused)]
    pub(crate) fn into_detail(self) -> ErrorDetail {
        *self.detail
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tor: {}: {}", self.detail.kind(), &self.detail)
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        self.detail.kind()
    }
}

impl tor_error::HasKind for ErrorDetail {
    fn kind(&self) -> ErrorKind {
        match self {
            ErrorDetail::Bug(e) => e.kind(),
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    /// This code makes sure that our errors implement all the traits we want.
    #[test]
    fn traits_ok() {
        // I had intended to use `assert_impl`, but that crate can't check whether
        // a type is 'static.
        fn assert<
            T: Send + Sync + Clone + std::fmt::Debug + Display + std::error::Error + 'static,
        >() {
        }
        fn check() {
            assert::<Error>();
            assert::<ErrorDetail>();
        }
        check(); // doesn't do anything, but avoids "unused function" warnings.
    }
}
