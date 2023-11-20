//! An error type for the `tor-keymgr` crate.

use tor_error::{ErrorKind, HasKind};

use dyn_clone::DynClone;

use std::error::Error as StdError;
use std::fmt;

/// An Error type for this crate.
pub type Error = Box<dyn KeystoreError>;

/// An error returned by a [`Keystore`](crate::Keystore).
pub trait KeystoreError:
    HasKind + StdError + DynClone + fmt::Debug + fmt::Display + Send + Sync + 'static
{
    /// Return a boxed version of this error.
    fn boxed(self) -> Box<Self>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

// Generate a Clone impl for Box<dyn KeystoreError>
dyn_clone::clone_trait_object!(KeystoreError);

impl KeystoreError for tor_error::Bug {}

impl<K: KeystoreError + Send + Sync> From<K> for Error {
    fn from(k: K) -> Self {
        Box::new(k)
    }
}

// This impl is needed because tor_keymgr::Error is the error source type of ErrorDetail::Keystore,
// which _must_ implement StdError (otherwise we get an error about thiserror::AsDynError not being
// implemented for tor_keymgr::Error).
//
// See <https://github.com/dtolnay/thiserror/issues/212>
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        (**self).source()
    }
}

/// An error caused by an invalid [`ArtiPath`].
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Invalid ArtiPath")]
#[non_exhaustive]
pub enum ArtiPathError {
    /// Found an empty path component.
    #[error("Empty path component")]
    EmptyPathComponent,

    /// The path contains a disallowed char.
    #[error("Found disallowed char {0}")]
    DisallowedChar(char),

    /// The path contains the `..` pattern.
    #[error("Found `..` pattern")]
    PathTraversal,

    /// The path starts with a disallowed char.
    #[error("Path starts or ends with disallowed char {0}")]
    BadOuterChar(char),

    /// The path contains an invalid key denotator.
    ///
    /// See the [`ArtiPath`] docs for more information.
    InvalidDenotator,
}

/// An error caused by keystore corruption.
///
// TODO HSS: refactor the keymgr error types to be variants of a top-level KeyMgrError enum
// (it should only be necessary to impl KeystoreError for custom/opaque keystore errors).
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Keystore corruption")]
#[non_exhaustive]
pub enum KeystoreCorruptionError {
    /// A keystore contains a key that has an invalid [`ArtiPath`].
    #[error("{0}")]
    ArtiPath(#[from] ArtiPathError),
}

impl KeystoreError for KeystoreCorruptionError {}

impl HasKind for KeystoreCorruptionError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::KeystoreCorrupted
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_error::ErrorKind;

    #[derive(Debug, Copy, Clone, PartialEq, thiserror::Error)]
    #[error("The source of a test error")]
    struct TestErrorSource;

    #[derive(Debug, Clone, thiserror::Error)]
    #[error("A test error")]
    struct TestError(#[from] TestErrorSource);

    impl KeystoreError for TestError {}

    impl HasKind for TestError {
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn error_source() {
        let e: Error = Box::new(TestError(TestErrorSource)) as Error;

        assert_eq!(e.source().unwrap().to_string(), TestErrorSource.to_string());
    }
}
