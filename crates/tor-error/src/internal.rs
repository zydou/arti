//! The InternalError type, macro for generating it, etc.

use std::fmt::{self, Debug, Display};
use std::panic;

use super::*;

#[cfg(feature = "backtrace")]
/// Backtrace implementation for when the feature is enabled
mod ie_backtrace {
    use super::*;
    use backtrace::Backtrace;

    #[derive(Debug, Clone)]
    /// Captured backtrace, if turned on
    pub(crate) struct Captured(Backtrace);

    /// Capture a backtrace, if turned on
    pub(crate) fn capture() -> Captured {
        Captured(Backtrace::new())
    }

    impl Display for Captured {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Debug::fmt(self, f)
        }
    }
}

#[cfg(not(feature = "backtrace"))]
/// Backtrace implementation for when the feature is disabled
mod ie_backtrace {
    use super::*;

    #[derive(Debug, Clone)]
    /// "Captured backtrace", but actually nothing
    pub(crate) struct Captured;

    /// "Capture a backtrace", but actually return nothing
    pub(crate) fn capture() -> Captured {
        Captured
    }

    impl Display for Captured {
        fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
/// Internal error (a bug)
//
// Boxed because it is fairly large (>=12 words), and will be in a variant in many other errors.
pub struct InternalError(Box<InternalErrorRepr>);

#[derive(Debug, Clone)]
/// Internal error (a bug)
struct InternalErrorRepr {
    /// Message, usually from internal!() like format!
    message: String,

    /// File and line number
    location: &'static panic::Location<'static>,

    /// Backtrace, perhaps
    backtrace: ie_backtrace::Captured,
}

impl InternalError {
    /// Create an internal error capturing this call site and backtrace
    ///
    /// Prefer to use [`internal!`],
    /// as that makes it easy to add additional information
    /// via format parameters.
    pub fn new<S: Into<String>>(message: S) -> Self {
        InternalError::new_inner(message.into())
    }

    /// Create an internal error
    fn new_inner(message: String) -> Self {
        InternalError(
            InternalErrorRepr {
                message,
                location: panic::Location::caller(),
                backtrace: ie_backtrace::capture(),
            }
            .into(),
        )
    }
}

impl std::error::Error for InternalError {}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "internal error (bug): {:?}: {}",
            &self.0.location, &self.0.message
        )?;
        Display::fmt(&self.0.backtrace, f)?;
        Ok(())
    }
}

/// Create an internal error, including a message like `format!`, and capturing this call site
///
/// The calling stack backtrace is also captured,
/// when the `backtrace` cargo feature this is enabled.
///
/// # Examples
///
/// ```
/// use tor_error::internal;
///
/// # fn main() -> Result<(), tor_error::InternalError> {
/// # let mut cells = [()].iter();
/// let need_cell = cells.next().ok_or_else(|| internal!("no cells"))?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! internal {
    { $( $arg:tt )* } => {
        $crate::InternalError::new(format!($($arg)*))
    }
}

impl HasKind for InternalError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InternalError
    }
}
