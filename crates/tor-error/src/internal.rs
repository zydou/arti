//! The InternalError type, macro for generating it, etc.

use std::fmt::{self, Debug, Display};
use std::panic;
use std::sync::Arc;

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

/// The source of an InternalError
type SourceError = Arc<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
/// Internal error (a bug)
struct InternalErrorRepr {
    /// Message, usually from internal!() like format!
    message: String,

    /// File and line number
    location: &'static panic::Location<'static>,

    /// Backtrace, perhaps
    backtrace: ie_backtrace::Captured,

    /// Source, perhaps
    source: Option<SourceError>,
}

impl InternalError {
    /// Create an internal error capturing this call site and backtrace
    ///
    /// Prefer to use [`internal!`],
    /// as that makes it easy to add additional information
    /// via format parameters.
    #[track_caller]
    pub fn new<S: Into<String>>(message: S) -> Self {
        InternalError::new_inner(message.into(), None)
    }

    /// Create an internal error
    #[track_caller]
    fn new_inner(message: String, source: Option<SourceError>) -> Self {
        InternalError(
            InternalErrorRepr {
                message,
                source,
                location: panic::Location::caller(),
                backtrace: ie_backtrace::capture(),
            }
            .into(),
        )
    }

    /// Create an internal error from another error, capturing this call site and backtrace
    ///
    /// In `map_err`, and perhaps elsewhere, prefer to use [`into_internal!`],
    /// as that makes it easy to add additional information
    /// via format parameters.
    #[track_caller]
    pub fn from_error<E, S>(source: E, message: S) -> Self
    where
        S: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        InternalError::new_inner(message.into(), Some(Arc::new(source)))
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .source
            .as_deref()
            .map(|traitobj| traitobj as _ /* cast away Send and Sync */)
    }
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "internal error (bug) at {}: {}",
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
//
// In principle this macro could perhaps support internal!(from=source, "format", ...)
// but there are alternative ways of writing that:
//    InternalError::new_from(source, format!(...)) or
//    into_internal!("format", ...)(source)
// Those are not so bad for what we think will be the rare cases not
// covered by internal!(...) or map_err(into_internal!(...))
#[macro_export]
macro_rules! internal {
    { $( $arg:tt )* } => {
        $crate::InternalError::new(format!($($arg)*))
    }
}

/// Helper for converting an error into an InternalError
///
/// Returns a closure implementing `FnOnce(E) -> InternalError`.
/// The source error `E` must be `std::error::Error + Send + Sync + 'static`.
///
/// # Examples
/// ```
/// use tor_error::into_internal;
///
/// # fn main() -> Result<(), tor_error::InternalError> {
/// # let s = b"";
/// let s = std::str::from_utf8(s).map_err(into_internal!("bad bytes: {:?}", s))?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! into_internal {
    { $( $arg:tt )* } => {
        |source| $crate::InternalError::from_error(source, format!($($arg)*))
    }
}

impl HasKind for InternalError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Internal
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn internal_macro_test() {
        let start_of_func = line!();

        let e = internal!("Couldn't {} the {}.", "wobble", "wobbling device");
        assert_eq!(e.0.message, "Couldn't wobble the wobbling device.");
        assert!(e.0.location.file().ends_with("internal.rs"));
        assert!(e.0.location.line() > start_of_func);
        assert!(e.0.source.is_none());

        let s = e.to_string();

        assert!(s.starts_with("internal error (bug) at "));
        assert!(s.contains("Couldn't wobble the wobbling device."));
        #[cfg(feature = "backtrace")]
        assert!(s.contains("internal_macro_test"));
    }

    #[test]
    fn source() {
        use std::error::Error;
        use std::str::FromStr;

        let start_of_func = line!();
        let s = "penguin";
        let inner = u32::from_str(s).unwrap_err();
        let outer = u32::from_str(s)
            .map_err(into_internal!("{} is not a number", s))
            .unwrap_err();

        let afterwards = line!();

        assert_eq!(outer.source().unwrap().to_string(), inner.to_string());
        assert!(outer.0.location.line() > start_of_func);
        assert!(outer.0.location.line() < afterwards);
    }
}
