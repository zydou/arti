//! The InternalError type, macro for generating it, etc.

use std::fmt::{self, Debug, Display};
use std::panic;
use std::sync::Arc;

use super::*;

#[cfg(feature = "backtrace")]
/// Backtrace implementation for when the feature is enabled
mod ie_backtrace {
    use super::*;
    // TODO MSRV 1.65: std::backtrace::Backtrace is stable; maybe we should be
    // using that instead?
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
            Debug::fmt(&self.0, f)
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
/// Programming error (a bug)
//
// Boxed because it is fairly large (>=12 words), and will be in a variant in many other errors.
//
// This is a single Bug type containing a kind in BugRepr, rather than separate InternalError and
// BadApiUsage types, primarily because that means that one Bug(#[from] tor_error::Bug) suffices in
// every crate's particular error type.
pub struct Bug(Box<BugRepr>);

/// The source of an Bug
type SourceError = Arc<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
/// Internal error (a bug)
struct BugRepr {
    /// Message, usually from internal!() like format!
    message: String,

    /// File and line number
    location: &'static panic::Location<'static>,

    /// Backtrace, perhaps
    backtrace: ie_backtrace::Captured,

    /// Source, perhaps
    source: Option<SourceError>,

    /// Kind
    ///
    /// `Internal` or `BadApiUsage`
    kind: ErrorKind,
}

impl Bug {
    /// Create a bug error report capturing this call site and backtrace
    ///
    /// Prefer to use [`internal!`],
    /// as that makes it easy to add additional information
    /// via format parameters.
    #[track_caller]
    pub fn new<S: Into<String>>(kind: ErrorKind, message: S) -> Self {
        Bug::new_inner(kind, message.into(), None)
    }

    /// Create an internal error
    #[track_caller]
    fn new_inner(kind: ErrorKind, message: String, source: Option<SourceError>) -> Self {
        Bug(BugRepr {
            kind,
            message,
            source,
            location: panic::Location::caller(),
            backtrace: ie_backtrace::capture(),
        }
        .into())
    }

    /// Create an bug error report from another error, capturing this call site and backtrace
    ///
    /// In `map_err`, and perhaps elsewhere, prefer to use [`into_internal!`],
    /// as that makes it easy to add additional information
    /// via format parameters.
    #[track_caller]
    pub fn from_error<E, S>(kind: ErrorKind, source: E, message: S) -> Self
    where
        S: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        Bug::new_inner(kind, message.into(), Some(Arc::new(source)))
    }
}

impl std::error::Error for Bug {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .source
            .as_deref()
            .map(|traitobj| traitobj as _ /* cast away Send and Sync */)
    }
}

impl Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{} at {}: {}",
            self.0.kind, &self.0.location, &self.0.message
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
/// # fn main() -> Result<(), tor_error::Bug> {
/// # let mut cells = [()].iter();
/// let need_cell = cells.next().ok_or_else(|| internal!("no cells"))?;
/// # Ok(())
/// # }
/// ```
//
// In principle this macro could perhaps support internal!(from=source, "format", ...)
// but there are alternative ways of writing that:
//    Bug::new_from(source, format!(...)) or
//    into_internal!("format", ...)(source)
// Those are not so bad for what we think will be the rare cases not
// covered by internal!(...) or map_err(into_internal!(...))
#[macro_export]
macro_rules! internal {
    { $( $arg:tt )* } => {
        $crate::Bug::new($crate::ErrorKind::Internal, format!($($arg)*))
    }
}

/// Create a bad API usage error, including a message like `format!`, and capturing this call site
///
/// The calling stack backtrace is also captured,
/// when the `backtrace` cargo feature this is enabled.
///
/// # Examples
///
/// ```
/// use tor_error::bad_api_usage;
///
/// # fn main() -> Result<(), tor_error::Bug> {
/// # let mut targets = [()].iter();
/// let need_target = targets.next().ok_or_else(|| bad_api_usage!("no targets"))?;
/// # Ok(())
/// # }
#[macro_export]
macro_rules! bad_api_usage {
    { $( $arg:tt )* } => {
        $crate::Bug::new($crate::ErrorKind::BadApiUsage, format!($($arg)*))
    }
}

/// Helper for converting an error into an internal error
///
/// Returns a closure implementing `FnOnce(E) -> Bug`.
/// The source error `E` must be `std::error::Error + Send + Sync + 'static`.
///
/// # Examples
/// ```
/// use tor_error::into_internal;
///
/// # fn main() -> Result<(), tor_error::Bug> {
/// # let s = b"";
/// let s = std::str::from_utf8(s).map_err(into_internal!("bad bytes: {:?}", s))?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! into_internal {
    { $( $arg:tt )* } => {
      std::convert::identity( // Hides the IEFI from clippy::redundant_closure_call
        |source| $crate::Bug::from_error($crate::ErrorKind::Internal, source, format!($($arg)*))
      )
    }
}

/// Helper for converting an error into an bad API usage error
///
/// Returns a closure implementing `FnOnce(E) -> InternalError`.
/// The source error `E` must be `std::error::Error + Send + Sync + 'static`.
///
/// # Examples
/// ```
/// use tor_error::into_bad_api_usage;
///
/// # fn main() -> Result<(), tor_error::Bug> {
/// # let host = b"";
/// let host = std::str::from_utf8(host).map_err(into_bad_api_usage!("hostname is bad UTF-8: {:?}", host))?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! into_bad_api_usage {
    { $( $arg:tt )* } => {
      std::convert::identity( // Hides the IEFI from clippy::redundant_closure_call
        |source| $crate::Bug::from_error($crate::ErrorKind::BadApiUsage, source, format!($($arg)*))
      )
    }
}

impl HasKind for Bug {
    fn kind(&self) -> ErrorKind {
        self.0.kind
    }
}

#[cfg(test)]
mod test {
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

    // We test this on "important" and "reliable" platforms only.
    //
    // This test case mainly is to ensure that we are using the backtrace module correctly, etc.,
    // which can be checked by doing it on one platform.
    //
    // Doing the test on on *all* platforms would simply expose us to the vagaries of platform
    // backtrace support.  Arti ought not to fail its tests just because someone is using a
    // platform with poor backtrace support.
    //
    // On the other hand, we *do* want to know that things are correct on platforms where we think
    // Rust backtraces work properly.
    //
    // So this list is a compromise.  See
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/509#note_2803085
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    #[inline(never)]
    fn internal_macro_test() {
        let start_of_func = line!();

        let e = internal!("Couldn't {} the {}.", "wobble", "wobbling device");
        assert_eq!(e.0.message, "Couldn't wobble the wobbling device.");
        assert!(e.0.location.file().ends_with("internal.rs"));
        assert!(e.0.location.line() > start_of_func);
        assert!(e.0.source.is_none());

        let s = e.to_string();
        dbg!(&s);

        assert!(s.starts_with("internal error (bug) at "));
        assert!(s.contains("Couldn't wobble the wobbling device."));
        #[cfg(feature = "backtrace")]
        assert!(s.contains("internal_macro_test"));

        #[derive(thiserror::Error, Debug)]
        enum Wrap {
            #[error("Internal error")]
            Internal(#[from] Bug),
        }

        let w: Wrap = e.into();
        let s = format!("Got: {}", w.report());
        dbg!(&s);
        assert!(s.contains("Couldn't wobble the wobbling device."));
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
