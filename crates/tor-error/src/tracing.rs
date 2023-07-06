//! Support for using `tor-error` with the `tracing` crate.

use crate::ErrorKind;

#[doc(hidden)]
pub use tracing::{event, Level};

impl ErrorKind {
    /// Return true if this [`ErrorKind`] should always be logged as
    /// a warning (or more severe).
    pub fn is_always_a_warning(&self) -> bool {
        matches!(self, ErrorKind::Internal | ErrorKind::BadApiUsage)
    }
}

/// Log a [`Report`](crate::Report) of a provided error at a given level, or a
/// higher level if appropriate.
///
/// (If [`ErrorKind::is_always_a_warning`] returns true for the error's kind, we
/// log it at WARN, unless this event is already at level WARN or ERROR.)
///
/// # Examples
///
/// ```
/// # // this is what implements HasKind in this crate.
/// # fn demo(err: &futures::task::SpawnError) {
/// # let num = 7;
/// use tor_error::event_report;
/// use tracing::Level;
///
/// event_report!(Level::DEBUG, err, "Couldn't chew gum while walking");
///
/// event_report!(Level::TRACE, err, "Ephemeral error on attempt #{}", num);
/// # }
/// ```
///
/// # Limitations
///
/// This macro does not support the full range of syntaxes supported by
/// [`tracing::event`].
//
// NOTE: We need this fancy conditional here because tracing::event! insists on
// getting a const expression for its `Level`.  So we can do
// `if cond {debug!(..)} else {warn!(..)}`,
// but we can't do
// `event!(if cond {DEBUG} else {WARN}, ..)`.
#[macro_export]
macro_rules! event_report {
    ($level:expr, $err:expr, $fmt:literal, $($arg:expr),* $(,)?) => {
        {
            use $crate::{tracing as tr, HasKind as _, };
            let err = $err;
            if err.kind().is_always_a_warning() && tr::Level::WARN < $level {
                $crate::event_report!(@raw tr::Level::WARN, err, $fmt, $($arg),*);
            } else {
                $crate::event_report!(@raw $level, err, $fmt, $($arg),*);
            }
        }
    };

    ($level:expr, $err:expr, $fmt:literal) => {
        $crate::event_report!($level, $err, $fmt, )
    };

    (@raw $level:expr, $err:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {
        {
            use $crate::{tracing as tr, ErrorReport as _};
            tr::event!(
                $level,
                concat!($fmt, ": {}"),
                $($arg ,)*
                ($err).report()
            )
        }
    }
}

/// Log a report for `err` at level `TRACE` (or higher if it is a bug).
///
/// # Examples:
///
/// ```
/// # fn demo(err: &futures::task::SpawnError) {
/// # let msg = ();
/// use tor_error::trace_report;
/// trace_report!(err, "Cheese exhausted (ephemeral)");
/// trace_report!(err, "Unable to parse message {:?}", msg);
/// # }
/// ```
#[macro_export]
macro_rules! trace_report {
    ( $err:expr, $($rest:expr),+ $(,)? ) => {
        $crate::event_report!($crate::tracing::Level::TRACE, $err, $($rest),+)
    }
}
/// Log a report for `err` at level `DEBUG` (or higher if it is a bug).
///
/// # Examples
///
/// ```
/// # fn demo(err: &futures::task::SpawnError) {
/// # let peer = "";
/// use tor_error::debug_report;
/// debug_report!(err, "Existentialism overload; retrying");
/// debug_report!(err, "Recoverable error from {}; will try somebody else", peer);
/// # }
/// ```
#[macro_export]
macro_rules! debug_report {
    ( $err:expr, $($rest:expr),+ $(,)? ) => {
        $crate::event_report!($crate::tracing::Level::DEBUG, $err, $($rest),+)
    }
}
/// Log a report for `err` at level `INFO` (or higher if it is a bug).
///
/// # Examples
///
/// ```
/// # fn demo(err: &futures::task::SpawnError) {
/// # let first = ""; let second = "";
/// use tor_error::info_report;
/// info_report!(err, "Speculative load failed; proceeding anyway");
/// info_report!(err, "No {} available; will try {} instead", first, second);
/// # }
/// ```
#[macro_export]
macro_rules! info_report {
    ( $err:expr, $($rest:expr),+ $(,)? ) => {
        $crate::event_report!($crate::tracing::Level::INFO, $err, $($rest),+)
    }
}
/// Log a report for `err` at level `WARN`.
///
/// # Examples
///
/// ```
/// # fn demo(err: &futures::task::SpawnError) {
/// # let peer = "";
/// use tor_error::warn_report;
/// warn_report!(err, "Cannot contact remote server");
/// warn_report!(err, "No address found for {}", peer);
/// # }
/// ```
#[macro_export]
macro_rules! warn_report {
    ( $err:expr, $($rest:expr),+ $(,)? ) => {
        // @raw, since we don't escalate warnings any higher,
        // no matter what their kind might be.
        $crate::event_report!(@raw $crate::tracing::Level::WARN, $err, $($rest),+)
    }
}
/// Log a report for `err` at level `ERROR`.
///
/// # Examples
///
/// ```
/// # fn demo(err: &futures::task::SpawnError) {
/// # let action = "";
/// use tor_error::error_report;
/// error_report!(err, "Everything has crashed");
/// error_report!(err, "Everything has crashed while trying to {}", action);
/// # }
/// ```
#[macro_export]
macro_rules! error_report {
    ( $err:expr, $($rest:expr),+ $(,)? ) => {
        // @raw, since we don't escalate warnings any higher,
        // no matter what their kind might be.
        $crate::event_report!(@raw $crate::tracing::Level::ERROR, $err, $($rest),+)
    }
}
