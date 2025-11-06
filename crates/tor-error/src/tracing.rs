//! Support for using `tor-error` with the `tracing` crate.

use crate::ErrorKind;

#[doc(hidden)]
pub use static_assertions;
#[doc(hidden)]
pub use tracing::{Level, event};

use paste::paste;

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
/// event_report!(Level::TRACE, err, attempt = %num, "Ephemeral error");
/// # }
/// ```
///
/// # Limitations
///
/// This macro does not support the full range of syntaxes supported by
/// [`tracing::event!`].
//
// NOTE: We need this fancy conditional here because tracing::event! insists on
// getting a const expression for its `Level`.  So we can do
// `if cond {debug!(..)} else {warn!(..)}`,
// but we can't do
// `event!(if cond {DEBUG} else {WARN}, ..)`.
#[macro_export]
macro_rules! event_report {
    ($level:expr, $err:expr) => {
        $crate::event_report!($level, $err,)
    };

    ($level:expr, $err:expr, $($arg:tt)*) => {
        {
            use $crate::{tracing as tr, HasKind as _, };
            let err = $err;
            if err.kind().is_always_a_warning() && tr::Level::WARN < $level {
                $crate::event_report!(@raw tr::Level::WARN, err, $($arg)*);
            } else {
                $crate::event_report!(@raw $level, err, $($arg)*);
            }
        }
    };

    (@raw $level:expr, $err:expr) => {
        $crate::event_report!(@raw $level, $err,)
    };

    (@raw $level:expr, $err:expr, $($arg:tt)*) => {
        {
            use $crate::tracing as tr;
            use ::std::ops::Deref as _;

            tr::event!(
                $level,
                // some types like `anyhow::Error` can deref to a `dyn Error`, and we cast as
                // `&dyn Error` so that it is handled as an error type by a tracing field
                // visitor (see `Visit::record_error()` from `tracing-core`)
                error = ((&($err)).deref() as &dyn std::error::Error),
                $($arg)*
            )
        }
    }
}

/// Define a macro `$level_report`
///
/// The title line for the doc comment will be
/// ``$title_1 `LEVEL` $title_2``
///
/// A standard body, containing a set of examples, will be provided.
///
/// You must pass a dollar sign for `D`, because there is no dollar escaping mechanism
/// for macro_rules macros in stable Rust (!)
macro_rules! define_report_macros { {
    # $title_1:tt
    LEVEL
    # $title_2:tt

    $D:tt
    $( [$($flag:tt)*] $level:ident )*
} => { $( paste!{
    # $title_1
    #[doc = concat!("`", stringify!( [< $level:upper >] ), "`")]
    # $title_2
    ///
    /// # Examples:
    ///
    /// ```
    /// # fn demo(err: &futures::task::SpawnError) {
    /// # let msg = ();
    #[doc = concat!("use tor_error::", stringify!($level), "_report;")]
    #[doc = concat!(stringify!($level), "_report!",
                    r#"(err, "Cheese exhausted (ephemeral)");"#)]
    #[doc = concat!(stringify!($level), "_report!",
                    r#"(err, "Unable to parse message {:?}", msg);"#)]
    /// # }
    /// ```
    #[macro_export]
    macro_rules! [< $level _report >] {
        ( $D err:expr ) => {
            // would be nice to do a `$D crate::[< $level _report >]!($D err,)` here,
            // but apparently this isn't allowed:
            // https://github.com/rust-lang/rust/pull/52234
            $D crate::event_report!($($flag)*
                                    $D crate::tracing::Level::[< $level:upper >],
                                    $D err)
        };

        ( $D err:expr, $D ($D rest:tt)* ) => {
            $D crate::event_report!($($flag)*
                                    $D crate::tracing::Level::[< $level:upper >],
                                    $D err, $D ($D rest)*)
        }
    }
} )* } }

define_report_macros! {
    /// Log a report for `err` at level
    LEVEL
    /// (or higher if it is a bug).

    $ [] trace
      [] debug
      [] info
}

define_report_macros! {
    /// Log a report for `err` at level
    LEVEL
    ///
    $ [@raw] warn
      [@raw] error
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::internal;
    use crate::report::ErrorReport;
    use thiserror::Error;
    use tracing_test::traced_test;

    #[derive(Error, Debug)]
    #[error("my error")]
    struct MyError;

    #[test]
    #[traced_test]
    // i really don't think that this test is too complicated
    #[allow(clippy::cognitive_complexity)]
    fn warn_report() {
        let me = MyError;
        let _ = me.report();
        warn_report!(me, "reporting unwrapped");

        let ae = anyhow::Error::from(me).context("context");
        let _ = ae.report();
        warn_report!(ae, "reporting anyhow");

        let ie = internal!("Foo was not initialized");
        let _ = ie.report();
        warn_report!(ie);
    }
}
