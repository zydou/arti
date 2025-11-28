#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::error::Error;
use std::fmt::{self, Debug, Display, Error as FmtError, Formatter};
use std::iter;
use std::time::{Duration, Instant, SystemTime};

/// An error type for use when we're going to do something a few times,
/// and they might all fail.
///
/// To use this error type, initialize a new RetryError before you
/// start trying to do whatever it is.  Then, every time the operation
/// fails, use [`RetryError::push()`] to add a new error to the list
/// of errors.  If the operation fails too many times, you can use
/// RetryError as an [`Error`] itself.
///
/// This type now tracks timestamps for each error occurrence, allowing
/// users to see when errors occurred and how long the retry process took.
#[derive(Debug, Clone)]
pub struct RetryError<E> {
    /// The operation we were trying to do.
    doing: String,
    /// The errors that we encountered when doing the operation.
    errors: Vec<(Attempt, E, Instant)>,
    /// The total number of errors we encountered.
    ///
    /// This can differ from errors.len() if the errors have been
    /// deduplicated.
    n_errors: usize,
    /// The wall-clock time when the first error occurred.
    ///
    /// This is used for human-readable display.
    first_error_at: Option<SystemTime>,
}

/// Represents which attempts, in sequence, failed to complete.
#[derive(Debug, Clone)]
enum Attempt {
    /// A single attempt that failed.
    Single(usize),
    /// A range of consecutive attempts that failed.
    Range(usize, usize),
}

// TODO: Should we declare that some error is the 'source' of this one?
// If so, should it be the first failure?  The last?
impl<E: Debug + AsRef<dyn Error>> Error for RetryError<E> {}

impl<E> RetryError<E> {
    /// Create a new RetryError, with no failed attempts.
    ///
    /// The provided `doing` argument is a short string that describes
    /// what we were trying to do when we failed too many times.  It
    /// will be used to format the final error message; it should be a
    /// phrase that can go after "while trying to".
    ///
    /// This RetryError should not be used as-is, since when no
    /// [`Error`]s have been pushed into it, it doesn't represent an
    /// actual failure.
    pub fn in_attempt_to<T: Into<String>>(doing: T) -> Self {
        RetryError {
            doing: doing.into(),
            errors: Vec::new(),
            n_errors: 0,
            first_error_at: None,
        }
    }
    /// Add an error to this RetryError.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    ///
    /// The `timestamp` parameter should be the monotonic time when the error
    /// occurred, typically obtained from a runtime's `now()` method.
    ///
    /// # Example
    /// ```
    /// # use retry_error::RetryError;
    /// # use std::time::Instant;
    /// let mut retry_err: RetryError<&str> = RetryError::in_attempt_to("connect");
    /// let now = Instant::now();
    /// retry_err.push_timed("connection failed", now);
    /// ```
    pub fn push_timed<T>(&mut self, err: T, timestamp: Instant)
    where
        T: Into<E>,
    {
        if self.n_errors < usize::MAX {
            self.n_errors += 1;
            let attempt = Attempt::Single(self.n_errors);

            // Set first_error_at on the first error
            if self.first_error_at.is_none() {
                self.first_error_at = Some(SystemTime::now());
            }

            self.errors.push((attempt, err.into(), timestamp));
        }
    }

    /// Add an error to this RetryError using the current time.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    ///
    /// This is a convenience wrapper around [`push_timed()`](Self::push_timed)
    /// that uses `Instant::now()` for the timestamp. For code that needs
    /// mockable time (such as in tests), prefer `push_timed()`.
    pub fn push<T>(&mut self, err: T)
    where
        T: Into<E>,
    {
        self.push_timed(err, Instant::now());
    }

    /// Return an iterator over all of the reasons that the attempt
    /// behind this RetryError has failed.
    pub fn sources(&self) -> impl Iterator<Item = &E> {
        self.errors.iter().map(|(.., e, _)| e)
    }

    /// Return the number of underlying errors.
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Return true if no underlying errors have been added.
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Group up consecutive errors of the same kind, for easier display.
    ///
    /// Two errors have "the same kind" if they return `true` when passed
    /// to the provided `dedup` function.
    pub fn dedup_by<F>(&mut self, same_err: F)
    where
        F: Fn(&E, &E) -> bool,
    {
        let mut old_errs = Vec::new();
        std::mem::swap(&mut old_errs, &mut self.errors);

        for (attempt, err, timestamp) in old_errs {
            if let Some((last_attempt, last_err, ..)) = self.errors.last_mut() {
                if same_err(last_err, &err) {
                    last_attempt.grow();
                } else {
                    self.errors.push((attempt, err, timestamp));
                }
            } else {
                self.errors.push((attempt, err, timestamp));
            }
        }
    }
}

impl<E: PartialEq<E>> RetryError<E> {
    /// Group up consecutive errors of the same kind, according to the
    /// `PartialEq` implementation.
    pub fn dedup(&mut self) {
        self.dedup_by(PartialEq::eq);
    }
}

impl Attempt {
    /// Extend this attempt by a single additional failure.
    fn grow(&mut self) {
        *self = match *self {
            Attempt::Single(idx) => Attempt::Range(idx, idx + 1),
            Attempt::Range(first, last) => Attempt::Range(first, last + 1),
        };
    }
}

impl<E, T> Extend<T> for RetryError<E>
where
    T: Into<E>,
{
    fn extend<C>(&mut self, iter: C)
    where
        C: IntoIterator<Item = T>,
    {
        for item in iter.into_iter() {
            self.push(item);
        }
    }
}

impl<E> IntoIterator for RetryError<E> {
    type Item = E;
    type IntoIter = std::vec::IntoIter<E>;
    #[allow(clippy::needless_collect)]
    // TODO We have to use collect/into_iter here for now, since
    // the actual Map<> type can't be named.  Once Rust lets us say
    // `type IntoIter = impl Iterator<Item=E>` then we fix the code
    // and turn the Clippy warning back on.
    fn into_iter(self) -> Self::IntoIter {
        self.errors
            .into_iter()
            .map(|(.., e, _)| e)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl Display for Attempt {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self {
            Attempt::Single(idx) => write!(f, "Attempt {}", idx),
            Attempt::Range(first, last) => write!(f, "Attempts {}..{}", first, last),
        }
    }
}

impl<E: AsRef<dyn Error>> Display for RetryError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self.n_errors {
            0 => write!(f, "Unable to {}. (No errors given)", self.doing),
            1 => {
                write!(f, "Unable to {}", self.doing)?;

                // Show timestamp if available
                if let (Some((.., timestamp)), Some(first_at)) =
                    (self.errors.first(), self.first_error_at)
                {
                    write!(
                        f,
                        " at {} ({})",
                        humantime::format_rfc3339(first_at),
                        format_time_ago(timestamp.elapsed())
                    )?;
                }

                write!(f, ": ")?;
                fmt_error_with_sources(self.errors[0].1.as_ref(), f)
            }
            n => {
                write!(f, "Tried to {} {} times", self.doing, n)?;

                // Show time range if we have timestamps
                if let (Some(first_at), Some((.., first_ts)), Some((.., last_ts))) =
                    (self.first_error_at, self.errors.first(), self.errors.last())
                {
                    let duration = last_ts.saturating_duration_since(*first_ts);

                    write!(f, " from {} ", humantime::format_rfc3339(first_at))?;

                    if duration.as_secs() > 0 {
                        write!(f, "to {} ", humantime::format_rfc3339(first_at + duration))?;
                    }

                    write!(f, "({})", format_time_ago(last_ts.elapsed()))?;
                }

                write!(f, ", but all attempts failed")?;

                // Show individual attempts with time offsets
                let first_ts = self.errors.first().map(|(.., ts)| ts);
                for (attempt, e, timestamp) in &self.errors {
                    write!(f, "\n{}", attempt)?;

                    // Show offset from first error
                    if let Some(first_ts) = first_ts {
                        let offset = timestamp.saturating_duration_since(*first_ts);
                        if offset.as_secs() > 0 {
                            write!(f, " ({})", format_duration(offset))?;
                        }
                    }

                    write!(f, ": ")?;
                    fmt_error_with_sources(e.as_ref(), f)?;
                }
                Ok(())
            }
        }
    }
}

/// Format a duration for display with "ago" suffix.
///
/// Returns strings like "2m 30s ago", "just now", "500ms ago".
fn format_time_ago(d: Duration) -> String {
    let secs = d.as_secs();

    if secs == 0 {
        let millis = d.as_millis();
        if millis == 0 {
            return "just now".to_string();
        }
        return format!("{}ms ago", millis);
    }

    let duration_str = if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        let rem_secs = secs % 60;
        if rem_secs == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m {}s", mins, rem_secs)
        }
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, mins)
        }
    };

    format!("{} ago", duration_str)
}

/// Format a duration without "ago" suffix (for offsets between attempts).
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();

    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        let rem_secs = secs % 60;
        if rem_secs == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m {}s", mins, rem_secs)
        }
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, mins)
        }
    }
}

/// Helper: formats a [`std::error::Error`] and its sources (as `"error: source"`)
///
/// Avoids duplication in messages by not printing messages which are
/// wholly-contained (textually) within already-printed messages.
///
/// Offered as a `fmt` function:
/// this is for use in more-convenient higher-level error handling functionality,
/// rather than directly in application/functional code.
///
/// This is used by `RetryError`'s impl of `Display`,
/// but will be useful for other error-handling situations.
///
/// # Example
///
/// ```
/// use std::fmt::{self, Display};
///
/// #[derive(Debug, thiserror::Error)]
/// #[error("some pernickety problem")]
/// struct Pernickety;
///
/// #[derive(Debug, thiserror::Error)]
/// enum ApplicationError {
///     #[error("everything is terrible")]
///     Terrible(#[source] Pernickety),
/// }
///
/// struct Wrapper(Box<dyn std::error::Error>);
/// impl Display for Wrapper {
///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
///         retry_error::fmt_error_with_sources(&*self.0, f)
///     }
/// }
///
/// let bad = Pernickety;
/// let err = ApplicationError::Terrible(bad);
///
/// let printed = Wrapper(err.into()).to_string();
/// assert_eq!(printed, "everything is terrible: some pernickety problem");
/// ```
pub fn fmt_error_with_sources(mut e: &dyn Error, f: &mut fmt::Formatter) -> fmt::Result {
    // We deduplicate the errors here under the assumption that the `Error` trait is poorly defined
    // and contradictory, and that some error types will duplicate error messages. This is
    // controversial, and since there isn't necessarily agreement, we should stick with the status
    // quo here and avoid changing this behaviour without further discussion.
    let mut last = String::new();
    let mut sep = iter::once("").chain(iter::repeat(": "));
    loop {
        let this = e.to_string();
        if !last.contains(&this) {
            write!(f, "{}{}", sep.next().expect("repeat ended"), &this)?;
        }
        last = this;

        if let Some(ne) = e.source() {
            e = ne;
        } else {
            break;
        }
    }
    Ok(())
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
    use super::*;
    use derive_more::From;

    #[test]
    fn bad_parse1() {
        let mut err: RetryError<anyhow::Error> = RetryError::in_attempt_to("convert some things");
        if let Err(e) = "maybe".parse::<bool>() {
            err.push(e);
        }
        if let Err(e) = "a few".parse::<u32>() {
            err.push(e);
        }
        if let Err(e) = "the_g1b50n".parse::<std::net::IpAddr>() {
            err.push(e);
        }
        let disp = format!("{}", err);
        // Check that the output contains the expected messages
        assert!(disp.contains("Tried to convert some things 3 times"));
        assert!(disp.contains("but all attempts failed"));
        assert!(disp.contains("Attempt 1: provided string was not `true` or `false`"));
        assert!(disp.contains("Attempt 2: invalid digit found in string"));
        assert!(disp.contains("Attempt 3: invalid IP address syntax"));
        // Check that timestamps are present
        assert!(disp.contains("from 20")); // Year prefix for timestamp
    }

    #[test]
    fn no_problems() {
        let empty: RetryError<anyhow::Error> =
            RetryError::in_attempt_to("immanentize the eschaton");
        let disp = format!("{}", empty);
        assert_eq!(
            disp,
            "Unable to immanentize the eschaton. (No errors given)"
        );
    }

    #[test]
    fn one_problem() {
        let mut err: RetryError<anyhow::Error> =
            RetryError::in_attempt_to("connect to torproject.org");
        if let Err(e) = "the_g1b50n".parse::<std::net::IpAddr>() {
            err.push(e);
        }
        let disp = format!("{}", err);
        assert!(disp.contains("Unable to connect to torproject.org"));
        assert!(disp.contains("invalid IP address syntax"));
        // Check that timestamp is present
        assert!(disp.contains("at 20")); // Year prefix for timestamp
    }

    #[test]
    fn operations() {
        use std::num::ParseIntError;

        #[derive(From, Clone, Debug, Eq, PartialEq)]
        struct Wrapper(ParseIntError);

        impl AsRef<dyn Error + 'static> for Wrapper {
            fn as_ref(&self) -> &(dyn Error + 'static) {
                &self.0
            }
        }

        let mut err: RetryError<Wrapper> = RetryError::in_attempt_to("parse some integers");
        assert!(err.is_empty());
        assert_eq!(err.len(), 0);
        err.extend(
            vec!["not", "your", "number"]
                .iter()
                .filter_map(|s| s.parse::<u16>().err())
                .map(Wrapper),
        );
        assert!(!err.is_empty());
        assert_eq!(err.len(), 3);

        let cloned = err.clone();
        for (s1, s2) in err.sources().zip(cloned.sources()) {
            assert_eq!(s1, s2);
        }

        err.dedup();
        let disp = format!("{}", err);
        assert!(disp.contains("Tried to parse some integers 3 times"));
        assert!(disp.contains("but all attempts failed"));
        assert!(disp.contains("Attempts 1..3: invalid digit found in string"));
        // Check that timestamps are present
        assert!(disp.contains("from 20")); // Year prefix for timestamp
    }

    #[test]
    fn overflow() {
        use std::num::ParseIntError;
        let mut err: RetryError<ParseIntError> =
            RetryError::in_attempt_to("parse too many integers");
        assert!(err.is_empty());
        let mut errors: Vec<ParseIntError> = vec!["no", "numbers"]
            .iter()
            .filter_map(|s| s.parse::<u16>().err())
            .collect();
        err.n_errors = usize::MAX;
        err.errors.push((
            Attempt::Range(1, err.n_errors),
            errors.pop().expect("parser did not fail"),
            Instant::now(),
        ));
        assert!(err.n_errors == usize::MAX);
        assert!(err.len() == 1);

        err.push(errors.pop().expect("parser did not fail"));
        assert!(err.n_errors == usize::MAX);
        assert!(err.len() == 1);
    }
}
