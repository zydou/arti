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
    /// This is used for human-readable display of absolute timestamps.
    ///
    /// We store both types because they serve different purposes:
    /// - `Instant` (in the errors vec): Monotonic clock for reliable duration calculations.
    ///   Immune to clock adjustments, but can't be displayed as wall-clock time.
    /// - `SystemTime` (here): Wall-clock time for displaying when the first error occurred
    ///   in a human-readable format (e.g., "2025-12-09T10:24:02Z").
    ///
    /// We only store `SystemTime` for the first error to show users *when* the problem
    /// started. Subsequent errors are displayed relative to the first ("+2m 30s"),
    /// using the reliable `Instant` timestamps.
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
    /// Add an error to this RetryError with explicit timestamps.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    ///
    /// The `instant` parameter should be the monotonic time when the error
    /// occurred, typically obtained from a runtime's `now()` method.
    ///
    /// The `wall_clock` parameter is the wall-clock time when the error occurred,
    /// used for human-readable display. Pass `None` to skip wall-clock tracking,
    /// or `Some(SystemTime::now())` for the current time.
    ///
    /// # Example
    /// ```
    /// # use retry_error::RetryError;
    /// # use std::time::{Instant, SystemTime};
    /// let mut retry_err: RetryError<&str> = RetryError::in_attempt_to("connect");
    /// let now = Instant::now();
    /// retry_err.push_timed("connection failed", now, Some(SystemTime::now()));
    /// ```
    pub fn push_timed<T>(&mut self, err: T, instant: Instant, wall_clock: Option<SystemTime>)
    where
        T: Into<E>,
    {
        if self.n_errors < usize::MAX {
            self.n_errors += 1;
            let attempt = Attempt::Single(self.n_errors);

            if self.first_error_at.is_none() {
                self.first_error_at = wall_clock;
            }

            self.errors.push((attempt, err.into(), instant));
        }
    }

    /// Add an error to this RetryError using the current time.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    ///
    /// This is a convenience wrapper around [`push_timed()`](Self::push_timed)
    /// that uses `Instant::now()` and `SystemTime::now()` for the timestamps.
    /// For code that needs mockable time (such as in tests), prefer `push_timed()`.
    pub fn push<T>(&mut self, err: T)
    where
        T: Into<E>,
    {
        self.push_timed(err, Instant::now(), Some(SystemTime::now()));
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

    /// Add multiple errors to this RetryError using the current time.
    ///
    /// This method uses [`push()`](Self::push) internally, which captures
    /// `SystemTime::now()`. For code that needs mockable time (such as in tests),
    /// iterate manually and call [`push_timed()`](Self::push_timed) instead.
    ///
    /// # Example
    /// ```
    /// # use retry_error::RetryError;
    /// let mut err: RetryError<anyhow::Error> = RetryError::in_attempt_to("parse");
    /// let errors = vec!["error1", "error2"].into_iter().map(anyhow::Error::msg);
    /// err.extend(errors);
    /// ```
    #[allow(clippy::disallowed_methods)] // This method intentionally uses push()
    pub fn extend<T>(&mut self, iter: impl IntoIterator<Item = T>)
    where
        T: Into<E>,
    {
        for item in iter {
            self.push(item);
        }
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

    /// Add multiple errors to this RetryError, preserving their original timestamps.
    ///
    /// The errors from other will be added to this RetryError, with their original
    /// timestamps retained. The `Attempt` counters will be updated to continue from
    /// the current state of this RetryError. `Attempt::Range` entries are preserved as ranges
    pub fn extend_from_retry_error(&mut self, other: RetryError<E>) {
        if self.first_error_at.is_none() {
            self.first_error_at = other.first_error_at;
        }

        for (attempt, err, timestamp) in other.errors {
            let new_attempt = match attempt {
                Attempt::Single(_) => {
                    let Some(new_n_errors) = self.n_errors.checked_add(1) else {
                        break;
                    };
                    self.n_errors = new_n_errors;
                    Attempt::Single(new_n_errors)
                }
                Attempt::Range(first, last) => {
                    let count = last - first + 1;
                    let Some(new_n_errors) = self.n_errors.checked_add(count) else {
                        break;
                    };
                    let start = self.n_errors + 1;
                    self.n_errors = new_n_errors;
                    Attempt::Range(start, new_n_errors)
                }
            };

            self.errors.push((new_attempt, err, timestamp));
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
        let show_timestamps = f.alternate();

        match self.n_errors {
            0 => write!(f, "Unable to {}. (No errors given)", self.doing),
            1 => {
                write!(f, "Unable to {}", self.doing)?;

                if show_timestamps {
                    if let (Some((.., timestamp)), Some(first_at)) =
                        (self.errors.first(), self.first_error_at)
                    {
                        write!(
                            f,
                            " at {} ({})",
                            humantime::format_rfc3339(first_at),
                            FormatTimeAgo(timestamp.elapsed())
                        )?;
                    }
                }

                write!(f, ": ")?;
                fmt_error_with_sources(self.errors[0].1.as_ref(), f)
            }
            n => {
                write!(
                    f,
                    "Tried to {} {} times, but all attempts failed",
                    self.doing, n
                )?;

                if show_timestamps {
                    if let (Some(first_at), Some((.., first_ts)), Some((.., last_ts))) =
                        (self.first_error_at, self.errors.first(), self.errors.last())
                    {
                        let duration = last_ts.saturating_duration_since(*first_ts);

                        write!(f, " (from {} ", humantime::format_rfc3339(first_at))?;

                        if duration.as_secs() > 0 {
                            write!(f, "to {}", humantime::format_rfc3339(first_at + duration))?;
                        }

                        write!(f, ", {})", FormatTimeAgo(last_ts.elapsed()))?;
                    }
                }

                let first_ts = self.errors.first().map(|(.., ts)| ts);
                for (attempt, e, timestamp) in &self.errors {
                    write!(f, "\n{}", attempt)?;

                    if show_timestamps {
                        if let Some(first_ts) = first_ts {
                            let offset = timestamp.saturating_duration_since(*first_ts);
                            if offset.as_secs() > 0 {
                                write!(f, " (+{})", FormatDuration(offset))?;
                            }
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

/// A wrapper for formatting a [`Duration`] in a human-readable way.
/// Produces output like "2m 30s", "5h 12m", "45s", "500ms".
///
/// We use this instead of `humantime::format_duration` because humantime tends to produce overly verbose output.
struct FormatDuration(Duration);

impl Display for FormatDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_duration_impl(self.0, f)
    }
}

/// A wrapper for formatting a [`Duration`] with "ago" suffix.
struct FormatTimeAgo(Duration);

impl Display for FormatTimeAgo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let millis = self.0.as_millis();

        // Special case: very recent times show as "just now" rather than "0s ago" or "0ms ago"
        if secs == 0 && millis == 0 {
            return write!(f, "just now");
        }

        fmt_duration_impl(self.0, f)?;
        write!(f, " ago")
    }
}

/// Internal helper to format a duration.
///
/// This function contains the actual formatting logic to avoid duplication
/// between `FormatDuration` and `FormatTimeAgo`.
fn fmt_duration_impl(duration: Duration, f: &mut Formatter<'_>) -> fmt::Result {
    let secs = duration.as_secs();

    if secs == 0 {
        let millis = duration.as_millis();
        if millis == 0 {
            write!(f, "0s")
        } else {
            write!(f, "{}ms", millis)
        }
    } else if secs < 60 {
        write!(f, "{}s", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        let rem_secs = secs % 60;
        if rem_secs == 0 {
            write!(f, "{}m", mins)
        } else {
            write!(f, "{}m {}s", mins, rem_secs)
        }
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            write!(f, "{}h", hours)
        } else {
            write!(f, "{}h {}m", hours, mins)
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
    #![allow(clippy::disallowed_methods)]
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
        assert_eq!(
            disp,
            "\
Tried to convert some things 3 times, but all attempts failed
Attempt 1: provided string was not `true` or `false`
Attempt 2: invalid digit found in string
Attempt 3: invalid IP address syntax"
        );

        let disp_alt = format!("{:#}", err);
        assert!(disp_alt.contains("Tried to convert some things 3 times, but all attempts failed"));
        assert!(disp_alt.contains("(from 20")); // Year prefix for timestamp
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
        assert_eq!(
            disp,
            "Unable to connect to torproject.org: invalid IP address syntax"
        );

        let disp_alt = format!("{:#}", err);
        assert!(disp_alt.contains("Unable to connect to torproject.org at 20")); // Year prefix
        assert!(disp_alt.contains("invalid IP address syntax"));
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
        assert_eq!(
            disp,
            "\
Tried to parse some integers 3 times, but all attempts failed
Attempts 1..3: invalid digit found in string"
        );

        let disp_alt = format!("{:#}", err);
        assert!(disp_alt.contains("Tried to parse some integers 3 times, but all attempts failed"));
        assert!(disp_alt.contains("(from 20")); // Year prefix for timestamp
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

    #[test]
    fn extend_from_retry_preserve_timestamps() {
        let n1 = Instant::now();
        let n2 = n1 + Duration::from_secs(10);
        let n3 = n1 + Duration::from_secs(20);

        let mut err1: RetryError<anyhow::Error> = RetryError::in_attempt_to("do first thing");
        let mut err2: RetryError<anyhow::Error> = RetryError::in_attempt_to("do second thing");

        err2.push_timed(anyhow::Error::msg("e1"), n1, None);
        err2.push_timed(anyhow::Error::msg("e2"), n2, None);

        // err1 is empty initially
        assert!(err1.first_error_at.is_none());

        err1.extend_from_retry_error(err2);

        assert_eq!(err1.len(), 2);
        // The timestamps should be preserved
        assert_eq!(err1.errors[0].2, n1);
        assert_eq!(err1.errors[1].2, n2);

        // Add another error to err1 to ensure mixed sources work
        err1.push_timed(anyhow::Error::msg("e3"), n3, None);
        assert_eq!(err1.len(), 3);
        assert_eq!(err1.errors[2].2, n3);
    }

    #[test]
    fn extend_from_retry_preserve_ranges() {
        let n1 = Instant::now();
        let mut err1: RetryError<anyhow::Error> = RetryError::in_attempt_to("do thing 1");

        // Push 2 errors
        err1.push(anyhow::Error::msg("e1"));
        err1.push(anyhow::Error::msg("e2"));
        assert_eq!(err1.n_errors, 2);

        let mut err2: RetryError<anyhow::Error> = RetryError::in_attempt_to("do thing 2");
        // Push 3 identical errors to create a range
        let _err_msg = anyhow::Error::msg("repeated");
        err2.push_timed(anyhow::Error::msg("repeated"), n1, None);
        err2.push_timed(anyhow::Error::msg("repeated"), n1, None);
        err2.push_timed(anyhow::Error::msg("repeated"), n1, None);

        // Dedup err2 so it has a range
        err2.dedup_by(|e1, e2| e1.to_string() == e2.to_string());
        assert_eq!(err2.len(), 1); // collapsed to 1 entry
        match err2.errors[0].0 {
            Attempt::Range(1, 3) => {}
            _ => panic!("Expected range 1..3"),
        }

        // Extend err1 with err2
        err1.extend_from_retry_error(err2);

        assert_eq!(err1.len(), 3); // 2 singles + 1 range
        assert_eq!(err1.n_errors, 5); // 2 + 3 = 5 total attempts

        // Check the range indices
        match err1.errors[2].0 {
            Attempt::Range(3, 5) => {}
            ref x => panic!("Expected range 3..5, got {:?}", x),
        }
    }
}
