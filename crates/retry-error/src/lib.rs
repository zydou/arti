#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::error::Error;
use std::fmt::{self, Debug, Display, Error as FmtError, Formatter};
use std::iter;

/// An error type for use when we're going to do something a few times,
/// and they might all fail.
///
/// To use this error type, initialize a new RetryError before you
/// start trying to do whatever it is.  Then, every time the operation
/// fails, use [`RetryError::push()`] to add a new error to the list
/// of errors.  If the operation fails too many times, you can use
/// RetryError as an [`Error`] itself.
#[derive(Debug, Clone)]
pub struct RetryError<E> {
    /// The operation we were trying to do.
    doing: String,
    /// The errors that we encountered when doing the operation.
    errors: Vec<(Attempt, E)>,
    /// The total number of errors we encountered.
    ///
    /// This can differ from errors.len() if the errors have been
    /// deduplicated.
    n_errors: usize,
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
        }
    }
    /// Add an error to this RetryError.
    ///
    /// You should call this method when an attempt at the underlying operation
    /// has failed.
    pub fn push<T>(&mut self, err: T)
    where
        T: Into<E>,
    {
        if self.n_errors < usize::MAX {
            self.n_errors += 1;
            let attempt = Attempt::Single(self.n_errors);
            self.errors.push((attempt, err.into()));
        }
    }

    /// Return an iterator over all of the reasons that the attempt
    /// behind this RetryError has failed.
    pub fn sources(&self) -> impl Iterator<Item = &E> {
        self.errors.iter().map(|(_, e)| e)
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

        for (attempt, err) in old_errs {
            if let Some((ref mut last_attempt, last_err)) = self.errors.last_mut() {
                if same_err(last_err, &err) {
                    last_attempt.grow();
                } else {
                    self.errors.push((attempt, err));
                }
            } else {
                self.errors.push((attempt, err));
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
        let v: Vec<_> = self.errors.into_iter().map(|x| x.1).collect();
        v.into_iter()
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
                write!(f, "Unable to {}: ", self.doing)?;
                fmt_error_with_sources(self.errors[0].1.as_ref(), f)
            }
            n => {
                write!(
                    f,
                    "Tried to {} {} times, but all attempts failed",
                    self.doing, n
                )?;

                for (attempt, e) in &self.errors {
                    write!(f, "\n{}: ", attempt)?;
                    fmt_error_with_sources(e.as_ref(), f)?;
                }
                Ok(())
            }
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
    #![allow(clippy::unchecked_duration_subtraction)]
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
        assert_eq!(
            disp,
            "\
Tried to convert some things 3 times, but all attempts failed
Attempt 1: provided string was not `true` or `false`
Attempt 2: invalid digit found in string
Attempt 3: invalid IP address syntax"
        );
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
        ));
        assert!(err.n_errors == usize::MAX);
        assert!(err.len() == 1);

        err.push(errors.pop().expect("parser did not fail"));
        assert!(err.n_errors == usize::MAX);
        assert!(err.len() == 1);
    }
}
