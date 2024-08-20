//! The state for a single backend for a basic log_ratelim().

use std::{error::Error as StdError, fmt, time::Duration};

/// A type-erased error type with the minimum features we need.
type DynError = Box<dyn StdError + Send + 'static>;

/// The state for a single rate-limited log message.
///
/// This type is used as a common implementation helper for the
/// [`log_ratelim!()`](crate::log_ratelim) macro.
///
/// Its role is to track successes and failures,
/// to remember some error information,
/// and produce Display-able messages when a [RateLim](crate::ratelim::RateLim)
/// decides that it is time to log.
///
/// This type has to be `pub`, but it is hidden:
/// using it directly will void your semver guarantees.
pub struct LogState {
    /// How many times has the activity failed since we last reset()?
    n_fail: usize,
    /// How many times has the activity succeeded since we last reset()?
    n_ok: usize,
    /// A string representing the activity itself.
    activity: String,
    /// If present, a message that we will along with `error`.
    error_message: Option<String>,
    /// If present, an error that we will log when reporting an error.
    error: Option<DynError>,
}
impl LogState {
    /// Create a new LogState with no recorded errors or successes.
    pub fn new(activity: String) -> Self {
        Self {
            n_fail: 0,
            n_ok: 0,
            activity,
            error_message: None,
            error: None,
        }
    }
    /// Discard all success and failure information in this LogState.
    pub fn reset(&mut self) {
        *self = Self::new(std::mem::take(&mut self.activity));
    }
    /// Record a single failure in this LogState.
    ///
    /// If this is the _first_ recorded failure, invoke `msg_fn` to get an
    /// optional failure message and an optional error to be reported as an
    /// example of the types of failures we are seeing.
    pub fn note_fail(&mut self, msg_fn: impl FnOnce() -> (Option<String>, Option<DynError>)) {
        if self.n_fail == 0 {
            let (m, e) = msg_fn();
            self.error_message = m;
            self.error = e;
        }
        self.n_fail = self.n_fail.saturating_add(1);
    }
    /// Record a single success in this LogState.
    pub fn note_ok(&mut self) {
        self.n_ok = self.n_ok.saturating_add(1);
    }
    /// Check whether there is any activity to report from this LogState.
    pub fn activity(&self) -> crate::Activity {
        if self.n_fail == 0 {
            crate::Activity::Dormant
        } else {
            crate::Activity::Active
        }
    }
    /// Return a wrapper type for reporting that we have observed problems in
    /// this LogState.
    pub fn display_problem(&self, dur: Duration) -> impl fmt::Display + '_ {
        DispProblem(self, dur)
    }
    /// Return a wrapper type for reporting that we have not observed problems in
    /// this LogState.
    pub fn display_recovery(&self, dur: Duration) -> impl fmt::Display + '_ {
        DispWorking(self, dur)
    }
}

/// Helper: wrapper for reporting problems via Display.
struct DispProblem<'a>(&'a LogState, Duration);
impl<'a> fmt::Display for DispProblem<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: error", self.0.activity)?;
        let n_total = self.0.n_fail.saturating_add(self.0.n_ok);
        write!(
            f,
            " (problem occurred {}/{} times in the last {})",
            self.0.n_fail,
            n_total,
            humantime::format_duration(self.1)
        )?;
        if let Some(msg) = self.0.error_message.as_ref() {
            write!(f, ": {}", msg)?;
        }
        if let Some(err) = self.0.error.as_ref() {
            let err = Adaptor(err);
            write!(f, ": {}", tor_error::Report(&err))?;
        }
        Ok(())
    }
}
/// Helper: wrapper for reporting a lack of problems via Display.
struct DispWorking<'a>(&'a LogState, Duration);
impl<'a> fmt::Display for DispWorking<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: now working", self.0.activity)?;
        write!(
            f,
            " (problem occurred 0/{} times in the last {})",
            self.0.n_ok,
            humantime::format_duration(self.1)
        )?;
        Ok(())
    }
}
/// Helper struct to make Report work correctly.
///
/// We can't use ErrorReport since our `Box<>`ed error is not only `dyn Error`, but also `Send`.
#[derive(Debug)]
struct Adaptor<'a>(&'a DynError);
impl<'a> AsRef<dyn StdError + 'static> for Adaptor<'a> {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {

    #![allow(clippy::redundant_closure)]
    use super::*;
    use crate::Activity;
    use std::time::Duration;
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[error("TestError is here!")]
    struct TestError {
        source: TestErrorBuddy,
    }

    #[derive(Debug, Error)]
    #[error("TestErrorBuddy is here!")]
    struct TestErrorBuddy;

    #[test]
    fn display_problem() {
        let duration = Duration::from_millis(10);
        let mut ls: LogState = LogState::new("test".to_string());
        let mut activity: Activity = ls.activity();
        assert_eq!(Activity::Dormant, activity);
        assert_eq!(ls.n_fail, 0);
        fn err_msg() -> (Option<String>, Option<DynError>) {
            (
                Some("test".to_string()),
                Some(Box::new(TestError {
                    source: TestErrorBuddy,
                })),
            )
        }
        ls.note_fail(|| err_msg());
        assert_eq!(ls.n_fail, 1);
        let problem = ls.display_problem(duration);
        let expected_problem = String::from(
            "test: error (problem occurred 1/1 times in the last 10ms): test: error: TestError is here!: TestErrorBuddy is here!"
        );
        let str_problem = format!("{problem}");
        assert_eq!(expected_problem, str_problem);
        activity = ls.activity();
        assert_eq!(Activity::Active, activity);
    }

    #[test]
    fn display_recovery() {
        let duration = Duration::from_millis(10);
        let mut ls = LogState::new("test".to_string());
        ls.note_ok();
        assert_eq!(ls.n_ok, 1);
        {
            let recovery = ls.display_recovery(duration);
            let expected_recovery =
                String::from("test: now working (problem occurred 0/1 times in the last 10ms)");
            let str_recovery = format!("{recovery}");
            assert_eq!(expected_recovery, str_recovery);
        }
        ls.reset();
        assert_eq!(ls.n_ok, 0);
    }
}
