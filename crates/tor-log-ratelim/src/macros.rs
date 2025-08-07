//! Macros to make it easier to work with rate-limited logs
//!

/// Log a rate-limited failure message.
///
/// This macro looks at a single `Result<T,E>`,
/// and keeps track of how many times the `Ok` and `Err` branches are seen.
/// After a delay, it reports via [`tracing::event!`]
/// how many errors it has seen since its last report.
/// (It only reports an absence of errors
/// when such an absence has followed
/// an error report.)
///
/// ## A simple example
///
/// ```
/// # use std::num::ParseIntError;
/// # let s = "1234";
/// # let source = "the cache";
/// use tor_log_ratelim::log_ratelim;
///  let r: Result<u8, ParseIntError> = s.parse();
///
/// log_ratelim!(
///   // The activity we were doing.
///   "Parsing a value from {}", source;
///   // The result we got.
///   r;
/// );
/// ```
///
/// This invocation could report errors like
/// ```text
/// WARN: Parsing a value from the cache: error (occurred 9/12 times in the last 5 minutes): number too large to fit in target type
/// ```
///
/// After a while without errors, it might log:
/// ```text
/// WARN: Parsing a value from the cache: now working (occurred 0/100 times in th last hour)
/// ```
///
/// ## Important concept: Activities
///
/// Every invocation of `log_ratelim!` defines a _set_ of rate limits
/// with respect to a collection of **activities**.  
/// Each separate **activity** value gets its own rate limit.
/// This lets you have separate rate limits for different operations,
/// such as connecting to different parties,
/// or invoking different programs.
///
/// Typical activities might be
/// `"Connecting to port {}", p`
/// or
/// `"Trying to start program {}", p`
///
/// (These activities should be described using a verb ending with "-ing",
/// to make the output nice.)
///
/// ## Requirements on the error type.
///
/// The error type for each `Result` passed to this macro must implement:
///  * [`Clone`]
///  * [`Send`]
///  * [`Error`](std::error::Error)
///
/// ## Reports are representative
///
/// No matter how many failures are seen between log messages,
/// `log_ratelim!` only records and reports
/// one error for each time it logs.
///
/// Its current behavior is to record and report
/// the _first_ error for each logged interval,
/// and discard the others.  
/// This can lead to confusing results if the error is not representative.
///
/// ## Advanced syntax
///
/// The `log_ratelim` macro can record additional information for its
/// representative error report,
/// and can log information on successes as well.
///
/// A full invocation of `log_ratelim!` looks like this:
///
/// ```
/// # use std::num::ParseIntError;
/// # let s = "1234";
/// # let source = "the cache";
/// # let more_information = |_| "";
/// use tor_log_ratelim::log_ratelim;
/// let r: Result<u8, ParseIntError> = s.parse();
/// log_ratelim!(
///   "Parsing a value from {}", source;
///   r;
///   Err(x) => WARN, "The problem was {}", more_information(x);
///   Ok(v) => TRACE, "Parsed {} successfully", v;
/// );
/// ```
///
/// Here the clause starting with `Err(x)`
/// tells the logger to include a message along with the error report,
/// and we explicitly specifies the level at which
/// to log our failure reports.
///
/// Note that the error itself is **always** reported;
/// there is no need to say
/// `Err(e) => WARN, "{}", e`.
/// In fact, doing so will create a redundant report of
/// the error.
//
// TODO: I don't think it makes sense to have an Ok() logger.
// Instead, we could just say
//    log_ratelim!("Parsing a value from {}", source; r;);
//    trace!("parsed value from {}: {:?}", source, r);
// This is probably better, since it logs a trace for every occurrence.
//
/// The clause starting with `Ok(v)` tells the logger what to do on success:
/// each individual success causes a _non-rate-limited_
/// message at TRACE level.
///
/// The `Ok() ...` clause
/// and the `Err() ...` clause
/// are both optional.
///
/// Within the Err() clause,
/// the format string and its arguments
/// are optional.
//
// TODO performance notes:
//
// There are many opportunities for possibly making this code go faster:
//  - Optimize the case where there is only one activity.
//  - Use a non-string key to distinguish activities, to avoid formatting
//    the activity string needlessly.
//  - Limit copies (of activity and of error).
//  - Use Event and Metadata from the tracing crate to defer formatting
//  - Check Metadata early for the case where we don't want to report the
//    event at all.
//
// Let's not pursue any of these until we know that this code actually
// shows up in a critical path.
#[macro_export]
macro_rules! log_ratelim {
  // ====
  // Actual implementation for rate-limited logging.
  // ====

  // Nobody invokes this syntax directly; it's used as a common body for the
  // various other syntaxes.
  {
    @impl activity_format: ( $act_fmt:literal $(, $act_arg:expr)* ) ;
          result: ($result:expr ) ;
          on_error: (Err($err_pat:pat), $err_level:ident $(, $err_fmt:literal $(, $err_arg:expr)* )? );
          $( on_ok: (Ok($ok_pat:pat), $ok_level:ident, $ok_fmt:literal $(, $ok_arg:expr)*  ); )?
  } => {
    #[allow(clippy::redundant_closure_call)]
    (||{
    use $crate::macro_prelude::*;
    let Some(runtime) = rt_support() else {
      // Nobody has called `install_runtime()`: we should just log whatever
      // happened and not worry about the rate-limiting.
      match &$result {
        #[allow(clippy::redundant_pattern)]
        Err(the_error @ $err_pat) => {
          tracing::event!(
            tracing::Level::$err_level,
            concat!($act_fmt, $(": ", $err_fmt, )? ": {}"),
            $($act_arg,)*
            $( $($err_arg, )* )?
            the_error.report()
          );
        }
        $(Ok($ok_pat) => {
          tracing::event!(
            tracing::Level::$ok_level,
            $ok_fmt
            $(, $ok_arg)*
          );
        })?
        #[allow(unreachable_patterns)]
        Ok(_) => {}
      }
      return;
    };

    /// An implementation of Loggable for this log message.
    //
    // We use a separate implementation here so that the tracing metadata will get
    // constructed correctly.  If we called tracing::event! from a location in
    // `tor-log-ratelim`, all the messages would appear to originate from there.
    //
    // (TODO: We could use tracing::Metadata explicitly, perhaps? That might be hard.)
    struct Lg(LogState);
    impl Loggable for Lg {
        fn flush(&mut self, summarizing: std::time::Duration) -> Activity {
            let activity = self.0.activity();
            match activity {
               Activity::Active => {
                  tracing::event!(
                      tracing::Level::$err_level,
                      "{}",
                      self.0.display_problem(summarizing)
                  );
               }
               Activity::Dormant => {
                  tracing::event!(
                      // Using err_level here is in some respects confusing:
                      // if the _presence_ of the problem is (say) a WARN,
                      // why should its newfound absence also be a WARN?
                      //
                      // We have had to decide which is worse:
                      // that a user only watching WARNs
                      // might not see a problem has gone away,
                      // or that a non-problem would be reported
                      // at an excessive severity.
                      // We went with the latter.
                      tracing::Level::$err_level,
                      "{}",
                      self.0.display_recovery(summarizing)
                  );
               }
            }
            self.0.reset();
            activity
        }
    }

    /// A lazy map from activity keys to weak RateLim handles.
    //
    // The strong reference for each RateLim is held by a task that flushes
    // the logger as appropriate, and drops the strong reference once it's
    // quiescent.
    static LOGGERS: LazyLock<Mutex<WeakValueHashMap<String, Weak<RateLim<Lg>>>>> =
    LazyLock::new(|| Mutex::new(WeakValueHashMap::new()));

    // We assign a separate rate limit for each activity.
    // For now, this is string-ly typed.
    let activity = format!($act_fmt $(, $act_arg)*);
    let key = activity.clone();

    match &$result {
      #[allow(clippy::redundant_pattern)]
      Err(the_error @ $err_pat) => {
        // The operation failed.
        //
        // 1) Create a rate-limited logger for this activity if one  did not
        //    already exist.
        let logger = LOGGERS
          .lock()
          .expect("poisoned lock")
          .entry(key)
          .or_insert_with(|| RateLim::new(Lg(LogState::new(activity))));
        // 2) Note failure in the activity with note_fail().
        logger.event(runtime, |lg| lg.0.note_fail(||
          // 2b) If this is the first time that this activity failed since the
          //     last flush, record the formatted err_msg, and a Clone of the error.
          (
            $crate::log_ratelim!{@first_nonempty
              { $( Some(format!($err_fmt $(, $err_arg)* )) )? }
              { None }
            },
            Some(Box::new(the_error.clone()))
          )
        ));
      }
      Ok($crate::log_ratelim!{@first_nonempty { $($ok_pat)? } {_} }) => {
        // The operation succeeded.
        //
        // 1) If this activity is tracked, call note_ok() on it.
        if let Some(logger) = LOGGERS
          .lock()
          .expect("poisoned lock")
          .get(&key) {
            logger.nonevent(|lg| lg.0.note_ok());
          }
        // 2) If we have a per-success item to log, log it.
        $(
        tracing::event!(tracing::Level::$ok_level, $ok_fmt $(, $ok_arg )* );
        )?
      }
    }
  })()
  };

  // ======
  // Exposed, documented syntax.
  // ======

  // Regular invocation with an Err(_) case.
  {
    $act_fmt:literal $(, $act_arg:expr )* $(,)? ;
    $result:expr ;
    Err($err_pat:pat) => $err_level:ident $(, $err_fmt:literal $(, $err_arg:expr)* )? $(,)?
    $(; Ok($ok_pat:pat) => $ok_level:ident, $ok_fmt:literal $(, $ok_arg:expr )* $(,)?  )?
    $(;)?
  } => {
    $crate::log_ratelim!{
      @impl
        activity_format: ( $act_fmt $(, $act_arg)* );
        result: ($result);
        on_error: (Err($err_pat), $err_level $(, $err_fmt $(, $err_arg)* )? );
        $( on_ok: ( Ok($ok_pat), $ok_level, $ok_fmt $(, $ok_arg)* ); )?
    }
  };
  // Regular invocation with no Err(_) case.
  {
    $act_fmt:literal $(, $act_arg:expr )* $(,)? ;
    $result:expr
    $(; Ok($ok_pat:pat) => $ok_level:ident, $ok_fmt:literal $(, $ok_arg:expr )* $(,)? )?
    $(;)?
  } => {
    $crate::log_ratelim!{
      @impl
        activity_format: ( $act_fmt $(, $act_arg)* );
        result: ($result);
        on_error: (Err(_), WARN);
        $( on_ok: ( Ok($ok_pat), $ok_level, $ok_fmt $(, $ok_arg)* ); )?
    }
  };

  // Expand to the first of two bodies that has at least one token in it.
  { @first_nonempty { $($a:tt)+ } { $($b:tt)* }} => { $($a)+ };
  { @first_nonempty { } { $($b:tt)* } } => { $($b)+ };
}

#[cfg(test)]
mod test_syntax {
    #![allow(dead_code)]

    #[derive(Clone, Debug, thiserror::Error)]
    enum MyErr {
        #[error("it didn't work")]
        DidntWork,
    }
    impl MyErr {
        fn badness(&self) -> u8 {
            3
        }
    }

    /// This doesn't actually run or test anything; it just makes sure that all
    /// the different syntaxes work.
    fn various_syntaxes(friend: &str, r: &Result<u32, MyErr>) {
        log_ratelim!(
          "saying hi to {}", friend;
          r;
        );

        log_ratelim!(
          "saying hi to {}", friend;
          r;
          Err(_) => WARN;
        );

        log_ratelim!(
          "saying hi to {}", friend;
          r;
          Err(e) => WARN, "badness={}", e.badness();
        );

        log_ratelim!(
          "saying hi to {}", friend;
          r;
          Ok(v) => TRACE, "nothing bad happened; v={}", v;
        );

        log_ratelim!(
          "saying hi to {}", friend;
          r;
          Ok(v) => TRACE, "nothing bad happened; v={}", v;
        );

        log_ratelim!(
          "saying hi to {}", friend;
          r;
          Err(e) => WARN, "badness={}", e.badness();
          Ok(v) => TRACE, "nothing bad happened; v={}", v;
        );
    }
}
