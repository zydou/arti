# Notes about dirmirror operation return types

There are two primary functions: `StaticEngine::execute` and `operate()`.
`operate()` is the top-level public entry point that wraps around `execute()`.

`execute()` receives the following inputs:
- Database pool
- ConsensusBoundData
- Some RetryDelay handler
- Current time

`operate()` only receives the database pool plus potentially a function that
returns the current system time.  It is responsible for initialiazing and
discarding the ConsensusBoundData but should not touch it.

`operate()` shall run forever in the current async task and only return in the
case of a fatal error, hence why it's return type ought to be
`Result<Void, FatalError>`.

`execute()` on the other hand is repeatedly called by `operate()` and returns a
`(Result<ExecSuccess, ExecError>, Timeout, ExecReportInfo)`.  The
`ExecReportInfo` only contains information that the caller may safely discard.
It is primarily for logging purposes.  `Timeout` is a type that implies a time
that the caller should wait before invoking the FSM again.  I have not yet decided
on whether to make this a `Duration`, `SystemTime`, or `Instant` or an `Option<>`
wrapped around those.  Last but not least, the `Result` contains the actual
information on how the FSM exited.  In the success case, `ExecSuccess` may either
be `ExecSuccess::Continue` or `ExecSuccess::Finished`, both implying different
kind of successes, with the latter one giving the caller the responsibility to
discard and re-initialize the `ConsensusBoundData`.  In the error case,
`ExecError` contains the error variant.  An associated method,
`ExecError::disposition` determines whether the error is fatal and it will be
the responsibility of the caller to call this.  This disposition method returns
a `Result<(), ErrorIsFatal>`, with `ErrorIsFatal` being a ZST token type that
the caller shall transform into a `FatalError` and return that as the result
of `operate()`, which in turn not only contains this ZST but also additional
information such as the `ExecError` and potentially logging information.

Some additional notes for the implementation are:
* `ConsensusBoundData` ought to be only modified from within `execute()` but
  owned by `operate()`, which also has the responsibility to initialize and
  discard it.
* Timeout calculation is performed solely by `execute()`.
* `RetryDelay` is kept outside of `ConsensusBoundData` and managed as a global
  (global as in: persisting FSM instances) state.

## Sketch

This is a sketch from Diziet, not 100% perfect or complete but kept for
historical reasons.  It diverges slightly from the design outlined above but
matches in spirit:
```
# suggestions from Diziet, from the MR, collated into sketch

/// Successful return from `execute`, indicating how `operate` should proceed
enum ExecSuccess {
    /// We made progress and should continue immediately from whatever the
    /// current (new) state is.
    Continue,

    /// We must wait `timeout` and then restart again from beginning,
    /// discarding all existing in-memory state.
    ///
    /// Used when:
    ///
    ///   * We have downloaded the entire consensus
    ///   * all descriptors that we haven't got are known to be malformed
    Finished {
        restart_time: SystemTime,
    },
}

/// Error from `execute`.
///
/// Might be fatal, or not.
///
/// `operate` asks `diposition` about this error, to figure out how to handle it.
enum ExecError {
    // all existing contents of `OperationErrorKind`
}

/// A fatal error, the dirmirror cannot continue
pub struct FatalError {
    /// The underlying error.
    ///
    /// Invariant: known to be fatal, as determined by `ExecError::disposition`
    error: ExecError,
    is_fatal: ErrorIsFatal,
    log_info: ErrorLogInfo,
};

/// Supplementary information for an error
///
/// Must only be used for logging and reporting, not for control flow.
struct ExecReportInfo {
    // state, request, additonal_errors from `OperationResult`
    // fields from, or a, `OperationStatusProgress`?
}

/// Error is fatal token returned by `ExecError::disposition`
struct ErrorIsFatal;

impl ExecError {
    /// How should we deal with this error?
    ///
    ///  * `Ok`: log the error, wait this long (perhaps no time at all) and continue
    ///  * `Err`: this was a fatal error, we should stop
    fn disposition(&self) -> Result<(), ErrorIsFatal> {
        // contents of the `match kind` from near existing operation.rs:557 go here
    }
}

    async fn execute<R: Rng>(
...
    ) -> (Result<(), ExecError>, ExecReportInfo) {
        let mut info = OperationLogInfo::default();
...
        let r = match state {
            State::LoadConsensus => self.load_consensus(&mut info, pool, data, now, rng),
...
        };

        (r, log_info)
    }

pub(crate) async fn operate<T: FlavoredConsensusUnverified, R: Rng>(
...
) -> Result<Void, FatalError> {

    {
        let (res, log_info) =
            engine.execute(&pool, &mut cbd, now_fn().into(), rng).await;

xxxx timeout handling not from disposition

        let wait;
        match res {
            Ok(ExecSuccess::Continue) => wait = ZERO,
            Ok(ExecSuccess::Reset { timeoeut }) => {
                cbd = default();
                wait = timeout
            },

    Err(error) => match error.disposition() {

        Err(is_fatal) => {

            log_info.augment_span(|| error_report!(...));

            return Err(FatalError { error, is_fatal, log_info });

        }

        Ok(w) => {

    log_info.augment_spabn(|| debug_report!(...));

    wait = w

      }

        };

        sleep(wait);
    }
}
```
