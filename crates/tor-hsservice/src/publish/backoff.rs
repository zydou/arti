//! Helpers for retrying a fallible operation according to a backoff schedule.
//!
//! [`Runner::run`] retries the specified operation according to the [`BackoffSchedule`] of the
//! [`Runner`]. Users can customize the backoff behavior by implementing [`BackoffSchedule`].

// TODO: this is a (somewhat) general-purpose utility, so it should probably be factored out of
// tor-hsservice

use std::pin::Pin;

use futures::future::FusedFuture;

use tor_rtcompat::TimeoutError;

use super::*;

/// A runner for a fallible operation, which retries on failure according to a [`BackoffSchedule`].
pub(super) struct Runner<B: BackoffSchedule, R: Runtime> {
    /// A description of the operation we are trying to do.
    doing: String,
    /// The backoff schedule.
    schedule: B,
    /// The runtime.
    runtime: R,
}

impl<B: BackoffSchedule, R: Runtime> Runner<B, R> {
    /// Create a new `Runner`.
    pub(super) fn new(doing: String, schedule: B, runtime: R) -> Self {
        Self {
            doing,
            schedule,
            runtime,
        }
    }

    /// Run `fallible_fn`, retrying according to the [`BackoffSchedule`] of this `Runner`.
    ///
    /// If `fallible_fn` eventually returns `Ok(_)`, return that output. Otherwise,
    /// keep retrying until either `fallible_fn` has failed too many times, or until
    /// a fatal error occurs.
    pub(super) async fn run<T, E, F>(
        mut self,
        mut fallible_fn: impl FnMut() -> F,
    ) -> Result<T, BackoffError<E>>
    where
        E: RetriableError,
        F: Future<Output = Result<T, E>> + Send,
    {
        let mut retry_count = 0;
        let mut errors = RetryError::in_attempt_to(self.doing.clone());

        // When this timeout elapses, the `Runner` will stop retrying the fallible operation.
        //
        // A `overall_timeout` of `None` means there is no time limit for the retries.
        let mut overall_timeout = match self.schedule.overall_timeout() {
            Some(timeout) => Either::Left(Box::pin(self.runtime.sleep(timeout))),
            None => Either::Right(future::pending()),
        }
        .fuse();

        loop {
            // Bail if we've exceeded the number of allowed retries.
            if matches!(self.schedule.max_retries(), Some(max_retry_count) if retry_count >= max_retry_count)
            {
                return Err(BackoffError::MaxRetryCountExceeded(errors));
            }

            let mut fallible_op = optionally_timeout(
                &self.runtime,
                fallible_fn(),
                self.schedule.single_attempt_timeout(),
            );

            trace!(attempt = (retry_count + 1), "{}", self.doing);

            select_biased! {
                _res = overall_timeout => {
                    // The timeout has elapsed, so stop retrying and return the errors
                    // accumulated so far.
                    return Err(BackoffError::Timeout(errors))
                }
                res = fallible_op => {
                    // TODO: the error branches in the match below have different error types,
                    // so we must compute should_retry and delay separately, on each branch.
                    //
                    // We could refactor this to extract the error using
                    // let err = match res { ... } and call err.should_retry()
                    // and next_delay() after the match, but this will involve
                    // rethinking the BackoffSchedule trait and/or RetriableError
                    // (currently RetriableError is Clone, so it's not object safe).
                    let (should_retry, delay) = match res {
                        Ok(Ok(res)) => return Ok(res),
                        Ok(Err(e)) => {
                            // The operation failed: check if we can retry it.
                            let should_retry = e.should_retry();

                            debug!(
                                attempt=(retry_count + 1), can_retry=should_retry,
                                "failed to {}: {e}", self.doing
                            );

                            errors.push(e.clone());
                            (e.should_retry(), self.schedule.next_delay(&e))
                        }
                        Err(e) => {
                            trace!("fallible operation timed out; retrying");
                            (e.should_retry(), self.schedule.next_delay(&e))
                        },
                    };

                    if should_retry {
                        retry_count += 1;

                        let Some(delay) = delay else {
                            return Err(BackoffError::ExplicitStop(errors));
                        };

                        // Introduce the specified delay between retries
                        let () = self.runtime.sleep(delay).await;

                        // Try again unless the entire operation has timed out.
                        continue;
                    }

                    return Err(BackoffError::FatalError(errors));
                },
            }
        }
    }
}

/// Wrap a [`Future`] with an optional timeout.
///
/// If `timeout` is `Some`, returns a [`Timeout`](tor_rtcompat::Timeout)
/// that resolves to the value of `future` if the future completes within `timeout`,
/// or a [`TimeoutError`] if it does not.
/// If `timeout` is `None`, returns a new future which maps the specified `future`'s
/// output type to a `Result::Ok`.
fn optionally_timeout<'f, R, F>(
    runtime: &R,
    future: F,
    timeout: Option<Duration>,
) -> Pin<Box<dyn FusedFuture<Output = Result<F::Output, TimeoutError>> + Send + 'f>>
where
    R: Runtime,
    F: Future + Send + 'f,
{
    match timeout {
        Some(timeout) => Box::pin(runtime.timeout(timeout, future).fuse()),
        None => Box::pin(future.map(Ok)),
    }
}

/// A trait that specifies the parameters for retrying a fallible operation.
pub(super) trait BackoffSchedule {
    /// The maximum number of retries.
    ///
    /// A return value of `None` indicates is no upper limit for the number of retries, and that
    /// the operation should be retried until [`BackoffSchedule::overall_timeout`] time elapses (or
    /// indefinitely, if [`BackoffSchedule::overall_timeout`] returns `None`).
    fn max_retries(&self) -> Option<usize>;

    /// The total amount of time allowed for the retriable operation.
    ///
    /// A return value of `None` indicates the operation should be retried until
    /// [`BackoffSchedule::max_retries`] number of retries are exceeded (or indefinitely, if
    /// [`BackoffSchedule::max_retries`] returns `None`).
    fn overall_timeout(&self) -> Option<Duration>;

    /// The total amount of time allowed for a single operation.
    fn single_attempt_timeout(&self) -> Option<Duration>;

    /// Return the delay to introduce before the next retry.
    ///
    /// The `error` parameter contains the error returned by the fallible operation. This enables
    /// implementors to (optionally) implement adaptive backoff. For example, if the operation is
    /// sending an HTTP request, and the error is a 429 (Too Many Requests) HTTP response with a
    /// `Retry-After` header, the implementor can implement a backoff schedule where the next retry
    /// is delayed by the value specified in the `Retry-After` header.
    fn next_delay<E: RetriableError>(&mut self, error: &E) -> Option<Duration>;
}

/// The type of error encountered while running a fallible operation.
#[derive(Clone, Debug, thiserror::Error)]
pub(super) enum BackoffError<E> {
    /// A fatal (non-transient) error occurred.
    #[error("A fatal (non-transient) error occurred")]
    FatalError(RetryError<E>),

    /// Ran out of retries.
    #[error("Ran out of retries")]
    MaxRetryCountExceeded(RetryError<E>),

    /// Exceeded the maximum allowed time.
    #[error("Timeout exceeded")]
    Timeout(RetryError<E>),

    /// The [`BackoffSchedule`] told us to stop retrying.
    #[error("Stopped retrying as requested by BackoffSchedule")]
    ExplicitStop(RetryError<E>),
}

impl<E> From<BackoffError<E>> for RetryError<E> {
    fn from(e: BackoffError<E>) -> Self {
        match e {
            BackoffError::FatalError(e)
            | BackoffError::MaxRetryCountExceeded(e)
            | BackoffError::Timeout(e)
            | BackoffError::ExplicitStop(e) => e,
        }
    }
}

/// A trait for representing retriable errors.
pub(super) trait RetriableError: StdError + Clone {
    /// Whether this error is transient.
    fn should_retry(&self) -> bool;
}

impl RetriableError for TimeoutError {
    fn should_retry(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
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
    use std::sync::Arc;

    use std::iter;
    use std::sync::RwLock;

    use tor_async_utils::oneshot;
    use tor_rtcompat::{BlockOn, SleepProvider};
    use tor_rtmock::MockRuntime;

    const SHORT_DELAY: Duration = Duration::from_millis(10);
    const TIMEOUT: Duration = Duration::from_millis(100);
    const SINGLE_TIMEOUT: Duration = Duration::from_millis(50);
    const MAX_RETRIES: usize = 5;

    macro_rules! impl_backoff_sched {
        ($name:ty, $max_retries:expr, $timeout:expr, $single_timeout:expr, $next_delay:expr) => {
            impl BackoffSchedule for $name {
                fn max_retries(&self) -> Option<usize> {
                    $max_retries
                }

                fn overall_timeout(&self) -> Option<Duration> {
                    $timeout
                }

                fn single_attempt_timeout(&self) -> Option<Duration> {
                    $single_timeout
                }

                #[allow(unused_variables)]
                fn next_delay<E: RetriableError>(&mut self, error: &E) -> Option<Duration> {
                    $next_delay
                }
            }
        };
    }

    struct BackoffWithMaxRetries;

    impl_backoff_sched!(
        BackoffWithMaxRetries,
        Some(MAX_RETRIES),
        None,
        None,
        Some(SHORT_DELAY)
    );

    struct BackoffWithTimeout;

    impl_backoff_sched!(
        BackoffWithTimeout,
        None,
        Some(TIMEOUT),
        None,
        Some(SHORT_DELAY)
    );

    struct BackoffWithSingleTimeout;

    impl_backoff_sched!(
        BackoffWithSingleTimeout,
        Some(MAX_RETRIES),
        None,
        Some(SINGLE_TIMEOUT),
        Some(SHORT_DELAY)
    );

    /// A potentially retriable error.
    #[derive(Debug, Copy, Clone, thiserror::Error)]
    enum TestError {
        /// A fatal error
        #[error("A fatal test error")]
        Fatal,
        /// A transient error
        #[error("A transient test error")]
        Transient,
    }

    impl RetriableError for TestError {
        fn should_retry(&self) -> bool {
            match self {
                Self::Fatal => false,
                Self::Transient => true,
            }
        }
    }

    /// Run a single [`Runner`] test.
    fn run_test<E: RetriableError + Send + Sync + 'static>(
        sleep_for: Option<Duration>,
        schedule: impl BackoffSchedule + Send + 'static,
        errors: impl Iterator<Item = E> + Send + Sync + 'static,
        expected_run_count: usize,
        description: &'static str,
        expected_duration: Duration,
    ) {
        let runtime = MockRuntime::new();

        runtime.clone().block_on(async move {
            let runner = Runner {
                doing: description.into(),
                schedule,
                runtime: runtime.clone(),
            };

            let retry_count = Arc::new(RwLock::new(0));
            let (tx, rx) = oneshot::channel();

            let start = runtime.now();
            runtime
                .mock_task()
                .spawn_identified(format!("retry runner task: {description}"), {
                    let retry_count = Arc::clone(&retry_count);
                    let errors = Arc::new(RwLock::new(errors));
                    let runtime = runtime.clone();
                    async move {
                        if let Ok(()) = runner
                            .run(|| async {
                                *retry_count.write().unwrap() += 1;

                                if let Some(dur) = sleep_for {
                                    runtime.sleep(dur).await;
                                }

                                Err::<(), _>(errors.write().unwrap().next().unwrap())
                            })
                            .await
                        {
                            unreachable!();
                        }

                        let () = tx.send(()).unwrap();
                    }
                });

            // The expected retry count may be unknown (for example, if we set a timeout but no
            // upper limit for the number of retries, it's impossible to tell exactly how many
            // times the operation will be retried)
            for i in 1..=expected_run_count {
                runtime.mock_task().progress_until_stalled().await;
                // If our fallible_op is sleeping, advance the time until after it times out or
                // finishes sleeping.
                if let Some(sleep_for) = sleep_for {
                    runtime
                        .mock_sleep()
                        .advance(std::cmp::min(SINGLE_TIMEOUT, sleep_for));
                }
                runtime.mock_task().progress_until_stalled().await;
                runtime.mock_sleep().advance(SHORT_DELAY);
                assert_eq!(*retry_count.read().unwrap(), i);
            }

            let () = rx.await.unwrap();
            let end = runtime.now();

            assert_eq!(*retry_count.read().unwrap(), expected_run_count);
            assert!(duration_close_to(end - start, expected_duration));
        });
    }

    /// Return true if d1 is in range [d2...d2 + 0.01sec]
    ///
    /// TODO: lifted from tor-circmgr
    fn duration_close_to(d1: Duration, d2: Duration) -> bool {
        d1 >= d2 && d1 <= d2 + SHORT_DELAY
    }

    #[test]
    fn max_retries() {
        run_test(
            None,
            BackoffWithMaxRetries,
            iter::repeat(TestError::Transient),
            MAX_RETRIES,
            "backoff with max_retries and no timeout (transient errors)",
            Duration::from_millis(SHORT_DELAY.as_millis() as u64 * MAX_RETRIES as u64),
        );
    }

    #[test]
    fn max_retries_fatal() {
        use TestError::*;

        /// The number of transient errors that happen before the final, fatal error.
        const RETRIES_UNTIL_FATAL: usize = 3;
        /// The total number of times we exoect the fallible function to be called.
        /// The first RETRIES_UNTIL_FATAL times, a transient error is returned.
        /// The last call corresponds to the fatal error
        const EXPECTED_TOTAL_RUNS: usize = RETRIES_UNTIL_FATAL + 1;

        run_test(
            None,
            BackoffWithMaxRetries,
            iter::repeat(Transient)
                .take(RETRIES_UNTIL_FATAL)
                .chain([Fatal])
                .chain(iter::repeat(Transient)),
            EXPECTED_TOTAL_RUNS,
            "backoff with max_retries and no timeout (transient errors followed by a fatal error)",
            Duration::from_millis(SHORT_DELAY.as_millis() as u64 * EXPECTED_TOTAL_RUNS as u64),
        );
    }

    #[test]
    fn timeout() {
        use TestError::*;

        let expected_run_count = TIMEOUT.as_millis() / SHORT_DELAY.as_millis();

        run_test(
            None,
            BackoffWithTimeout,
            iter::repeat(Transient),
            expected_run_count as usize,
            "backoff with timeout and no max_retries (transient errors)",
            TIMEOUT,
        );
    }

    #[test]
    fn single_timeout() {
        use TestError::*;

        // Each attempt will time out after SINGLE_TIMEOUT time units,
        // and the backoff runner sleeps for SLEEP_DELAY units in between retries
        let expected_duration = Duration::from_millis(
            (SHORT_DELAY.as_millis() + SINGLE_TIMEOUT.as_millis()) as u64 * MAX_RETRIES as u64,
        );

        run_test(
            // Sleep for more than SINGLE_TIMEOUT units
            // to trigger the single_attempt_timeout() timeout
            Some(SINGLE_TIMEOUT * 2),
            BackoffWithSingleTimeout,
            iter::repeat(Transient),
            MAX_RETRIES,
            "backoff with single timeout and max_retries and no overall timeout",
            expected_duration,
        );
    }

    // TODO (#1120): needs tests for the remaining corner cases
}
