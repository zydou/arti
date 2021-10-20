//! Declarations for a [`TimeoutEstimator`] type that can change implementation.

use crate::timeouts::{Action, TimeoutEstimator};
use std::sync::Mutex;
use std::time::Duration;
use tor_netdir::params::NetParameters;

/// A timeout estimator that can change its inner implementation and share its
/// implementation among multiple threads.
pub(crate) struct Estimator {
    /// The estimator we're currently using.
    inner: Mutex<Box<dyn TimeoutEstimator + Send + 'static>>,
}

impl Estimator {
    /// Construct a new estimator from some variant.
    pub(crate) fn new(est: impl TimeoutEstimator + Send + 'static) -> Self {
        Self {
            inner: Mutex::new(Box::new(est)),
        }
    }

    /// Record that a given circuit hop has completed.
    ///
    /// The `hop` number is a zero-indexed value for which hop just completed.
    ///
    /// The `delay` value is the amount of time after we first launched the
    /// circuit.
    ///
    /// If this is the last hop of the circuit, then `is_last` is true.
    pub(crate) fn note_hop_completed(&self, hop: u8, delay: Duration, is_last: bool) {
        let mut inner = self.inner.lock().expect("Timeout estimator lock poisoned.");

        inner.note_hop_completed(hop, delay, is_last);
    }

    /// Record that a circuit failed to complete because it took too long.
    ///
    /// The `hop` number is a the number of hops that were successfully
    /// completed.
    ///
    /// The `delay` number is the amount of time after we first launched the
    /// circuit.
    pub(crate) fn note_circ_timeout(&self, hop: u8, delay: Duration) {
        let mut inner = self.inner.lock().expect("Timeout estimator lock poisoned.");
        inner.note_circ_timeout(hop, delay);
    }

    /// Return the current estimation for how long we should wait for a given
    /// [`Action`] to complete.
    ///
    /// This function should return a 2-tuple of `(timeout, abandon)`
    /// durations.  After `timeout` has elapsed since circuit launch,
    /// the circuit should no longer be used, but we should still keep
    /// building it in order see how long it takes.  After `abandon`
    /// has elapsed since circuit launch, the circuit should be
    /// abandoned completely.
    pub(crate) fn timeouts(&self, action: &Action) -> (Duration, Duration) {
        let mut inner = self.inner.lock().expect("Timeout estimator lock poisoned.");

        inner.timeouts(action)
    }

    /// Return true if we're currently trying to learn more timeouts
    /// by launching testing circuits.
    pub(crate) fn learning_timeouts(&self) -> bool {
        let inner = self.inner.lock().expect("Timeout estimator lock poisoned.");
        inner.learning_timeouts()
    }

    /// Replace the network parameters used by this estimator (if any)
    /// with ones derived from `params`.
    pub(crate) fn update_params(&self, params: &NetParameters) {
        let mut inner = self.inner.lock().expect("Timeout estimator lock poisoned.");
        inner.update_params(params);
    }

    /// Store any state associated with this timeout esimator into `storage`.
    pub(crate) fn save_state(&self, storage: &crate::TimeoutStateHandle) -> crate::Result<()> {
        let state = {
            let mut inner = self.inner.lock().expect("Timeout estimator lock poisoned.");
            inner.build_state()
        };
        if let Some(state) = state {
            storage.store(&state)?;
        }
        Ok(())
    }
}

/*
/// An enum that can hold an estimator state.
enum EstimatorInner {
    Pareto(ParetoTimeoutEstimator),
}

impl TimeoutEstimatorImpl for EstimatorInner {
    fn note_hop_completed(&mut self, hop: u8, delay: Duration, is_last: bool) {
        match self {
            EstimatorInner::Pareto(mut p) => p.note_hop_completed(hop, delay, is_last)
        }
    }

    fn note_circ_timeout(&mut self, hop: u8, delay: Duration) {
        match self {
            EstimatorInner::Pareto(mut p) => p.note_circ_timeout(hop, delay)
        }
    }

    fn timeouts(&mut self, action: &Action) -> (Duration, Duration) {
        match self {
            EstimatorInner::Pareto(mut p) => p.timeouts(action)
        }
    }

    fn learning_timeouts(&self) -> bool {
        match self {
            EstimatorInner::Pareto(p) => p.learning_timeouts()
        }
    }

    fn update_params(&mut self, params: &tor_netdir::NetParameters) {
        match self {
            EstimatorInner::Pareto(mut p) => p.update_params(params),
        }
    }


}

*/
