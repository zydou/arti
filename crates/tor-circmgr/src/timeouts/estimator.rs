//! Declarations for a [`TimeoutEstimator`] type that can change implementation.

use crate::timeouts::{
    pareto::{ParetoTimeoutEstimator, ParetoTimeoutState},
    readonly::ReadonlyTimeoutEstimator,
    Action, TimeoutEstimator,
};
use crate::TimeoutStateHandle;
use std::sync::Mutex;
use std::time::Duration;
use tor_netdir::params::NetParameters;
use tracing::{debug, warn};

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

    /// Create this estimator based on the values stored in `storage`, and whether
    /// this storage is read-only.
    pub(crate) fn from_storage(storage: &TimeoutStateHandle) -> Self {
        let (_, est) = estimator_from_storage(storage);
        Self {
            inner: Mutex::new(est),
        }
    }

    /// Assuming that we can read and write to `storage`, replace our state with
    /// a new state that estimates timeouts.
    pub(crate) fn upgrade_to_owning_storage(&self, storage: &TimeoutStateHandle) {
        let (readonly, est) = estimator_from_storage(storage);
        if readonly {
            warn!("Unable to upgrade to owned persistent storage.");
            return;
        }
        *self.inner.lock().expect("Timeout estimator lock poisoned") = est;
    }

    /// Replace the contents of this estimator with a read-only state estimator
    /// based on the contents of `storage`.
    pub(crate) fn reload_readonly_from_storage(&self, storage: &TimeoutStateHandle) {
        if let Ok(Some(v)) = storage.load() {
            let est = ReadonlyTimeoutEstimator::from_state(&v);
            *self.inner.lock().expect("Timeout estimator lock poisoned") = Box::new(est);
        } else {
            debug!("Unable to reload timeout state.")
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
    pub(crate) fn save_state(&self, storage: &TimeoutStateHandle) -> crate::Result<()> {
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

/// Try to construct a new boxed TimeoutEstimator based on the contents of
/// storage, and whether it is read-only.
///
/// Returns true on a read-only state.
fn estimator_from_storage(
    storage: &TimeoutStateHandle,
) -> (bool, Box<dyn TimeoutEstimator + Send + 'static>) {
    let state = match storage.load() {
        Ok(Some(v)) => v,
        Ok(None) => ParetoTimeoutState::default(),
        Err(e) => {
            warn!("Unable to load timeout state: {}", e);
            return (true, Box::new(ReadonlyTimeoutEstimator::new()));
        }
    };

    if storage.can_store() {
        // We own the lock, so we're going to use a full estimator.
        (false, Box::new(ParetoTimeoutEstimator::from_state(state)))
    } else {
        (true, Box::new(ReadonlyTimeoutEstimator::from_state(&state)))
    }
}
