//! Declarations for a [`TimeoutEstimator`] type that can change implementation.

use crate::timeouts::{
    pareto::{ParetoTimeoutEstimator, ParetoTimeoutState},
    readonly::ReadonlyTimeoutEstimator,
    Action, TimeoutEstimator,
};
use crate::TimeoutStateHandle;
use std::sync::Mutex;
use std::time::Duration;
use tor_error::warn_report;
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
    #[cfg(test)]
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
            debug!("Unable to reload timeout state.");
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

    /// Store any state associated with this timeout estimator into `storage`.
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
            warn_report!(e, "Unable to load timeout state");
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
    use tor_persist::StateMgr;

    #[test]
    fn load_estimator() {
        let params = NetParameters::default();

        // Construct an estimator with write access to a state manager.
        let storage = tor_persist::TestingStateMgr::new();
        assert!(storage.try_lock().unwrap().held());
        let handle = storage.clone().create_handle("paretorama");

        let est = Estimator::from_storage(&handle);
        assert!(est.learning_timeouts());
        est.save_state(&handle).unwrap();

        // Construct another estimator that is looking at the same data,
        // but which only gets read-only access
        let storage2 = storage.new_manager();
        assert!(!storage2.try_lock().unwrap().held());
        let handle2 = storage2.clone().create_handle("paretorama");

        let est2 = Estimator::from_storage(&handle2);
        assert!(!est2.learning_timeouts());

        est.update_params(&params);
        est2.update_params(&params);

        // Initial timeouts, since no data is present yet.
        let act = Action::BuildCircuit { length: 3 };
        assert_eq!(
            est.timeouts(&act),
            (Duration::from_secs(60), Duration::from_secs(60))
        );
        assert_eq!(
            est2.timeouts(&act),
            (Duration::from_secs(60), Duration::from_secs(60))
        );

        // Pretend both estimators have gotten a bunch of observations...
        for _ in 0..500 {
            est.note_hop_completed(2, Duration::from_secs(7), true);
            est.note_hop_completed(2, Duration::from_secs(2), true);
            est2.note_hop_completed(2, Duration::from_secs(4), true);
        }
        assert!(!est.learning_timeouts());

        // Have est save and est2 load.
        est.save_state(&handle).unwrap();
        let to_1 = est.timeouts(&act);
        assert_ne!(
            est.timeouts(&act),
            (Duration::from_secs(60), Duration::from_secs(60))
        );
        assert_eq!(
            est2.timeouts(&act),
            (Duration::from_secs(60), Duration::from_secs(60))
        );
        est2.reload_readonly_from_storage(&handle2);
        let to_1_secs = to_1.0.as_secs_f64();
        let timeouts = est2.timeouts(&act);
        assert!((timeouts.0.as_secs_f64() - to_1_secs).abs() < 0.001);
        assert!((timeouts.1.as_secs_f64() - to_1_secs).abs() < 0.001);

        drop(est);
        drop(handle);
        drop(storage);

        // Now storage2 can upgrade...
        assert!(storage2.try_lock().unwrap().held());
        est2.upgrade_to_owning_storage(&handle2);
        let to_2 = est2.timeouts(&act);
        // This will be similar but not the same.
        assert!(to_2.0 > to_1.0 - Duration::from_secs(1));
        assert!(to_2.0 < to_1.0 + Duration::from_secs(1));
        // Make sure est2 is now mutable...
        for _ in 0..200 {
            est2.note_hop_completed(2, Duration::from_secs(1), true);
        }
        let to_3 = est2.timeouts(&act);
        assert!(to_3.0 < to_2.0);
    }
}
