//! Implement a timeout estimator that just uses another process's estimates.

use crate::timeouts::{Action, TimeoutEstimator, pareto::ParetoTimeoutState};
use std::time::Duration;

/// A timeout estimator based on reading timeouts that another timeout estimator
/// is computing, in another process.
pub(crate) struct ReadonlyTimeoutEstimator {
    /// Are we using the timeouts?
    using_estimates: bool,
    /// Latest estimate from the persistent state.
    latest_timeout: Option<Duration>,
    /// Timeout to use if we don't have a computed timeout.
    default_timeout: Duration,
}

impl ReadonlyTimeoutEstimator {
    /// Create a new ReadonlyTimeoutEstimator with default settings.
    pub(crate) fn new() -> Self {
        ReadonlyTimeoutEstimator {
            using_estimates: true,
            latest_timeout: None,
            default_timeout: Duration::from_secs(60),
        }
    }

    /// Create a new ReadonlyTimeoutEstimator, based on persistent state
    pub(crate) fn from_state(s: &ParetoTimeoutState) -> Self {
        let mut est = Self::new();
        est.update_from_state(s);
        est
    }

    /// Update this estimator based on a newly read state.
    pub(crate) fn update_from_state(&mut self, s: &ParetoTimeoutState) {
        self.latest_timeout = s.latest_estimate();
    }
}

impl TimeoutEstimator for ReadonlyTimeoutEstimator {
    fn note_hop_completed(&mut self, _hop: u8, _delay: Duration, _is_last: bool) {
        // We don't record any timeouts with this estimator.
    }

    fn note_circ_timeout(&mut self, _hop: u8, _delay: Duration) {
        // as above
    }

    fn timeouts(&mut self, action: &Action) -> (Duration, Duration) {
        let base = match (self.using_estimates, self.latest_timeout) {
            (true, Some(d)) => d,
            (_, _) => self.default_timeout,
        };

        let reference_action = Action::BuildCircuit { length: 3 };
        debug_assert!(reference_action.timeout_scale() > 0);

        let multiplier =
            (action.timeout_scale() as f64) / (reference_action.timeout_scale() as f64);

        use super::mul_duration_f64_saturating as mul;
        let timeout = mul(base, multiplier);

        // We use the same timeout twice here, since we don't need
        // separate abandon and timeout thresholds when we are not
        // recording timeout info.
        //
        // TODO: decide whether it is a problem that this might let an
        // observer know whether our stat is read-only.
        (timeout, timeout)
    }

    fn learning_timeouts(&self) -> bool {
        false
    }

    fn update_params(&mut self, params: &tor_netdir::params::NetParameters) {
        self.using_estimates = !bool::from(params.cbt_learning_disabled);
        self.default_timeout = params
            .cbt_initial_timeout
            .try_into()
            .unwrap_or_else(|_| Duration::from_secs(60));
    }

    fn build_state(&mut self) -> Option<ParetoTimeoutState> {
        None
    }
}
