//! Congestion control subsystem.
//!
//! This object is attached to a circuit hop (CircHop) and controls the logic for the congestion
//! control support of the Tor Network. It also manages the circuit level SENDME logic which is
//! part of congestion control.
//!
//! # Implementation
//!
//! The basics of this subsystem is that it is notified when a DATA cell is received or sent. This
//! in turn updates the congestion control state so that the very important
//! [`can_send`](CongestionControl::can_send) function be accurate to decide if a DATA cell can be
//! sent or not.
//!
//! Any part of the arti code that wants to send a DATA cell on the wire needs to call
//! [`can_send`](CongestionControl::can_send) before else we'll risk leaving the circuit in a
//! protocol violation state.
//!
//! Futhermore, as we receive and emit SENDMEs, it also has entry point for those two events in
//! order to update the state.

/// Congestion control parameters exposed to the circuit manager so they can be set per circuit.
pub mod params;
/// Round trip estimator module.
mod rtt;

use self::params::CongestionWindowParams;

/// Congestion control state.
#[derive(Copy, Clone, Default)]
#[allow(dead_code)]
pub(crate) enum State {
    /// The initial state any circuit starts in. Used to gradually increase the amount of data
    /// being transmitted in order to converge towards to optimal capacity.
    #[default]
    SlowStart,
    /// Steady state representing what we think is optimal. This is always after slow start.
    Steady,
}

#[allow(dead_code)]
impl State {
    /// Return true iff this is SlowStart.
    pub(crate) fn in_slow_start(&self) -> bool {
        matches!(self, State::SlowStart)
    }
}

/// A congestion window. This is generic for all algorithms but their parameters' value will differ
/// depending on the selected algorithm.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct CongestionWindow {
    /// Congestion window parameters from the consensus.
    params: CongestionWindowParams,
    /// The actual value of our congestion window.
    value: u32,
    /// The congestion window is full.
    is_full: bool,
}

#[allow(dead_code)]
impl CongestionWindow {
    /// Constructor taking consensus parameters.
    fn new(params: &CongestionWindowParams) -> Self {
        Self {
            value: params.cwnd_init,
            params: params.clone(),
            is_full: false,
        }
    }

    /// Decrement the window by the increment value.
    pub(crate) fn dec(&mut self) {
        self.value = self
            .value
            .saturating_sub(self.increment())
            .max(self.params.cwnd_min);
    }

    /// Increment the window by the increment value.
    pub(crate) fn inc(&mut self) {
        self.value = self
            .value
            .saturating_add(self.increment())
            .min(self.params.cwnd_max);
    }

    /// Return the current value.
    pub(crate) fn get(&self) -> u32 {
        self.value
    }

    /// Return the expected rate for which the congestion window should be updated at.
    ///
    /// See `CWND_UPDATE_RATE` in prop324.
    pub(crate) fn update_rate(&self, state: &State) -> u32 {
        if state.in_slow_start() {
            1
        } else {
            (self.get() + self.increment_rate() * self.sendme_inc() / 2)
                / (self.increment_rate() * self.sendme_inc())
        }
    }

    /// Return minimum value of the congestion window.
    pub(crate) fn min(&self) -> u32 {
        self.params.cwnd_min
    }

    /// Set the congestion window value with a new value.
    pub(crate) fn set(&mut self, value: u32) {
        self.value = value;
    }

    /// Return the increment value.
    pub(crate) fn increment(&self) -> u32 {
        self.params.cwnd_inc
    }

    /// Return the rate at which we should increment the window.
    pub(crate) fn increment_rate(&self) -> u32 {
        self.params.cwnd_inc_rate
    }

    /// Return true iff this congestion window is full.
    pub(crate) fn is_full(&self) -> bool {
        self.is_full
    }

    /// Reset the full flag meaning it is now not full.
    pub(crate) fn reset_full(&mut self) {
        self.is_full = false;
    }

    /// Return the number of expected SENDMEs per congestion window.
    ///
    /// Spec: prop324 SENDME_PER_CWND definition
    pub(crate) fn sendme_per_cwnd(&self) -> u32 {
        (self.get() + (self.sendme_inc() / 2)) / self.sendme_inc()
    }

    /// Return the RFC3742 slow start increment value.
    ///
    /// Spec: prop324 rfc3742_ss_inc definition
    pub(crate) fn rfc3742_ss_inc(&mut self, ss_cap: u32) -> u32 {
        let inc = if self.get() <= ss_cap {
            ((self.params.cwnd_inc_pct_ss.as_percent() * self.sendme_inc()) + 50) / 100
        } else {
            (((self.sendme_inc() * ss_cap) + self.get()) / (self.get() * 2)).max(1)
        };
        self.value += inc;
        inc
    }

    /// Evaluate the fullness of the window with the given parameters.
    ///
    /// Spec: prop324 see cwnd_is_full and cwnd_is_nonfull definition.
    /// C-tor: cwnd_became_full() and cwnd_became_nonfull()
    pub(crate) fn eval_fullness(&mut self, inflight: u32, full_gap: u32, full_minpct: u32) {
        if (inflight + (self.sendme_inc() * full_gap)) >= self.get() {
            self.is_full = true;
        } else if (100 * inflight) < (full_minpct * self.get()) {
            self.is_full = false;
        }
    }

    /// Return the SENDME increment value.
    pub(crate) fn sendme_inc(&self) -> u32 {
        self.params.sendme_inc
    }

    #[cfg(test)]
    pub(crate) fn params(&self) -> &CongestionWindowParams {
        &self.params
    }
}

#[cfg(test)]
pub(crate) mod test {
    use tor_units::Percentage;

    use super::{
        params::{
            CongestionWindowParams, CongestionWindowParamsBuilder, RoundTripEstimatorParams,
            RoundTripEstimatorParamsBuilder,
        },
        rtt::RoundtripTimeEstimator,
        CongestionWindow,
    };

    pub(crate) fn new_rtt_estimator() -> RoundtripTimeEstimator {
        RoundtripTimeEstimator::new(&build_rtt_params())
    }

    pub(crate) fn new_cwnd() -> CongestionWindow {
        CongestionWindow::new(&build_cwnd_params())
    }

    fn build_rtt_params() -> RoundTripEstimatorParams {
        RoundTripEstimatorParamsBuilder::default()
            .ewma_cwnd_pct(Percentage::new(50))
            .ewma_max(10)
            .ewma_ss_max(2)
            .rtt_reset_pct(Percentage::new(100))
            .build()
            .expect("Unable to build RTT parameters")
    }

    fn build_cwnd_params() -> CongestionWindowParams {
        // Values taken from the prop324.
        CongestionWindowParamsBuilder::default()
            .cwnd_init(124)
            .cwnd_inc_pct_ss(Percentage::new(100))
            .cwnd_inc(1)
            .cwnd_inc_rate(31)
            .cwnd_min(124)
            .cwnd_max(u32::MAX)
            .sendme_inc(31)
            .build()
            .expect("Unable to build congestion window parameters")
    }

    #[test]
    fn test_cwnd() {
        let mut cwnd = new_cwnd();

        // Validate the getters are coherent with initialization.
        assert_eq!(cwnd.get(), cwnd.params().cwnd_init);
        assert_eq!(cwnd.min(), cwnd.params().cwnd_min);
        assert_eq!(cwnd.increment(), cwnd.params().cwnd_inc);
        assert_eq!(cwnd.increment_rate(), cwnd.params().cwnd_inc_rate);
        assert_eq!(cwnd.sendme_inc(), cwnd.params().sendme_inc);
        assert!(!cwnd.is_full());

        // Validate changes.
        cwnd.inc();
        assert_eq!(cwnd.get(), cwnd.params().cwnd_init + cwnd.params().cwnd_inc);
        cwnd.dec();
        assert_eq!(cwnd.get(), cwnd.params().cwnd_init);
    }
}
