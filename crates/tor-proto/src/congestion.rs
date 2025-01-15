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

#[cfg(any(test, feature = "testing"))]
pub(crate) mod test_utils;

mod fixed;
pub mod params;
mod rtt;
pub(crate) mod sendme;
mod vegas;

use std::time::Instant;

use crate::{Error, Result};

use self::{
    params::{Algorithm, CongestionControlParams, CongestionWindowParams},
    rtt::RoundtripTimeEstimator,
    sendme::{CircTag, SendmeValidator},
};

/// This trait defines what a congestion control algorithm must implement in order to interface
/// with the circuit reactor.
///
/// Note that all functions informing the algorithm, as in not getters, return a Result meaning
/// that on error, it means we can't recover or that there is a protocol violation. In both
/// cases, the circuit MUST be closed.
pub(crate) trait CongestionControlAlgorithm: Send {
    /// Return true iff the next cell is expected to be a SENDME.
    fn is_next_cell_sendme(&self) -> bool;
    /// Return true iff a cell can be sent on the wire according to the congestion control
    /// algorithm.
    fn can_send(&self) -> bool;
    /// Return the congestion window object. The reason is returns an Option is because not all
    /// algorithm uses one and so we avoid acting on it if so.
    fn cwnd(&self) -> Option<&CongestionWindow>;

    /// Inform the algorithm that we just got a DATA cell.
    ///
    /// Return true if a SENDME should be sent immediately or false if not.
    fn data_received(&mut self) -> Result<bool>;
    /// Inform the algorithm that we just sent a DATA cell.
    fn data_sent(&mut self) -> Result<()>;
    /// Inform the algorithm that we've just received a SENDME.
    ///
    /// This is a core function because the algorithm massively update its state when receiving a
    /// SENDME by using the RTT value and congestion signals.
    fn sendme_received(
        &mut self,
        state: &mut State,
        rtt: &mut RoundtripTimeEstimator,
        signals: CongestionSignals,
    ) -> Result<()>;
    /// Inform the algorithm that we just sent a SENDME.
    fn sendme_sent(&mut self) -> Result<()>;

    /// Test Only: Return the congestion window.
    #[cfg(test)]
    fn send_window(&self) -> u32;
}

/// These are congestion signals used by a congestion control algorithm to make decisions. These
/// signals are various states of our internals. This is not an exhaustive list.
#[derive(Copy, Clone)]
pub(crate) struct CongestionSignals {
    /// Indicate if the channel is blocked.
    pub(crate) channel_blocked: bool,
    /// The size of the channel outbound queue.
    pub(crate) channel_outbound_size: u32,
}

impl CongestionSignals {
    /// Constructor
    pub(crate) fn new(channel_blocked: bool, channel_outbound_size: usize) -> Self {
        Self {
            channel_blocked,
            channel_outbound_size: channel_outbound_size.saturating_add(0) as u32,
        }
    }
}

/// Congestion control state.
#[derive(Copy, Clone, Default)]
pub(crate) enum State {
    /// The initial state any circuit starts in. Used to gradually increase the amount of data
    /// being transmitted in order to converge towards to optimal capacity.
    #[default]
    SlowStart,
    /// Steady state representing what we think is optimal. This is always after slow start.
    Steady,
}

impl State {
    /// Return true iff this is SlowStart.
    pub(crate) fn in_slow_start(&self) -> bool {
        matches!(self, State::SlowStart)
    }
}

/// A congestion window. This is generic for all algorithms but their parameters' value will differ
/// depending on the selected algorithm.
#[derive(Clone, Debug)]
pub(crate) struct CongestionWindow {
    /// Congestion window parameters from the consensus.
    params: CongestionWindowParams,
    /// The actual value of our congestion window.
    value: u32,
    /// The congestion window is full.
    is_full: bool,
}

impl CongestionWindow {
    /// Constructor taking consensus parameters.
    fn new(params: &CongestionWindowParams) -> Self {
        Self {
            value: params.cwnd_init(),
            params: params.clone(),
            is_full: false,
        }
    }

    /// Decrement the window by the increment value.
    pub(crate) fn dec(&mut self) {
        self.value = self
            .value
            .saturating_sub(self.increment())
            .max(self.params.cwnd_min());
    }

    /// Increment the window by the increment value.
    pub(crate) fn inc(&mut self) {
        self.value = self
            .value
            .saturating_add(self.increment())
            .min(self.params.cwnd_max());
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
        self.params.cwnd_min()
    }

    /// Set the congestion window value with a new value.
    pub(crate) fn set(&mut self, value: u32) {
        self.value = value;
    }

    /// Return the increment value.
    pub(crate) fn increment(&self) -> u32 {
        self.params.cwnd_inc()
    }

    /// Return the rate at which we should increment the window.
    pub(crate) fn increment_rate(&self) -> u32 {
        self.params.cwnd_inc_rate()
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
            ((self.params.cwnd_inc_pct_ss().as_percent() * self.sendme_inc()) + 50) / 100
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
        self.params.sendme_inc()
    }

    #[cfg(test)]
    pub(crate) fn params(&self) -> &CongestionWindowParams {
        &self.params
    }
}

/// Congestion control state of a hop on a circuit.
///
/// This controls the entire logic of congestion control and circuit level SENDMEs.
pub(crate) struct CongestionControl {
    /// Which congestion control state are we in?
    state: State,
    /// This is the SENDME validator as in it keeps track of the circuit tag found within an
    /// authenticated SENDME cell. It can store the tags and validate a tag against our queue of
    /// expected values.
    sendme_validator: SendmeValidator<CircTag>,
    /// The RTT estimator for the circuit we are attached on.
    rtt: RoundtripTimeEstimator,
    /// The congestion control algorithm.
    algorithm: Box<dyn CongestionControlAlgorithm>,
}

impl CongestionControl {
    /// Construct a new CongestionControl
    pub(crate) fn new(params: &CongestionControlParams) -> Self {
        let state = State::default();
        // Use what the consensus tells us to use.
        let algorithm: Box<dyn CongestionControlAlgorithm> = match params.alg() {
            Algorithm::FixedWindow(p) => Box::new(fixed::FixedWindow::new(p.circ_window_start())),
            Algorithm::Vegas(ref p) => {
                let cwnd = CongestionWindow::new(params.cwnd_params());
                Box::new(vegas::Vegas::new(p, &state, cwnd))
            }
        };
        Self {
            algorithm,
            rtt: RoundtripTimeEstimator::new(params.rtt_params()),
            sendme_validator: SendmeValidator::new(),
            state,
        }
    }

    /// Return true iff a DATA cell is allowed to be sent based on the congestion control state.
    pub(crate) fn can_send(&self) -> bool {
        self.algorithm.can_send()
    }

    /// Called when a SENDME cell is received.
    ///
    /// An error is returned if there is a protocol violation with regards to congestion control.
    pub(crate) fn note_sendme_received(
        &mut self,
        tag: CircTag,
        signals: CongestionSignals,
    ) -> Result<()> {
        // This MUST be the first thing that we do that is validate the SENDME. Any error leads to
        // closing the circuit.
        self.sendme_validator.validate(Some(tag))?;

        // Update our RTT estimate if the algorithm yields back a congestion window. RTT
        // measurements only make sense for a congestion window. For example, FixedWindow here
        // doesn't use it and so no need for the RTT.
        if let Some(cwnd) = self.algorithm.cwnd() {
            self.rtt
                .update(Instant::now(), &self.state, cwnd)
                .map_err(|e| Error::CircProto(e.to_string()))?;
        }

        // Notify the algorithm that we've received a SENDME.
        self.algorithm
            .sendme_received(&mut self.state, &mut self.rtt, signals)
    }

    /// Called when a SENDME cell is sent.
    pub(crate) fn note_sendme_sent(&mut self) -> Result<()> {
        self.algorithm.sendme_sent()
    }

    /// Called when a DATA cell is received.
    ///
    /// Returns true iff a SENDME should be sent false otherwise. An error is returned if there is
    /// a protocol violation with regards to flow or congestion control.
    pub(crate) fn note_data_received(&mut self) -> Result<bool> {
        self.algorithm.data_received()
    }

    /// Called when a DATA cell is sent.
    ///
    /// An error is returned if there is a protocol violation with regards to flow or congestion
    /// control.
    pub(crate) fn note_data_sent<U>(&mut self, tag: &U) -> Result<()>
    where
        U: Clone + Into<CircTag>,
    {
        // Inform the algorithm that the data was just sent. This is important to be the very first
        // thing so the congestion window can be updated accordingly making the following calls
        // using the latest data.
        self.algorithm.data_sent()?;

        // If next cell is a SENDME, we need to record the tag of this cell in order to validate
        // the next SENDME when it arrives.
        if self.algorithm.is_next_cell_sendme() {
            self.sendme_validator.record(tag);
            // Only keep the SENDME timestamp if the algorithm has a congestion window.
            if self.algorithm.cwnd().is_some() {
                self.rtt.expect_sendme(Instant::now());
            }
        }

        Ok(())
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

    use crate::congestion::test_utils::new_cwnd;

    use super::sendme::CircTag;
    use super::CongestionControl;

    impl CongestionControl {
        /// For testing: get a copy of the current send window, and the
        /// expected incoming tags.
        pub(crate) fn send_window_and_expected_tags(&self) -> (u32, Vec<CircTag>) {
            (
                self.algorithm.send_window(),
                self.sendme_validator.expected_tags(),
            )
        }
    }

    #[test]
    fn test_cwnd() {
        let mut cwnd = new_cwnd();

        // Validate the getters are coherent with initialization.
        assert_eq!(cwnd.get(), cwnd.params().cwnd_init());
        assert_eq!(cwnd.min(), cwnd.params().cwnd_min());
        assert_eq!(cwnd.increment(), cwnd.params().cwnd_inc());
        assert_eq!(cwnd.increment_rate(), cwnd.params().cwnd_inc_rate());
        assert_eq!(cwnd.sendme_inc(), cwnd.params().sendme_inc());
        assert!(!cwnd.is_full());

        // Validate changes.
        cwnd.inc();
        assert_eq!(
            cwnd.get(),
            cwnd.params().cwnd_init() + cwnd.params().cwnd_inc()
        );
        cwnd.dec();
        assert_eq!(cwnd.get(), cwnd.params().cwnd_init());
    }
}
