//! Implementation of the Tor Vegas congestion control algorithm.
//!
//! This is used by the circuit reactor in order to decide when to send data and SENDMEs.
//!
//! Spec: prop324 section 3.3 (TOR_VEGAS)

use super::{
    params::VegasParams, rtt::RoundtripTimeEstimator, CongestionControlAlgorithm,
    CongestionSignals, CongestionWindow, State,
};
use crate::Result;

use tor_error::{error_report, internal};

/// Bandwidth-Delay Product (BDP) estimator.
///
/// Spec: prop324 section 3.1 (BDP_ESTIMATION).
#[derive(Clone, Debug, Default)]
pub(crate) struct BdpEstimator {
    /// The BDP value of this estimator.
    bdp: u32,
}

impl BdpEstimator {
    /// Return the current BDP value.
    fn get(&self) -> u32 {
        self.bdp
    }

    /// Update the estimator with the given congestion window, RTT estimator and any condition
    /// signals that we are currently experiencing.
    ///
    /// C-tor: congestion_control_update_circuit_bdp() in congestion_control_common.c
    fn update(
        &mut self,
        cwnd: &CongestionWindow,
        rtt: &RoundtripTimeEstimator,
        signals: &CongestionSignals,
    ) {
        // Stalled clock means our RTT value is invalid so set the BDP to the cwnd.
        if rtt.clock_stalled() {
            self.bdp = if signals.channel_blocked {
                // Set the BDP to the cwnd minus the outbound queue size, capping it to the minimum
                // cwnd.
                cwnd.get()
                    .saturating_sub(signals.channel_outbound_size)
                    .max(cwnd.min())
            } else {
                cwnd.get()
            };
        } else {
            // Congestion window based BDP will respond to changes in RTT only, and is relative to
            // cwnd growth. It is useful for correcting for BDP overestimation, but if BDP is
            // higher than the current cwnd, it will underestimate it.
            //
            // To clarify this is equivalent to: cwnd * min_rtt / ewma_rtt.
            self.bdp = cwnd
                .get()
                .saturating_mul(rtt.min_rtt_usec())
                .saturating_div(rtt.ewma_rtt_usec());
        }
    }
}

/// Congestion control Vegas algorithm.
///
/// TCP Vegas control algorithm estimates the queue lengths at relays by subtracting the current
/// BDP estimate from the current congestion window.
///
/// This object implements CongestionControlAlgorithm trait used by the ['CongestionControl'].
///
/// Spec: prop324 section 3.3 (TOR_VEGAS)
/// C-tor: Split between congestion_control_vegas.c and the congestion_control_t struct.
#[derive(Clone, Debug)]
pub(crate) struct Vegas {
    /// Congestion control parameters.
    params: VegasParams,
    /// Bandwidth delay product.
    /// C-tor: "bdp"
    bdp: BdpEstimator,
    /// Congestion window.
    /// C-tor: "cwnd", "cwnd_inc_pct_ss", "cwnd_inc", "cwnd_min", "cwnd_inc_rate", "cwnd_full",
    cwnd: CongestionWindow,
    /// Number of cells expected before we send a SENDME resulting in more data.
    num_cell_until_sendme: u32,
    /// The number of SENDME until we will acknowledge a congestion event again.
    /// C-tor: "next_cc_event"
    num_sendme_until_cwnd_update: u32,
    /// Counts down until we process a cwnd worth of SENDME acks. Used to track full cwnd status.
    /// C-tor: "next_cwnd_event"
    num_sendme_per_cwnd: u32,
    /// Number of cells in-flight (sent but awaiting SENDME ack).
    /// C-tor: "inflight"
    num_inflight: u32,
    /// Indicate if we noticed we were blocked on channel during an algorithm run. This is used to
    /// notice a change from blocked to non-blocked in order to reset the num_sendme_per_cwnd.
    /// C-tor: "blocked_chan"
    is_blocked_on_chan: bool,
}

impl Vegas {
    /// Create a new [`Vegas`] from the specified parameters, state, and cwnd.
    pub(crate) fn new(params: &VegasParams, state: &State, cwnd: CongestionWindow) -> Self {
        Self {
            params: params.clone(),
            bdp: BdpEstimator::default(),
            num_cell_until_sendme: cwnd.sendme_inc(),
            num_inflight: 0,
            num_sendme_per_cwnd: 0,
            num_sendme_until_cwnd_update: cwnd.update_rate(state),
            cwnd,
            is_blocked_on_chan: false,
        }
    }
}

impl CongestionControlAlgorithm for Vegas {
    fn is_next_cell_sendme(&self) -> bool {
        // Matching inflight number to the SENDME increment, time to send a SENDME. Contrary to
        // C-tor, this is called after num_inflight is incremented.
        self.num_inflight % self.cwnd.sendme_inc() == 0
    }

    fn can_send(&self) -> bool {
        self.num_inflight < self.cwnd.get()
    }

    fn cwnd(&self) -> Option<&CongestionWindow> {
        Some(&self.cwnd)
    }

    /// Called when a SENDME cell is received.
    ///
    /// This is where the Vegas algorithm magic happens entirely. For every SENDME we get, the
    /// entire state is updated which usually result in the congestion window being changed.
    ///
    /// An error is returned if there is a protocol violation with regards to flow or congestion
    /// control.
    ///
    /// Spec: prop324 section 3.3 (TOR_VEGAS)
    /// C-tor: congestion_control_vegas_process_sendme() in congestion_control_vegas.c
    fn sendme_received(
        &mut self,
        state: &mut State,
        rtt: &mut RoundtripTimeEstimator,
        signals: CongestionSignals,
    ) -> Result<()> {
        // Update the countdown until we need to update the congestion window.
        self.num_sendme_until_cwnd_update = self.num_sendme_until_cwnd_update.saturating_sub(1);
        // We just got a SENDME so decrement the amount of expected SENDMEs for a cwnd.
        self.num_sendme_per_cwnd = self.num_sendme_per_cwnd.saturating_sub(1);

        // From here, C-tor proceeds to update the RTT and BDP (circuit estimates). The RTT is
        // updated before this is called and so the "rtt" object is up to date with the latest. As
        // for the BDP, we update it now. See C-tor congestion_control_update_circuit_estimates().

        // Update the BDP estimator even if the RTT estimator is not ready. If that is the case,
        // we'll estimate a BDP value to bootstrap.
        self.bdp.update(&self.cwnd, rtt, &signals);

        // Evalute if we changed state on the blocked chan. This is done in the BDP update function
        // in C-tor. Instead, we do it now after the update of the BDP value.
        if rtt.is_ready() {
            if signals.channel_blocked {
                // Going from non blocked to block, it is an immediate congestion signal so reset the
                // number of sendme per cwnd because we are about to reevaluate it.
                if !self.is_blocked_on_chan {
                    self.num_sendme_until_cwnd_update = 0;
                }
            } else {
                // Going from blocked to non block, need to reevaluate the cwnd and so reset num
                // sendme.
                if self.is_blocked_on_chan {
                    self.num_sendme_until_cwnd_update = 0;
                }
            }
        }
        self.is_blocked_on_chan = signals.channel_blocked;

        // Only run the algorithm if the RTT estimator is ready or we have a blocked channel.
        if !rtt.is_ready() && !self.is_blocked_on_chan {
            // The inflight value can never be below a sendme_inc because everytime a cell is sent,
            // inflight is incremented and we only end up decrementing if we receive a valid
            // authenticated SENDME which is always after the sendme_inc value that we get that.
            debug_assert!(self.num_inflight >= self.cwnd.sendme_inc());
            self.num_inflight = self.num_inflight.saturating_sub(self.cwnd.sendme_inc());
            return Ok(());
        }

        // The queue use is the amount in which our cwnd is above BDP;
        // if it is below, then 0 queue use.
        let queue_use = self.cwnd.get().saturating_sub(self.bdp.get());

        // Evaluate if the congestion window has became full or not.
        self.cwnd.eval_fullness(
            self.num_inflight,
            self.params.cwnd_full_gap(),
            self.params.cwnd_full_min_pct().as_percent(),
        );

        // Spec: See the pseudocode of TOR_VEGAS with RFC3742
        if state.in_slow_start() {
            if queue_use < self.params.cell_in_queue_params().gamma() && !self.is_blocked_on_chan {
                // If the congestion window is not fully in use, skip any increment in slow start.
                if self.cwnd.is_full() {
                    // This is the "Limited Slow Start" increment.
                    let inc = self
                        .cwnd
                        .rfc3742_ss_inc(self.params.cell_in_queue_params().ss_cwnd_cap());

                    // Check if inc is less than what we would do in steady-state avoidance. Note
                    // that this is likely never to happen in practice. If so, exit slow start.
                    if (inc * self.cwnd.sendme_per_cwnd())
                        <= (self.cwnd.increment() * self.cwnd.increment_rate())
                    {
                        *state = State::Steady;
                    }
                }
            } else {
                // Congestion signal: Set cwnd to gamma threshold
                self.cwnd
                    .set(self.bdp.get() + self.params.cell_in_queue_params().gamma());
                // Exit slow start due to congestion signal.
                *state = State::Steady;
            }

            // Max the window and exit slow start.
            if self.cwnd.get() >= self.params.ss_cwnd_max() {
                self.cwnd.set(self.params.ss_cwnd_max());
                *state = State::Steady;
            }
        } else if self.num_sendme_until_cwnd_update == 0 {
            // Once in steady state, we only update once per window.
            if queue_use > self.params.cell_in_queue_params().delta() {
                // Above delta threshold, drop cwnd down to the delta.
                self.cwnd.set(
                    self.bdp.get() + self.params.cell_in_queue_params().delta()
                        - self.cwnd.increment(),
                );
            } else if queue_use > self.params.cell_in_queue_params().beta()
                || self.is_blocked_on_chan
            {
                // Congestion signal: Above beta or if channel is blocked, decrement window.
                self.cwnd.dec();
            } else if self.cwnd.is_full() && queue_use < self.params.cell_in_queue_params().alpha()
            {
                // Congestion window is full and the queue usage is below alpha, increment.
                self.cwnd.inc();
            }
        }

        // Reset our counters if they reached their bottom.
        if self.num_sendme_until_cwnd_update == 0 {
            self.num_sendme_until_cwnd_update = self.cwnd.update_rate(state);
        }
        if self.num_sendme_per_cwnd == 0 {
            self.num_sendme_per_cwnd = self.cwnd.sendme_per_cwnd();
        }

        // Decide if enough time has passed to reset the cwnd.
        if self.params.cwnd_full_per_cwnd() != 0 {
            if self.num_sendme_per_cwnd == self.cwnd.sendme_per_cwnd() {
                self.cwnd.reset_full();
            }
        } else if self.num_sendme_until_cwnd_update == self.cwnd.update_rate(state) {
            self.cwnd.reset_full();
        }

        // Finally, update the inflight now that we have a SENDME.
        self.num_inflight = self.num_inflight.saturating_sub(self.cwnd.sendme_inc());
        Ok(())
    }

    fn sendme_sent(&mut self) -> Result<()> {
        // SENDME is on the wire, set our counter until next one.
        self.num_cell_until_sendme = self.cwnd.sendme_inc();
        Ok(())
    }

    fn data_received(&mut self) -> Result<bool> {
        if self.num_cell_until_sendme == 0 {
            // This is not a protocol violation, it is a code flow error and so don't close the
            // circuit by sending back an Error. Catching this prevents from sending two SENDMEs
            // back to back. We recover from this but scream very loudly.
            error_report!(internal!("Congestion control unexptected data cell"), "");
            return Ok(false);
        }

        // Decrement the expected window.
        self.num_cell_until_sendme = self.num_cell_until_sendme.saturating_sub(1);

        // Reaching zero, lets inform the caller a SENDME needs to be sent. This counter is reset
        // when the SENDME is actually sent.
        Ok(self.num_cell_until_sendme == 0)
    }

    fn data_sent(&mut self) -> Result<()> {
        // This can be above cwnd because that cwnd can shrink while we are still sending data.
        self.num_inflight = self.num_inflight.saturating_add(1);
        Ok(())
    }

    #[cfg(test)]
    fn send_window(&self) -> u32 {
        self.cwnd.get()
    }
}

#[cfg(test)]
#[allow(clippy::print_stderr)]
pub(crate) mod test {
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

    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };
    use tor_units::Percentage;

    use super::*;
    use crate::congestion::{
        params::VegasParamsBuilder,
        test_utils::{new_cwnd, new_rtt_estimator},
    };

    impl Vegas {
        /// Set the number of inflight cell.
        pub(crate) fn set_inflight(&mut self, v: u32) {
            self.num_inflight = v;
        }
        /// Return the state of the blocked on chan flag.
        fn is_blocked_on_chan(&self) -> bool {
            self.is_blocked_on_chan
        }
        /// Set the state of the blocked on chan flag.
        fn set_is_blocked_on_chan(&mut self, v: bool) {
            self.is_blocked_on_chan = v;
        }
    }

    /// The test vector parameters. They have the exact same name as in C-tor in order to help
    /// matching them and avoid confusion.
    #[derive(Debug)]
    struct TestVectorParams {
        // Inbound parameters.
        sent_usec_in: u64,
        got_sendme_usec_in: u64,
        or_conn_blocked_in: bool,
        inflight_in: u32,
        // Expected outbound parameters.
        ewma_rtt_usec_out: u32,
        min_rtt_usec_out: u32,
        cwnd_out: u32,
        in_slow_start_out: bool,
        cwnd_full_out: bool,
        blocked_chan_out: bool,
    }

    impl From<[u32; 10]> for TestVectorParams {
        fn from(arr: [u32; 10]) -> Self {
            Self {
                sent_usec_in: u64::from(arr[0]),
                got_sendme_usec_in: u64::from(arr[1]),
                or_conn_blocked_in: arr[2] == 1,
                inflight_in: arr[3],
                ewma_rtt_usec_out: arr[4],
                min_rtt_usec_out: arr[5],
                cwnd_out: arr[6],
                in_slow_start_out: arr[7] == 1,
                cwnd_full_out: arr[8] == 1,
                blocked_chan_out: arr[9] == 1,
            }
        }
    }

    struct VegasTest {
        params: VecDeque<TestVectorParams>,
        rtt: RoundtripTimeEstimator,
        state: State,
        vegas: Vegas,
    }

    impl VegasTest {
        fn new(vec: Vec<[u32; 10]>) -> Self {
            let mut params = VecDeque::new();
            for values in vec {
                params.push_back(values.into());
            }
            let state = State::default();
            Self {
                params,
                rtt: new_rtt_estimator(),
                vegas: Vegas::new(&build_vegas_params(), &state, new_cwnd()),
                state,
            }
        }

        fn run_once(&mut self, p: &TestVectorParams) {
            eprintln!("Testing vector: {:?}", p);
            // Set the inflight and channel blocked value from the test vector.
            self.vegas.set_inflight(p.inflight_in);
            self.vegas.set_is_blocked_on_chan(p.or_conn_blocked_in);

            let now = Instant::now();
            self.rtt
                .expect_sendme(now + Duration::from_micros(p.sent_usec_in));
            let ret = self.rtt.update(
                now + Duration::from_micros(p.got_sendme_usec_in),
                &self.state,
                self.vegas.cwnd().expect("No CWND"),
            );
            assert!(ret.is_ok());

            let signals = CongestionSignals::new(p.or_conn_blocked_in, 0);
            let ret = self
                .vegas
                .sendme_received(&mut self.state, &mut self.rtt, signals);
            assert!(ret.is_ok());

            assert_eq!(self.rtt.ewma_rtt_usec(), p.ewma_rtt_usec_out);
            assert_eq!(self.rtt.min_rtt_usec(), p.min_rtt_usec_out);
            assert_eq!(self.vegas.cwnd().expect("No CWND").get(), p.cwnd_out);
            assert_eq!(
                self.vegas.cwnd().expect("No CWND").is_full(),
                p.cwnd_full_out
            );
            assert_eq!(self.state.in_slow_start(), p.in_slow_start_out);
            assert_eq!(self.vegas.is_blocked_on_chan(), p.blocked_chan_out);
        }

        fn run(&mut self) {
            while let Some(param) = self.params.pop_front() {
                self.run_once(&param);
            }
        }
    }

    pub(crate) fn build_vegas_params() -> VegasParams {
        const OUTBUF_CELLS: u32 = 62;
        VegasParamsBuilder::default()
            .cell_in_queue_params(
                (
                    3 * OUTBUF_CELLS, // alpha
                    4 * OUTBUF_CELLS, // beta
                    5 * OUTBUF_CELLS, // delta
                    3 * OUTBUF_CELLS, // gamma
                    600,              // ss_cap
                )
                    .into(),
            )
            .ss_cwnd_max(5_000)
            .cwnd_full_gap(4)
            .cwnd_full_min_pct(Percentage::new(25))
            .cwnd_full_per_cwnd(1)
            .build()
            .expect("Unable to build Vegas parameters")
    }

    #[test]
    fn test_vectors() {
        let vec1 = vec![
            [100000, 200000, 0, 124, 100000, 100000, 155, 1, 0, 0],
            [200000, 300000, 0, 155, 100000, 100000, 186, 1, 1, 0],
            [350000, 500000, 0, 186, 133333, 100000, 217, 1, 1, 0],
            [500000, 550000, 0, 217, 77777, 77777, 248, 1, 1, 0],
            [600000, 700000, 0, 248, 92592, 77777, 279, 1, 1, 0],
            [700000, 750000, 0, 279, 64197, 64197, 310, 1, 0, 0], // Fullness expiry
            [750000, 875000, 0, 310, 104732, 64197, 341, 1, 1, 0],
            [875000, 900000, 0, 341, 51577, 51577, 372, 1, 1, 0],
            [900000, 950000, 0, 279, 50525, 50525, 403, 1, 1, 0],
            [950000, 1000000, 0, 279, 50175, 50175, 434, 1, 1, 0],
            [1000000, 1050000, 0, 279, 50058, 50058, 465, 1, 1, 0],
            [1050000, 1100000, 0, 279, 50019, 50019, 496, 1, 1, 0],
            [1100000, 1150000, 0, 279, 50006, 50006, 527, 1, 1, 0],
            [1150000, 1200000, 0, 279, 50002, 50002, 558, 1, 1, 0],
            [1200000, 1250000, 0, 550, 50000, 50000, 589, 1, 1, 0],
            [1250000, 1300000, 0, 550, 50000, 50000, 620, 1, 0, 0], // Fullness expiry
            [1300000, 1350000, 0, 550, 50000, 50000, 635, 1, 1, 0],
            [1350000, 1400000, 0, 550, 50000, 50000, 650, 1, 1, 0],
            [1400000, 1450000, 0, 150, 50000, 50000, 650, 1, 0, 0], // cwnd not full
            [1450000, 1500000, 0, 150, 50000, 50000, 650, 1, 0, 0], // cwnd not full
            [1500000, 1550000, 0, 550, 50000, 50000, 664, 1, 1, 0], // cwnd full
            [1500000, 1600000, 0, 550, 83333, 50000, 584, 0, 1, 0], // gamma exit
            [1600000, 1650000, 0, 550, 61111, 50000, 585, 0, 1, 0], // alpha
            [1650000, 1700000, 0, 550, 53703, 50000, 586, 0, 1, 0],
            [1700000, 1750000, 0, 100, 51234, 50000, 586, 0, 0, 0], // alpha, not full
            [1750000, 1900000, 0, 100, 117078, 50000, 559, 0, 0, 0], // delta, not full
            [1900000, 2000000, 0, 100, 105692, 50000, 558, 0, 0, 0], // beta, not full
            [2000000, 2075000, 0, 500, 85230, 50000, 558, 0, 1, 0], // no change
            [2075000, 2125000, 1, 500, 61743, 50000, 557, 0, 1, 1], // beta, blocked
            [2125000, 2150000, 0, 500, 37247, 37247, 558, 0, 1, 0], // alpha
            [2150000, 2350000, 0, 500, 145749, 37247, 451, 0, 1, 0], // delta
        ];
        VegasTest::new(vec1).run();

        let vec2 = vec![
            [100000, 200000, 0, 124, 100000, 100000, 155, 1, 0, 0],
            [200000, 300000, 0, 155, 100000, 100000, 186, 1, 1, 0],
            [350000, 500000, 0, 186, 133333, 100000, 217, 1, 1, 0],
            [500000, 550000, 1, 217, 77777, 77777, 403, 0, 1, 1], // ss exit, blocked
            [600000, 700000, 0, 248, 92592, 77777, 404, 0, 1, 0], // alpha
            [700000, 750000, 1, 404, 64197, 64197, 403, 0, 0, 1], // blocked beta
            [750000, 875000, 0, 403, 104732, 64197, 404, 0, 1, 0],
        ];
        VegasTest::new(vec2).run();

        let vec3 = vec![
            [18258527, 19002938, 0, 83, 744411, 744411, 155, 1, 0, 0],
            [18258580, 19254257, 0, 52, 911921, 744411, 186, 1, 1, 0],
            [20003224, 20645298, 0, 164, 732023, 732023, 217, 1, 1, 0],
            [20003367, 21021444, 0, 133, 922725, 732023, 248, 1, 1, 0],
            [20003845, 21265508, 0, 102, 1148683, 732023, 279, 1, 1, 0],
            [20003975, 21429157, 0, 71, 1333015, 732023, 310, 1, 0, 0],
            [20004309, 21707677, 0, 40, 1579917, 732023, 310, 1, 0, 0],
        ];
        VegasTest::new(vec3).run();

        let vec4 = vec![
            [358297091, 358854163, 0, 83, 557072, 557072, 155, 1, 0, 0],
            [358297649, 359123845, 0, 52, 736488, 557072, 186, 1, 1, 0],
            [359492879, 359995330, 0, 186, 580463, 557072, 217, 1, 1, 0],
            [359493043, 360489243, 0, 217, 857621, 557072, 248, 1, 1, 0],
            [359493232, 360489673, 0, 248, 950167, 557072, 279, 1, 1, 0],
            [359493795, 360489971, 0, 279, 980839, 557072, 310, 1, 0, 0],
            [359493918, 360490248, 0, 310, 991166, 557072, 341, 1, 1, 0],
            [359494029, 360716465, 0, 341, 1145346, 557072, 372, 1, 1, 0],
            [359996888, 360948867, 0, 372, 1016434, 557072, 403, 1, 1, 0],
            [359996979, 360949330, 0, 403, 973712, 557072, 434, 1, 1, 0],
            [360489528, 361113615, 0, 434, 740628, 557072, 465, 1, 1, 0],
            [360489656, 361281604, 0, 465, 774841, 557072, 496, 1, 1, 0],
            [360489837, 361500461, 0, 496, 932029, 557072, 482, 0, 1, 0],
            [360489963, 361500631, 0, 482, 984455, 557072, 482, 0, 1, 0],
            [360490117, 361842481, 0, 482, 1229727, 557072, 481, 0, 1, 0],
        ];
        VegasTest::new(vec4).run();
    }
}
