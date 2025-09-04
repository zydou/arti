//! Test helpers.

#[cfg(test)]
use super::{CongestionWindow, rtt::RoundtripTimeEstimator};

// Make a new RTT estimator.
#[cfg(test)]
pub(crate) fn new_rtt_estimator() -> RoundtripTimeEstimator {
    RoundtripTimeEstimator::new(&params::build_rtt_params())
}

// Make a new congestion window.
#[cfg(test)]
pub(crate) fn new_cwnd() -> CongestionWindow {
    CongestionWindow::new(params::build_cwnd_params())
}

#[cfg(test)]
pub(crate) mod params {
    use tor_units::Percentage;

    use crate::ccparams::{
        Algorithm, CongestionControlParams, CongestionControlParamsBuilder, CongestionWindowParams,
        CongestionWindowParamsBuilder, FixedWindowParams, FixedWindowParamsBuilder,
        RoundTripEstimatorParams, RoundTripEstimatorParamsBuilder, VegasParamsBuilder,
    };

    fn build_fixed_params() -> FixedWindowParams {
        FixedWindowParamsBuilder::default()
            .circ_window_start(1000)
            .circ_window_min(100)
            .circ_window_max(1000)
            .build()
            .expect("Unable to build fixed window params")
    }

    pub(crate) fn build_cc_vegas_params() -> CongestionControlParams {
        // Following values are the default from the proposal. They likely differ from what the
        // consensus uses today.
        let params = VegasParamsBuilder::default()
            .cell_in_queue_params((186, 248, 310, 186, 600).into())
            .ss_cwnd_max(5000)
            .cwnd_full_gap(4)
            .cwnd_full_min_pct(Percentage::new(25))
            .cwnd_full_per_cwnd(1)
            .build()
            .expect("Unable to build Vegas params");
        CongestionControlParamsBuilder::default()
            .rtt_params(build_rtt_params())
            .cwnd_params(build_cwnd_params())
            .alg(Algorithm::Vegas(params))
            .fixed_window_params(build_fixed_params())
            .build()
            .expect("Unable to build CC params")
    }

    pub(crate) fn build_cc_fixed_params() -> CongestionControlParams {
        let params = build_fixed_params();
        CongestionControlParamsBuilder::default()
            .rtt_params(build_rtt_params())
            .cwnd_params(build_cwnd_params())
            .alg(Algorithm::FixedWindow(params))
            .fixed_window_params(params)
            .build()
            .expect("Unable to build CC params")
    }

    // Build the round trip estimator parameters. with good enough values for tests.
    pub(crate) fn build_rtt_params() -> RoundTripEstimatorParams {
        RoundTripEstimatorParamsBuilder::default()
            .ewma_cwnd_pct(Percentage::new(50))
            .ewma_max(10)
            .ewma_ss_max(2)
            .rtt_reset_pct(Percentage::new(100))
            .build()
            .expect("Unable to build RTT parameters")
    }

    // Build the congestion window parameters. with good enough values for tests.
    pub(crate) fn build_cwnd_params() -> CongestionWindowParams {
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
}
