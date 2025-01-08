//! Test helpers.

#[cfg(test)]
use super::{rtt::RoundtripTimeEstimator, CongestionWindow};

// Make a new RTT estimator.
#[cfg(test)]
pub(crate) fn new_rtt_estimator() -> RoundtripTimeEstimator {
    RoundtripTimeEstimator::new(&params::build_rtt_params())
}

// Make a new congestion window.
#[cfg(test)]
pub(crate) fn new_cwnd() -> CongestionWindow {
    CongestionWindow::new(&params::build_cwnd_params())
}

#[cfg(test)]
pub(crate) mod params {
    use tor_units::Percentage;

    use crate::ccparams::{
        CongestionWindowParams, CongestionWindowParamsBuilder, RoundTripEstimatorParams,
        RoundTripEstimatorParamsBuilder,
    };

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
