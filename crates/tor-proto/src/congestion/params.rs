//! Define the congestion control parameters needed for the algorithms.
//!
//! All of these values are taken from the consensus. And so the details of these values can be
//! found in section 6.5.1. of proposal 324.

use caret::caret_int;
use derive_builder::Builder;

use tor_config::{impl_standard_builder, ConfigBuildError};
use tor_units::Percentage;

/// Fixed window parameters that are for the SENDME v0 world of fixed congestion window.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct FixedWindowParams {
    /// Circuit window starting point. From the "circwindow" param.
    pub circ_window_start: u16,
    /// Circuit window minimum value.
    pub circ_window_min: u16,
    /// Circuit window maximum value.
    pub circ_window_max: u16,
}
impl_standard_builder! { FixedWindowParams: !Deserialize + !Default }

/// Vegas queuing parameters taken from the consensus only which are different depending if the
/// circuit is an onion service one, an exit or used for SBWS.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct VegasQueueParams {
    /// Alpha parameter is used to know when to increase the window.
    pub alpha: u32,
    /// Beta parameter is used to know when to decrease the window
    pub beta: u32,
    /// Delta parameter is used as an indicator to drop the window to this considering the current
    /// BDP value and increment.
    pub delta: u32,
    /// Gamma parameter is only used in slow start and used to know when to increase or adjust the
    /// window with the BDP.
    pub gamma: u32,
    /// Parameter describe the RFC3742 'cap', after which congestion window increments are reduced.
    /// INT32_MAX disables
    pub ss_cwnd_cap: u32,
}

/// Used when we parse at once all the specific circuit type vegas queue parameters. They are
/// bundled in a 5-tuple and transformed with this.
impl From<(u32, u32, u32, u32, u32)> for VegasQueueParams {
    fn from(v: (u32, u32, u32, u32, u32)) -> Self {
        Self {
            alpha: v.0,
            beta: v.1,
            delta: v.2,
            gamma: v.3,
            ss_cwnd_cap: v.4,
        }
    }
}

/// Vegas algorithm parameters taken from the consensus.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct VegasParams {
    /// The amount of queued cells that Vegas can tolerate before reacting.
    pub cell_in_queue_params: VegasQueueParams,
    /// A hard-max on the congestion window in Slow Start.
    pub ss_cwnd_max: u32,
    /// This parameter defines the integer number of 'cc_sendme_inc' multiples
    /// of gap allowed between inflight and cwnd, to still declare the cwnd full.
    pub cwnd_full_gap: u32,
    /// This paramter defines a low watermark in percent.
    pub cwnd_full_min_pct: Percentage<u32>,
    /// This parameter governs how often a cwnd must be full.
    pub cwnd_full_per_cwnd: u32,
}
impl_standard_builder! { VegasParams: !Deserialize + !Default }

/// The different congestion control algorithms. Each contain their parameters taken from the
/// consensus.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Algorithm {
    /// Fixed window algorithm.
    FixedWindow(FixedWindowParams),
    /// Vegas algorithm.
    Vegas(VegasParams),
}

caret_int! {
    /// Congestion control algorithm types defined by numerical values. See "cc_alg" in proposal
    /// 324 section 6.5.1 for the supported values.
    ///
    /// This is a i32 so it is the same type as the consensus supported value type.
    pub struct AlgorithmType(i32) {
        /// Fixed window algorithm.
        FIXED_WINDOW = 0,
        /// Vegas algorithm.
        VEGAS = 2,
    }
}

/// The round trip estimator parameters taken from consensus and used to estimate the round trip
/// time on a circuit.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct RoundTripEstimatorParams {
    /// The "N" parameter in N-EWMA smoothing of RTT and/or bandwidth estimation, specified as a
    /// percentage of the number of SENDME acks in a congestion window.
    ///
    /// A percentage over 100% indicates smoothing with more than one congestion window's worth
    /// of SENDMEs.
    pub ewma_cwnd_pct: Percentage<u32>,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation.
    pub ewma_max: u32,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation but in Slow Start.
    pub ewma_ss_max: u32,
    /// Describes a percentile average between min and current ewma, for use to reset RTT_min, when
    /// the congestion window hits cwnd_min.
    pub rtt_reset_pct: Percentage<u32>,
}
impl_standard_builder! { RoundTripEstimatorParams: !Deserialize + !Default }

/// The parameters of what constitute a congestion window. This is used by all congestion control
/// algorithms as in it is not specific to an algorithm.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CongestionWindowParams {
    /// Initial size of the congestion window.
    pub cwnd_init: u32,
    /// Percent of cwnd to increment by during slow start.
    pub cwnd_inc_pct_ss: Percentage<u32>,
    /// Number of cells to increment cwnd by during steady state.
    pub cwnd_inc: u32,
    /// Number of times per congestion window to update based on congestion signals.
    pub cwnd_inc_rate: u32,
    /// Minimum congestion window (must be at least sendme_inc)
    pub cwnd_min: u32,
    /// Maximum congestion window
    pub cwnd_max: u32,
    /// The SENDME increment as in the number of cells to ACK with every SENDME. This is coming
    /// from the consensus and negotiated during circuit setup.
    pub sendme_inc: u32,
}
impl_standard_builder! { CongestionWindowParams: !Deserialize + !Default}

/// Global congestion control parameters taken from consensus. These are per-circuit.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CongestionControlParams {
    /// The congestion control algorithm to use.
    pub alg: Algorithm,
    /// Congestion window parameters.
    pub cwnd_params: CongestionWindowParams,
    /// RTT calculation parameters.
    pub rtt_params: RoundTripEstimatorParams,
}
impl_standard_builder! { CongestionControlParams: !Deserialize + !Default }
