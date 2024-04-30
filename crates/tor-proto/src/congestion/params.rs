//! Define the congestion control parameters needed for the algorithms.
//!
//! All of these values are taken from the consensus. And so the details of these values can be
//! found in section 6.5.1. of proposal 324.

use derive_builder::Builder;

use tor_config::{impl_standard_builder, ConfigBuildError};
use tor_units::Percentage;

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
    #[builder(default = "Percentage::new(0)")]
    pub ewma_cwnd_pct: Percentage<u32>,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation.
    #[builder(default)]
    pub ewma_max: u32,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation but in Slow Start.
    #[builder(default)]
    pub ewma_ss_max: u32,
    /// Describes a percentile average between min and current ewma, for use to reset RTT_min, when
    /// the congestion window hits cwnd_min.
    #[builder(default = "Percentage::new(0)")]
    pub rtt_reset_pct: Percentage<u32>,
}
impl_standard_builder! { RoundTripEstimatorParams: !Deserialize }

/// The parameters of what constitute a congestion window. This is used by all congestion control
/// algorithms as in it is not specific to an algorithm.
#[non_exhaustive]
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CongestionWindowParams {
    /// Initial size of the congestion window.
    #[builder(default)]
    pub cwnd_init: u32,
    /// Percent of cwnd to increment by during slow start.
    #[builder(default = "Percentage::new(0)")]
    pub cwnd_inc_pct_ss: Percentage<u32>,
    /// Number of cells to increment cwnd by during steady state.
    #[builder(default)]
    pub cwnd_inc: u32,
    /// Number of times per congestion window to update based on congestion signals.
    #[builder(default)]
    pub cwnd_inc_rate: u32,
    /// Minimum congestion window (must be at least sendme_inc)
    #[builder(default)]
    pub cwnd_min: u32,
    /// Maximum congestion window
    #[builder(default)]
    pub cwnd_max: u32,
    /// The SENDME increment as in the number of cells to ACK with every SENDME. This is coming
    /// from the consensus and negotiated during circuit setup.
    #[builder(default)]
    pub sendme_inc: u32,
}
impl_standard_builder! { CongestionWindowParams: !Deserialize }
