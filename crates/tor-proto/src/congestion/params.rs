//! Define the congestion control parameters needed for the algorithms.
//!
//! All of these values are taken from the consensus. And so the details of these values can be
//! found in section 6.5.1. of proposal 324.

use caret::caret_int;
use derive_builder::Builder;

use tor_config::{ConfigBuildError, impl_standard_builder};
use tor_units::Percentage;

/// Fixed window parameters that are for the SENDME v0 world of fixed congestion window.
#[non_exhaustive]
#[derive(Builder, Copy, Clone, Debug, amplify::Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct FixedWindowParams {
    /// Circuit window starting point. From the "circwindow" param.
    #[getter(as_copy)]
    circ_window_start: u16,
    /// Circuit window minimum value.
    #[getter(as_copy)]
    circ_window_min: u16,
    /// Circuit window maximum value.
    #[getter(as_copy)]
    circ_window_max: u16,
}
impl_standard_builder! { FixedWindowParams: !Deserialize + !Default }

/// Vegas queuing parameters taken from the consensus only which are different depending if the
/// circuit is an onion service one, an exit or used for SBWS.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, amplify::Getters)]
pub struct VegasQueueParams {
    /// Alpha parameter is used to know when to increase the window.
    #[getter(as_copy)]
    alpha: u32,
    /// Beta parameter is used to know when to decrease the window
    #[getter(as_copy)]
    beta: u32,
    /// Delta parameter is used as an indicator to drop the window to this considering the current
    /// BDP value and increment.
    #[getter(as_copy)]
    delta: u32,
    /// Gamma parameter is only used in slow start and used to know when to increase or adjust the
    /// window with the BDP.
    #[getter(as_copy)]
    gamma: u32,
    /// Parameter describe the RFC3742 'cap', after which congestion window increments are reduced.
    /// INT32_MAX disables
    #[getter(as_copy)]
    ss_cwnd_cap: u32,
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
#[derive(Builder, Copy, Clone, Debug, amplify::Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct VegasParams {
    /// The amount of queued cells that Vegas can tolerate before reacting.
    cell_in_queue_params: VegasQueueParams,
    /// A hard-max on the congestion window in Slow Start.
    #[getter(as_copy)]
    ss_cwnd_max: u32,
    /// This parameter defines the integer number of 'cc_sendme_inc' multiples
    /// of gap allowed between inflight and cwnd, to still declare the cwnd full.
    #[getter(as_copy)]
    cwnd_full_gap: u32,
    /// This parameter defines a low watermark in percent.
    cwnd_full_min_pct: Percentage<u32>,
    /// This parameter governs how often a cwnd must be full.
    #[getter(as_copy)]
    cwnd_full_per_cwnd: u32,
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

impl Algorithm {
    /// Return true if this algorithm can be used along with CGO.
    ///
    /// CGO requires the V1 relay cell format, where every relay command
    /// implies either the presence or absence of a StreamID.
    /// But that format is not compatible with (legacy) stream-level SENDME messages
    /// for flow control.
    pub(crate) fn compatible_with_cgo(&self) -> bool {
        match self {
            Algorithm::FixedWindow(_) => false,
            Algorithm::Vegas(_) => true,
        }
    }
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
#[derive(Builder, Clone, Debug, amplify::Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct RoundTripEstimatorParams {
    /// The "N" parameter in N-EWMA smoothing of RTT and/or bandwidth estimation, specified as a
    /// percentage of the number of SENDME acks in a congestion window.
    ///
    /// A percentage over 100% indicates smoothing with more than one congestion window's worth
    /// of SENDMEs.
    ewma_cwnd_pct: Percentage<u32>,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation.
    #[getter(as_copy)]
    ewma_max: u32,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation but in Slow Start.
    #[getter(as_copy)]
    ewma_ss_max: u32,
    /// Describes a percentile average between min and current ewma, for use to reset RTT_min, when
    /// the congestion window hits cwnd_min.
    rtt_reset_pct: Percentage<u32>,
}
impl_standard_builder! { RoundTripEstimatorParams: !Deserialize + !Default }

/// The parameters of what constitute a congestion window. This is used by all congestion control
/// algorithms as in it is not specific to an algorithm.
#[non_exhaustive]
#[derive(Builder, Clone, Copy, Debug, amplify::Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CongestionWindowParams {
    /// Initial size of the congestion window.
    #[getter(as_copy)]
    cwnd_init: u32,
    /// Percent of cwnd to increment by during slow start.
    cwnd_inc_pct_ss: Percentage<u32>,
    /// Number of cells to increment cwnd by during steady state.
    #[getter(as_copy)]
    cwnd_inc: u32,
    /// Number of times per congestion window to update based on congestion signals.
    #[getter(as_copy)]
    cwnd_inc_rate: u32,
    /// Minimum congestion window (must be at least sendme_inc)
    #[getter(as_copy)]
    cwnd_min: u32,
    /// Maximum congestion window
    #[getter(as_copy)]
    cwnd_max: u32,
    /// The SENDME increment as in the number of cells to ACK with every SENDME. This is coming
    /// from the consensus and negotiated during circuit setup.
    #[getter(as_copy)]
    sendme_inc: u32,
}
impl_standard_builder! { CongestionWindowParams: !Deserialize + !Default}

impl CongestionWindowParams {
    /// Set the `sendme_inc` value.
    ///
    /// This is used to override the default increment value from when this was constructed with a
    /// [`CongestionWindowParamsBuilder`].
    /// Typically the default when built should be from the network parameters from the consensus.
    pub(crate) fn set_sendme_inc(&mut self, inc: u8) {
        self.sendme_inc = u32::from(inc);
    }
}

/// Global congestion control parameters taken from consensus. These are per-circuit.
#[non_exhaustive]
#[derive(Builder, Clone, Debug, amplify::Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct CongestionControlParams {
    /// The congestion control algorithm to use.
    alg: Algorithm,
    /// Parameters to the fallback fixed-window algorithm, which we use
    /// when the one in `alg` is not supported by a given relay.
    ///
    /// It is put in here because by the time we do path selection, we don't have access to the
    /// consensus and so we have to keep our fallback ready.
    fixed_window_params: FixedWindowParams,
    /// Congestion window parameters.
    #[getter(as_mut)]
    #[getter(as_copy)]
    cwnd_params: CongestionWindowParams,
    /// RTT calculation parameters.
    rtt_params: RoundTripEstimatorParams,
}
impl_standard_builder! { CongestionControlParams: !Deserialize + !Default }

impl CongestionControlParams {
    /// Return true iff congestion control is enabled that is the algorithm is anything other than
    /// the fixed window SENDMEs.
    ///
    /// C-tor ref: congestion_control_enabled()
    pub(crate) fn is_enabled(&self) -> bool {
        !matches!(self.alg(), Algorithm::FixedWindow(_))
    }

    /// Make these parameters to use the fallback algorithm. This can't be reversed.
    pub(crate) fn use_fallback_alg(&mut self) {
        self.alg = Algorithm::FixedWindow(self.fixed_window_params);
    }
}

/// Return true iff the given sendme increment is valid with regards to the value in the circuit
/// parameters that is taken from the consensus.
pub(crate) fn is_sendme_inc_valid(inc: u8, params: &CongestionControlParams) -> bool {
    // Ease our lives a bit because the consensus value is u32.
    let inc_u32 = u32::from(inc);
    // A consensus value of 1 would allow this sendme increment to be 0 and thus
    // we have to special case it before evaluating.
    if inc == 0 {
        return false;
    }
    let inc_consensus = params.cwnd_params().sendme_inc();
    // See prop324 section 10.3
    if inc_u32 > (inc_consensus.saturating_add(1)) || inc_u32 < (inc_consensus.saturating_sub(1)) {
        return false;
    }
    true
}

#[cfg(test)]
mod test {
    use crate::{
        ccparams::is_sendme_inc_valid, congestion::test_utils::params::build_cc_vegas_params,
    };

    #[test]
    fn test_sendme_inc_valid() {
        let params = build_cc_vegas_params();
        let ref_inc = params.cwnd_params().sendme_inc() as u8;

        // In range.
        assert!(is_sendme_inc_valid(ref_inc, &params));
        assert!(is_sendme_inc_valid(ref_inc + 1, &params));
        assert!(is_sendme_inc_valid(ref_inc - 1, &params));
        // Out of range.
        assert!(!is_sendme_inc_valid(0, &params));
        assert!(!is_sendme_inc_valid(ref_inc + 2, &params));
        assert!(!is_sendme_inc_valid(ref_inc - 2, &params));
    }
}
