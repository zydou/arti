//! Implement Tor's sort-of-Pareto estimator for circuit build timeouts.
//!
//! Our build times don't truly follow a
//! [Pareto](https://en.wikipedia.org/wiki/Pareto_distribution)
//! distribution; instead they seem to be closer to a
//! [Fréchet](https://en.wikipedia.org/wiki/Fr%C3%A9chet_distribution)
//! distribution.  But those are hard to work with, and we only care
//! about the right tail, so we're using Pareto instead.
//!
//! This estimator also includes several heuristics and kludges to
//! try to behave better on unreliable networks.
//! For more information on the exact algorithms and their rationales,
//! see [`path-spec.txt`](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/path-spec.txt).

use bounded_vec_deque::BoundedVecDeque;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tor_netdir::params::NetParameters;

use super::Action;
use tor_persist::JsonValue;

/// How many circuit build time observations do we record?
const TIME_HISTORY_LEN: usize = 1000;

/// How many circuit success-versus-timeout observations do we record
/// by default?
const SUCCESS_HISTORY_DEFAULT_LEN: usize = 20;

/// How many milliseconds wide is each bucket in our histogram?
const BUCKET_WIDTH_MSEC: u32 = 10;

/// A circuit build time or timeout duration, measured in milliseconds.
///
/// Requires that we don't care about tracking timeouts above u32::MAX
/// milliseconds (about 49 days).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
struct MsecDuration(u32);

impl MsecDuration {
    /// Convert a Duration into a MsecDuration, saturating
    /// extra-high values to u32::MAX milliseconds.
    fn new_saturating(d: &Duration) -> Self {
        let msec = std::cmp::min(d.as_millis(), u128::from(u32::MAX)) as u32;
        MsecDuration(msec)
    }
}

/// Module to hold calls to const_assert.
///
/// This is a separate module so we can change the clippy warnings on it.
#[allow(clippy::checked_conversions)]
mod assertion {
    use static_assertions::const_assert;
    // If this assertion is untrue, then we can't safely use u16 fields in
    // time_histogram.
    const_assert!(super::TIME_HISTORY_LEN <= u16::MAX as usize);
}

/// A history of circuit timeout observations, used to estimate our
/// likely circuit timeouts.
#[derive(Debug, Clone)]
struct History {
    /// Our most recent observed circuit construction times.
    ///
    /// For the purpose of this estimator, a circuit counts as
    /// "constructed" when a certain "significant" hop (typically the third)
    /// is completed.
    time_history: BoundedVecDeque<MsecDuration>,

    /// A histogram representation of the values in [`History::time_history`].
    ///
    /// This histogram is implemented as a sparse map from the center
    /// value of each histogram bucket to the number of entries in
    /// that bucket.  It is completely derivable from time_history; we
    /// keep it separate here for efficiency.
    time_histogram: BTreeMap<MsecDuration, u16>,

    /// Our most recent circuit timeout statuses.
    ///
    /// Each `true` value represents a successfully completed circuit
    /// (all hops).  Each `false` value represents a circuit that
    /// timed out after having completed at least one hop.
    success_history: BoundedVecDeque<bool>,
}

impl History {
    /// Initialize a new empty `History` with no observations.
    fn new_empty() -> Self {
        History {
            time_history: BoundedVecDeque::new(TIME_HISTORY_LEN),
            time_histogram: BTreeMap::new(),
            success_history: BoundedVecDeque::new(SUCCESS_HISTORY_DEFAULT_LEN),
        }
    }

    /// Remove all observations from this `History`.
    fn clear(&mut self) {
        self.time_history.clear();
        self.time_histogram.clear();
        self.success_history.clear();
    }

    /// Change the number of successes to record in our success
    /// history to `n`.
    fn set_success_history_len(&mut self, n: usize) {
        if n < self.success_history.len() {
            self.success_history
                .drain(0..(self.success_history.len() - n));
        }
        self.success_history.set_max_len(n);
    }

    /// Change the number of circuit time observations to record in
    /// our time history to `n`.
    ///
    /// This is a testing-only function.
    #[cfg(test)]
    fn set_time_history_len(&mut self, n: usize) {
        self.time_history.set_max_len(n);
    }

    /// Construct a new `History` from an iterator representing a sparse
    /// histogram of values.
    ///
    /// The input must be a sequence of `(D,N)` tuples, where each `D`
    /// represents a circuit build duration, and `N` represents the
    /// number of observations with that duration.
    ///
    /// These observations are shuffled into a random order, then
    /// added to a new History.
    fn from_sparse_histogram<I>(iter: I) -> Self
    where
        I: Iterator<Item = (MsecDuration, u16)>,
    {
        use rand::seq::{IteratorRandom, SliceRandom};
        use std::iter;
        let mut rng = rand::thread_rng();

        // We want to build a vector with the elements of the old histogram in
        // random order, but we want to defend ourselves against bogus inputs
        // that would take too much RAM.
        let mut observations = iter
            .take(TIME_HISTORY_LEN) // limit number of bins
            .flat_map(|(dur, n)| iter::repeat(dur).take(n as usize))
            .choose_multiple(&mut rng, TIME_HISTORY_LEN);
        // choose_multiple doesn't guarantee anything about the order of its output.
        observations.shuffle(&mut rng);

        let mut result = History::new_empty();
        for obs in observations {
            result.add_time(obs);
        }

        result
    }

    /// Return an iterator yielding a sparse histogram of the circuit build
    /// time values in this `History`.
    ///
    /// Each histogram entry is a `(D,N)` tuple, where `D` is the
    /// center of a histogram bucket, and `N` is the number of
    /// observations in that bucket.
    ///
    /// Buckets with `N=0` are omitted.  Buckets are yielded in order.
    fn sparse_histogram(&self) -> impl Iterator<Item = (MsecDuration, u16)> + '_ {
        self.time_histogram.iter().map(|(d, n)| (*d, *n))
    }

    /// Return the center value for the bucket containing `time`.
    fn bucket_center(time: MsecDuration) -> MsecDuration {
        let idx = time.0 / BUCKET_WIDTH_MSEC;
        let msec = (idx * BUCKET_WIDTH_MSEC) + (BUCKET_WIDTH_MSEC) / 2;
        MsecDuration(msec)
    }

    /// Increment the histogram bucket containing `time` by one.
    fn inc_bucket(&mut self, time: MsecDuration) {
        let center = History::bucket_center(time);
        *self.time_histogram.entry(center).or_insert(0) += 1;
    }

    /// Decrement the histogram bucket containing `time` by one, removing
    /// it if it becomes 0.
    fn dec_bucket(&mut self, time: MsecDuration) {
        use std::collections::btree_map::Entry;
        let center = History::bucket_center(time);
        match self.time_histogram.entry(center) {
            Entry::Vacant(_) => {
                // this is a bug.
            }
            Entry::Occupied(e) if e.get() <= &1 => {
                e.remove();
            }
            Entry::Occupied(mut e) => {
                *e.get_mut() -= 1;
            }
        }
    }

    /// Add `time` to our list of circuit build time observations, and
    /// adjust the histogram accordingly.
    fn add_time(&mut self, time: MsecDuration) {
        match self.time_history.push_back(time) {
            None => {}
            Some(removed_time) => {
                // `removed_time` just fell off the end of the deque:
                // remove it from the histogram.
                self.dec_bucket(removed_time);
            }
        }
        self.inc_bucket(time);
    }

    /// Return the number of observations in our time history.
    ///
    /// This will always be `<= TIME_HISTORY_LEN`.
    fn n_times(&self) -> usize {
        self.time_history.len()
    }

    /// Record a success (true) or timeout (false) in our record of whether
    /// circuits timed out or not.
    fn add_success(&mut self, succeeded: bool) {
        self.success_history.push_back(succeeded);
    }

    /// Return the number of timeouts recorded in our success history.
    fn n_recent_timeouts(&self) -> usize {
        self.success_history.iter().filter(|x| !**x).count()
    }

    /// Helper: return the `n` most frequent histogram bins.
    fn n_most_frequent_bins(&self, n: usize) -> Vec<(MsecDuration, u16)> {
        use itertools::Itertools;
        // we use cmp::Reverse here so that we can use k_smallest as
        // if it were "k_largest".
        use std::cmp::Reverse;

        // We want the buckets that have the _largest_ counts; we want
        // to break ties in favor of the _smallest_ values.  So we
        // apply Reverse only to the counts before passing the tuples
        // to k_smallest.

        self.sparse_histogram()
            .map(|(center, count)| (Reverse(count), center))
            // (k_smallest runs in O(n_bins * lg(n))
            .k_smallest(n)
            .map(|(Reverse(count), center)| (center, count))
            .collect()
    }

    /// Return an estimator for the `X_m` of our Pareto distribution,
    /// by looking at the `n_modes` most frequently filled histogram
    /// bins.
    ///
    /// It is not a true `X_m` value, since there are definitely
    /// values less than this, but it seems to work as a decent
    /// heuristic.
    ///
    /// Return `None` if we have no observations.
    fn estimate_xm(&self, n_modes: usize) -> Option<u32> {
        // From path-spec:
        //   Tor clients compute the Xm parameter using the weighted
        //   average of the midpoints of the 'cbtnummodes' (10)
        //   most frequently occurring 10ms histogram bins.

        // The most frequently used bins.
        let bins = self.n_most_frequent_bins(n_modes);
        // Total number of observations in these bins.
        let n_observations: u16 = bins.iter().map(|(_, n)| n).sum();
        // Sum of all observations in these bins.
        let total_observations: u64 = bins
            .iter()
            .map(|(d, n)| u64::from(d.0 * u32::from(*n)))
            .sum();

        if n_observations == 0 {
            None
        } else {
            Some((total_observations / u64::from(n_observations)) as u32)
        }
    }

    /// Compute a maximum-likelihood pareto distribution based on this
    /// history, computing `X_m` based on the `n_modes` most frequent
    /// histograms.
    ///
    /// Return None if we have no observations.
    fn pareto_estimate(&self, n_modes: usize) -> Option<ParetoDist> {
        let xm = self.estimate_xm(n_modes)?;

        // From path-spec:
        //     alpha = n/(Sum_n{ln(MAX(Xm, x_i))} - n*ln(Xm))

        let n = self.time_history.len();
        let sum_of_log_observations: f64 = self
            .time_history
            .iter()
            .map(|m| f64::from(std::cmp::max(m.0, xm)).ln())
            .sum();
        let sum_of_log_xm = (n as f64) * f64::from(xm).ln();

        // We're computing 1/alpha here, instead of alpha.  This avoids
        // division by zero, and has the advantage of being what our
        // quantile estimator actually needs.
        let inv_alpha = (sum_of_log_observations - sum_of_log_xm) / (n as f64);

        Some(ParetoDist {
            x_m: f64::from(xm),
            inv_alpha,
        })
    }
}

/// A Pareto distribution, for use in estimating timeouts.
///
/// Values are represented by a number of milliseconds.
#[derive(Debug)]
struct ParetoDist {
    /// The lower bound for the pareto distribution.
    x_m: f64,
    /// The inverse of the alpha parameter in the pareto distribution.
    ///
    /// (We use 1/alpha here to save a step in [`ParetoDist::quantile`].
    inv_alpha: f64,
}

impl ParetoDist {
    /// Compute an inverse CDF for this distribution.
    ///
    /// Given a `q` value between 0 and 1, compute a distribution `v`
    /// value such that `q` of the Pareto Distribution is expected to
    /// be less than `v`.
    ///
    /// If `q` is out of bounds, it is clamped to [0.0, 1.0].
    fn quantile(&self, q: f64) -> f64 {
        let q = q.clamp(0.0, 1.0);
        self.x_m / ((1.0 - q).powf(self.inv_alpha))
    }
}

/// A set of parameters determining the behavior of a ParetoTimeoutEstimator.
///
/// These are typically derived from a set of consensus parameters.
#[derive(Clone, Debug)]
pub(crate) struct Params {
    /// Should we use our estimates when deciding on circuit timeouts.
    ///
    /// When this is false, our timeouts are fixed to the default.
    use_estimates: bool,
    /// How many observations must we have made before we can use our
    /// Pareto estimators to guess a good set of timeouts?
    min_observations: u16,
    /// Which hop is the "significant hop" we should use when recording circuit
    /// build times?  (Watch out! This is zero-indexed.)
    significant_hop: u8,
    /// A quantile (in range [0.0,1.0]) describing a point in the
    /// Pareto distribution to use when determining when a circuit
    /// should be treated as having "timed out".
    ///
    /// (A "timed out" circuit continues building for measurement
    /// purposes, but can't be used for traffic.)
    timeout_quantile: f64,
    /// A quantile (in range [0.0,1.0]) describing a point in the Pareto
    /// distribution to use when determining when a circuit should be
    /// "abandoned".
    ///
    /// (An "abandoned" circuit is stopped entirely, and not included
    /// in measurements.
    abandon_quantile: f64,
    /// Default values to return from the `timeouts` function when we
    /// have no observations.
    default_thresholds: (Duration, Duration),
    /// Number of histogram buckets to use when determining the Xm estimate.
    ///
    /// (See [`History::estimate_xm`] for details.)
    n_modes_for_xm: usize,
    /// How many entries do we record in our success/timeout history?
    success_history_len: usize,
    /// How many timeouts should we allow in our success/timeout history
    /// before we assume that network has changed in a way that makes
    /// our estimates completely wrong?
    reset_after_timeouts: usize,
    /// Minimum base timeout to ever infer or return.
    min_timeout: Duration,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            use_estimates: true,
            min_observations: 100,
            significant_hop: 2,
            timeout_quantile: 0.80,
            abandon_quantile: 0.99,
            default_thresholds: (Duration::from_secs(60), Duration::from_secs(60)),
            n_modes_for_xm: 10,
            success_history_len: SUCCESS_HISTORY_DEFAULT_LEN,
            reset_after_timeouts: 18,
            min_timeout: Duration::from_millis(10),
        }
    }
}

impl From<&NetParameters> for Params {
    fn from(p: &NetParameters) -> Params {
        // Because of the underlying bounds, the "unwrap_or_else"
        // conversions here should be impossible, and the "as"
        // conversions should always be in-range.

        let timeout = p
            .cbt_initial_timeout
            .try_into()
            .unwrap_or_else(|_| Duration::from_secs(60));
        let learning_disabled: bool = p.cbt_learning_disabled.into();
        Params {
            use_estimates: !learning_disabled,
            min_observations: p.cbt_min_circs_for_estimate.get() as u16,
            significant_hop: 2,
            timeout_quantile: p.cbt_timeout_quantile.as_fraction(),
            abandon_quantile: p.cbt_abandon_quantile.as_fraction(),
            default_thresholds: (timeout, timeout),
            n_modes_for_xm: p.cbt_num_xm_modes.get() as usize,
            success_history_len: p.cbt_success_count.get() as usize,
            reset_after_timeouts: p.cbt_max_timeouts.get() as usize,
            min_timeout: p
                .cbt_min_timeout
                .try_into()
                .unwrap_or_else(|_| Duration::from_millis(10)),
        }
    }
}

/// Tor's default circuit build timeout estimator.
///
/// This object records a set of observed circuit build times, and
/// uses it to determine good values for how long we should allow
/// circuits to build.
///
/// For full details of the algorithms used, see
/// [`path-spec.txt`](https://gitlab.torproject.org/tpo/core/torspec/-/blob/master/path-spec.txt).
pub(crate) struct ParetoTimeoutEstimator {
    /// Our observations for circuit build times and success/failure
    /// history.
    history: History,

    /// Our most recent timeout estimate, if we have one that is
    /// up-to-date.
    ///
    /// (We reset this to None whenever we get a new observation.)
    timeouts: Option<(Duration, Duration)>,

    /// The timeouts that we use when we do not have sufficient observations
    /// to conclude anything about our circuit build times.
    ///
    /// These start out as `p.default_thresholds`, but can be adjusted
    /// depending on how many timeouts we've been seeing.
    fallback_timeouts: (Duration, Duration),

    /// A set of parameters to use in computing circuit build timeout
    /// estimates.
    p: Params,
}

impl Default for ParetoTimeoutEstimator {
    fn default() -> Self {
        Self::from_history(History::new_empty())
    }
}

/// An object used to serialize our timeout history for persistent state.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub(crate) struct ParetoTimeoutState {
    /// A version field used to help encoding and decoding.
    #[allow(dead_code)]
    version: usize,
    /// A record of observed timeouts, as returned by `sparse_histogram()`.
    histogram: Vec<(MsecDuration, u16)>,
    /// The current timeout estimate: kept for reference.
    current_timeout: Option<MsecDuration>,

    /// Fields from the state file that was used to make this `ParetoTimeoutState` that
    /// this version of Arti doesn't understand.
    #[serde(flatten)]
    unknown_fields: HashMap<String, JsonValue>,
}

impl ParetoTimeoutState {
    /// Return the latest base timeout estimate, as recorded in this state.
    pub(crate) fn latest_estimate(&self) -> Option<Duration> {
        self.current_timeout
            .map(|m| Duration::from_millis(m.0.into()))
    }
}

impl ParetoTimeoutEstimator {
    /// Construct a new ParetoTimeoutEstimator from the provided history
    /// object.
    fn from_history(history: History) -> Self {
        let p = Params::default();
        ParetoTimeoutEstimator {
            history,
            timeouts: None,
            fallback_timeouts: p.default_thresholds,
            p,
        }
    }

    /// Create a new ParetoTimeoutEstimator based on a loaded
    /// ParetoTimeoutState.
    pub(crate) fn from_state(state: ParetoTimeoutState) -> Self {
        let history = History::from_sparse_histogram(state.histogram.into_iter());
        Self::from_history(history)
    }

    /// Compute an unscaled basic pair of timeouts for a circuit of
    /// the "normal" length.
    ///
    /// Return a cached value if we have no observations since the
    /// last time this function was called.
    fn base_timeouts(&mut self) -> (Duration, Duration) {
        if let Some(x) = self.timeouts {
            // Great; we have a cached value.
            return x;
        }

        if self.history.n_times() < self.p.min_observations as usize {
            // We don't have enough values to estimate.
            return self.fallback_timeouts;
        }

        // Here we're going to compute the timeouts, cache them, and
        // return them.
        let dist = match self.history.pareto_estimate(self.p.n_modes_for_xm) {
            Some(dist) => dist,
            None => {
                return self.fallback_timeouts;
            }
        };
        let timeout_threshold = dist.quantile(self.p.timeout_quantile);
        let abandon_threshold = dist
            .quantile(self.p.abandon_quantile)
            .max(timeout_threshold);

        let timeouts = (
            Duration::from_secs_f64(timeout_threshold / 1000.0).max(self.p.min_timeout),
            Duration::from_secs_f64(abandon_threshold / 1000.0).max(self.p.min_timeout),
        );
        self.timeouts = Some(timeouts);

        timeouts
    }
}

impl super::TimeoutEstimator for ParetoTimeoutEstimator {
    fn update_params(&mut self, p: &NetParameters) {
        let parameters = p.into();
        self.p = parameters;
        let new_success_len = self.p.success_history_len;
        self.history.set_success_history_len(new_success_len);
    }

    fn note_hop_completed(&mut self, hop: u8, delay: Duration, is_last: bool) {
        if hop == self.p.significant_hop {
            let time = MsecDuration::new_saturating(&delay);
            self.history.add_time(time);
            self.timeouts.take();
        }
        if is_last {
            self.history.add_success(true);
        }
    }

    fn note_circ_timeout(&mut self, hop: u8, delay: Duration) {
        // Only record this timeout if we have seen some network activity since
        // we launched the circuit.
        let have_seen_recent_activity =
            if let Some(last_traffic) = tor_proto::time_since_last_incoming_traffic() {
                last_traffic < delay
            } else {
                // TODO: Is this the correct behavior in this case?
                true
            };

        tracing::trace!(%hop, ?delay, %have_seen_recent_activity, "Circuit timeout");

        if hop > 0 && have_seen_recent_activity {
            self.history.add_success(false);
            if self.history.n_recent_timeouts() > self.p.reset_after_timeouts {
                let base_timeouts = self.base_timeouts();
                self.history.clear();
                self.timeouts.take();
                // If we already had a timeout that was at least the
                // length of our fallback timeouts, we should double
                // those fallback timeouts.
                if base_timeouts.0 >= self.fallback_timeouts.0 {
                    self.fallback_timeouts.0 *= 2;
                    self.fallback_timeouts.1 *= 2;
                }
            }
        }
    }

    fn timeouts(&mut self, action: &Action) -> (Duration, Duration) {
        let (base_t, base_a) = if self.p.use_estimates {
            self.base_timeouts()
        } else {
            // If we aren't using this estimator, then just return the
            // default thresholds from our parameters.
            return self.p.default_thresholds;
        };

        let reference_action = Action::BuildCircuit {
            length: self.p.significant_hop as usize + 1,
        };
        debug_assert!(reference_action.timeout_scale() > 0);

        let multiplier =
            (action.timeout_scale() as f64) / (reference_action.timeout_scale() as f64);

        // TODO-SPEC The spec doesn't define any of this
        // action-based-multiplier stuff.  Tor doesn't multiply the
        // abandon timeout.
        use super::mul_duration_f64_saturating as mul;
        (mul(base_t, multiplier), mul(base_a, multiplier))
    }

    fn learning_timeouts(&self) -> bool {
        self.p.use_estimates && self.history.n_times() < self.p.min_observations.into()
    }

    fn build_state(&mut self) -> Option<ParetoTimeoutState> {
        let cur_timeout = MsecDuration::new_saturating(&self.base_timeouts().0);
        Some(ParetoTimeoutState {
            version: 1,
            histogram: self.history.sparse_histogram().collect(),
            current_timeout: Some(cur_timeout),
            unknown_fields: Default::default(),
        })
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
    use crate::timeouts::TimeoutEstimator;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_basic_utils::RngExt as _;

    /// Return an action to build a 3-hop circuit.
    fn b3() -> Action {
        Action::BuildCircuit { length: 3 }
    }

    impl From<u32> for MsecDuration {
        fn from(v: u32) -> Self {
            Self(v)
        }
    }

    #[test]
    fn ms_partial_cmp() {
        #![allow(clippy::eq_op)]
        let myriad: MsecDuration = 10_000.into();
        let lakh: MsecDuration = 100_000.into();
        let crore: MsecDuration = 10_000_000.into();

        assert!(myriad < lakh);
        assert!(myriad == myriad);
        assert!(crore > lakh);
        assert!(crore >= crore);
        assert!(crore <= crore);
    }

    #[test]
    fn history_lowlev() {
        assert_eq!(History::bucket_center(1.into()), 5.into());
        assert_eq!(History::bucket_center(903.into()), 905.into());
        assert_eq!(History::bucket_center(0.into()), 5.into());
        assert_eq!(History::bucket_center(u32::MAX.into()), 4294967295.into());

        let mut h = History::new_empty();
        h.inc_bucket(7.into());
        h.inc_bucket(8.into());
        h.inc_bucket(9.into());
        h.inc_bucket(10.into());
        h.inc_bucket(11.into());
        h.inc_bucket(12.into());
        h.inc_bucket(13.into());
        h.inc_bucket(299.into());
        assert_eq!(h.time_histogram.get(&5.into()), Some(&3));
        assert_eq!(h.time_histogram.get(&15.into()), Some(&4));
        assert_eq!(h.time_histogram.get(&25.into()), None);
        assert_eq!(h.time_histogram.get(&295.into()), Some(&1));

        h.dec_bucket(299.into());
        h.dec_bucket(24.into());
        h.dec_bucket(12.into());

        assert_eq!(h.time_histogram.get(&15.into()), Some(&3));
        assert_eq!(h.time_histogram.get(&25.into()), None);
        assert_eq!(h.time_histogram.get(&295.into()), None);

        h.add_success(true);
        h.add_success(false);
        assert_eq!(h.success_history.len(), 2);

        h.clear();
        assert_eq!(h.time_histogram.len(), 0);
        assert_eq!(h.time_history.len(), 0);
        assert_eq!(h.success_history.len(), 0);
    }

    #[test]
    fn time_observation_management() {
        let mut h = History::new_empty();
        h.set_time_history_len(8); // to make it easier to overflow.

        h.add_time(300.into());
        h.add_time(500.into());
        h.add_time(542.into());
        h.add_time(305.into());
        h.add_time(543.into());
        h.add_time(307.into());

        assert_eq!(h.n_times(), 6);
        let v = h.n_most_frequent_bins(10);
        assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2), (505.into(), 1)]);
        let v = h.n_most_frequent_bins(2);
        assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2)]);

        let v: Vec<_> = h.sparse_histogram().collect();
        assert_eq!(&v[..], [(305.into(), 3), (505.into(), 1), (545.into(), 2)]);

        h.add_time(212.into());
        h.add_time(203.into());
        // now we replace the first couple of older elements.
        h.add_time(617.into());
        h.add_time(413.into());

        assert_eq!(h.n_times(), 8);

        let v: Vec<_> = h.sparse_histogram().collect();
        assert_eq!(
            &v[..],
            [
                (205.into(), 1),
                (215.into(), 1),
                (305.into(), 2),
                (415.into(), 1),
                (545.into(), 2),
                (615.into(), 1)
            ]
        );

        let h2 = History::from_sparse_histogram(v.clone().into_iter());
        let v2: Vec<_> = h2.sparse_histogram().collect();
        assert_eq!(v, v2);
    }

    #[test]
    fn success_observation_mechanism() {
        let mut h = History::new_empty();
        h.set_success_history_len(20);

        assert_eq!(h.n_recent_timeouts(), 0);
        h.add_success(true);
        assert_eq!(h.n_recent_timeouts(), 0);
        h.add_success(false);
        assert_eq!(h.n_recent_timeouts(), 1);
        for _ in 0..200 {
            h.add_success(false);
        }
        assert_eq!(h.n_recent_timeouts(), 20);
        h.add_success(true);
        h.add_success(true);
        h.add_success(true);
        assert_eq!(h.n_recent_timeouts(), 20 - 3);

        h.set_success_history_len(10);
        assert_eq!(h.n_recent_timeouts(), 10 - 3);
    }

    #[test]
    fn xm_calculation() {
        let mut h = History::new_empty();
        assert_eq!(h.estimate_xm(2), None);

        for n in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
            h.add_time(MsecDuration(*n));
        }

        let v = h.n_most_frequent_bins(2);
        assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2)]);
        let est = (305 * 3 + 545 * 2) / 5;
        assert_eq!(h.estimate_xm(2), Some(est));
        assert_eq!(est, 401);
    }

    #[test]
    fn pareto_estimate() {
        let mut h = History::new_empty();
        assert!(h.pareto_estimate(2).is_none());

        for n in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
            h.add_time(MsecDuration(*n));
        }
        let expected_log_sum: f64 = [401, 500, 542, 401, 543, 401, 401, 401, 617, 413]
            .iter()
            .map(|x| f64::from(*x).ln())
            .sum();
        let expected_log_xm: f64 = (401_f64).ln() * 10.0;
        let expected_alpha = 10.0 / (expected_log_sum - expected_log_xm);
        let expected_inv_alpha = 1.0 / expected_alpha;

        let p = h.pareto_estimate(2).unwrap();

        // We can't do "eq" with floats, so we'll do "very close".
        assert!((401.0 - p.x_m).abs() < 1.0e-9);
        assert!((expected_inv_alpha - p.inv_alpha).abs() < 1.0e-9);

        let q60 = p.quantile(0.60);
        let q99 = p.quantile(0.99);

        assert!((q60 - 451.127) < 0.001);
        assert!((q99 - 724.841) < 0.001);
    }

    #[test]
    fn pareto_estimate_timeout() {
        let mut est = ParetoTimeoutEstimator::default();

        assert_eq!(
            est.timeouts(&b3()),
            (Duration::from_secs(60), Duration::from_secs(60))
        );
        // Set the parameters up to mimic the situation in
        // `pareto_estimate` above.
        est.p.min_observations = 0;
        est.p.n_modes_for_xm = 2;
        assert_eq!(
            est.timeouts(&b3()),
            (Duration::from_secs(60), Duration::from_secs(60))
        );

        for msec in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
            let d = Duration::from_millis(*msec);
            est.note_hop_completed(2, d, true);
        }

        let t = est.timeouts(&b3());
        assert_eq!(t.0.as_micros(), 493_169);
        assert_eq!(t.1.as_micros(), 724_841);

        let t2 = est.timeouts(&b3());
        assert_eq!(t2, t);

        let t2 = est.timeouts(&Action::BuildCircuit { length: 4 });
        assert_eq!(t2.0, t.0.mul_f64(10.0 / 6.0));
        assert_eq!(t2.1, t.1.mul_f64(10.0 / 6.0));
    }

    #[test]
    fn pareto_estimate_clear() {
        let mut est = ParetoTimeoutEstimator::default();

        // Set the parameters up to mimic the situation in
        // `pareto_estimate` above.
        let params = NetParameters::from_map(&"cbtmincircs=1 cbtnummodes=2".parse().unwrap());
        est.update_params(&params);

        assert_eq!(est.timeouts(&b3()).0.as_micros(), 60_000_000);
        assert!(est.learning_timeouts());

        for msec in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
            let d = Duration::from_millis(*msec);
            est.note_hop_completed(2, d, true);
        }
        assert_ne!(est.timeouts(&b3()).0.as_micros(), 60_000_000);
        assert!(!est.learning_timeouts());
        assert_eq!(est.history.n_recent_timeouts(), 0);

        // 17 timeouts happen and we're still getting real numbers...
        for _ in 0..18 {
            est.note_circ_timeout(2, Duration::from_secs(2000));
        }
        assert_ne!(est.timeouts(&b3()).0.as_micros(), 60_000_000);

        // ... but 18 means "reset".
        est.note_circ_timeout(2, Duration::from_secs(2000));
        assert_eq!(est.timeouts(&b3()).0.as_micros(), 60_000_000);

        // And if we fail 18 bunch more times, it doubles.
        for _ in 0..20 {
            est.note_circ_timeout(2, Duration::from_secs(2000));
        }
        assert_eq!(est.timeouts(&b3()).0.as_micros(), 120_000_000);
    }

    #[test]
    fn default_params() {
        let p1 = Params::default();
        let p2 = Params::from(&tor_netdir::params::NetParameters::default());
        // discount version of derive(eq)
        assert_eq!(format!("{:?}", p1), format!("{:?}", p2));
    }

    #[test]
    fn state_conversion() {
        // We have tests elsewhere for converting to and from
        // histograms, so all we really need to ddo here is make sure
        // that the histogram conversion happens.

        let mut est = ParetoTimeoutEstimator::default();
        let mut rng = testing_rng();
        for _ in 0..1000 {
            let d = Duration::from_millis(rng.gen_range_checked(10..3_000).unwrap());
            est.note_hop_completed(2, d, true);
        }

        let state = est.build_state().unwrap();
        assert_eq!(state.version, 1);
        assert!(state.current_timeout.is_some());

        let mut est2 = ParetoTimeoutEstimator::from_state(state);
        let act = Action::BuildCircuit { length: 3 };
        // This isn't going to be exact, since we're recording histogram bins
        // instead of exact timeouts.
        let ms1 = est.timeouts(&act).0.as_millis() as i32;
        let ms2 = est2.timeouts(&act).0.as_millis() as i32;
        assert!((ms1 - ms2).abs() < 50);
    }

    // TODO: add tests from Tor.
}
