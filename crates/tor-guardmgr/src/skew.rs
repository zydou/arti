//! Code for creating and manipulating observations about clock skew.

// TODO:
//   - See if we can safely report a "no-confidence" value with even fewer
//     observations than we currently collect.
//   - If the universe of fallbacks and/or the guard sample size and/or the list
//     of bridges is very small, see if we can still use that to make a
//     low-confidence value.

use std::time::{Duration, Instant};

use tor_proto::ClockSkew;

/// A single observation related to reported clock skew.
#[derive(Debug, Clone)]
pub(crate) struct SkewObservation {
    /// The reported clock skew
    pub(crate) skew: ClockSkew,
    /// The time when we added this observation.
    pub(crate) when: Instant,
}

impl SkewObservation {
    /// Return true if this observation has been made more recently than
    /// `cutoff`. If cutoff is None, consider it's very far in the past.
    pub(crate) fn more_recent_than(&self, cutoff: Option<Instant>) -> bool {
        cutoff.map_or(true, |cutoff| self.when > cutoff)
    }
}

/// An estimate of how skewed our clock is, plus a summary of why we think so.
//
// SEMVER NOTE: this type is re-exported from tor-circmgr.
#[derive(Clone, Debug)]
pub struct SkewEstimate {
    /// Our best guess for the magnitude of the skew.
    estimate: ClockSkew,
    /// The number of observations leading to this estimate.
    n_observations: usize,
    /// A description of how confident we are.
    confidence: Confidence,
}

/// Subjective description of how sure we are that our clock is/isn't skewed.
#[derive(Clone, Debug)]
enum Confidence {
    /// We aren't very sure about our estimate.
    None,
    /// It seems plausible that our clock is skewed
    Low,
    /// We are pretty confident that our clock is skewed.
    High,
}

/// How bad does clock skew need to be before we'll tell the user that it's a
/// problem?
const SIGNIFICANCE_THRESHOLD: Duration = Duration::from_secs(15 * 60);

impl std::fmt::Display for SkewEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Format the whole-second part of `d`.
        ///
        /// We don't care about fractions here, since skew only mattes if it's
        /// on the order of many minutes.
        fn fmt_secs(d: Duration) -> humantime::FormattedDuration {
            humantime::format_duration(Duration::from_secs(d.as_secs()))
        }

        match self.estimate {
            ClockSkew::Slow(d) => write!(f, "slow by around {}", fmt_secs(d)),
            ClockSkew::None => write!(
                f,
                "not skewed by more than {}",
                fmt_secs(SIGNIFICANCE_THRESHOLD)
            ),
            ClockSkew::Fast(d) => write!(f, "fast by around {}", fmt_secs(d)),
        }?;

        let confidence = match self.confidence {
            Confidence::None => "very little confidence",
            Confidence::Low => "some confidence",
            Confidence::High => "high confidence",
        };

        write!(
            f,
            " (based on {} recent observations, with {})",
            self.n_observations, confidence
        )
    }
}

impl SkewEstimate {
    /// Return our best estimate for the current clock skew.
    pub fn skew(&self) -> ClockSkew {
        self.estimate
    }

    /// Return true if this estimate is worth telling the user about.
    pub fn noteworthy(&self) -> bool {
        !matches!(self.estimate, ClockSkew::None) && !matches!(self.confidence, Confidence::None)
    }

    /// Compute an estimate of how skewed we think our clock is, based on the
    /// reports in `skews`.
    pub(crate) fn estimate_skew<'a>(
        skews: impl Iterator<Item = &'a SkewObservation>,
        now: Instant,
    ) -> Option<Self> {
        // Only consider skew observations reported at least this recently.
        let cutoff = now.checked_sub(Duration::from_secs(3600));

        // Don't even look at our observations unless we  have at least this
        // many. (This value is chosen somewhat arbitrarily.)
        //
        // Note that under normal client operation, we won't connect to this
        // many guards or fallbacks.  That's fine: clock skew is only a problem
        // when it keeps us from bootstrapping, and when we are having
        // bootstrapping problems, we _will_ connect to many guards or
        // fallbacks.
        let min_observations = 8;

        let skews: Vec<_> = skews
            .filter_map(|obs| obs.more_recent_than(cutoff).then_some(obs.skew))
            .collect();
        if skews.len() < min_observations {
            return None;
        }

        // Throw away all the members of `skews` that are too eccentric, and
        // convert the rest to f64s.
        let skews: Vec<f64> = discard_outliers(skews);
        let n_observations = skews.len();
        debug_assert!(n_observations >= 3);

        // Use the mean of the remaining observations to determine our estimate.
        let (mean, standard_deviation) = mean_and_standard_deviation(&skews[..]);
        let estimate = ClockSkew::from_secs_f64(mean)
            .expect("Somehow generated NaN clock skew‽")
            .if_above(SIGNIFICANCE_THRESHOLD);

        // Use the standard deviation to determine how confident we should be in
        // our estimate.
        //
        // TODO: probably we should be using a real statistical test instead,
        // but that seems like overkill.
        let confidence = if standard_deviation < 1.0 {
            // Avoid divide-by-zero below: if the standard deviation is less
            // than 1 second then the mean is probably right.
            Confidence::High
        } else {
            let distance = if estimate.is_skewed() {
                // If we're saying that we are skewed, look at how many standard
                // deviations we are from zero.
                estimate.magnitude().as_secs_f64() / standard_deviation
            } else {
                // If we're saying that we're not skewed, look at how many
                // standard deviations zero is from "skewed".
                SIGNIFICANCE_THRESHOLD.as_secs_f64() / standard_deviation
            };
            if distance >= 3.0 {
                Confidence::High
            } else if distance >= 2.0 {
                Confidence::Low
            } else {
                Confidence::None
            }
        };

        Some(SkewEstimate {
            estimate: estimate.if_above(SIGNIFICANCE_THRESHOLD),
            n_observations,
            confidence,
        })
    }
}

/// Remove all outliers from `values`, and convert the resulting times into
/// `f64`s.
///
/// We guarantee that no more than 1/2 of the input will be discarded.
///
/// # Panics
///
/// Panics if values is empty.
fn discard_outliers(mut values: Vec<ClockSkew>) -> Vec<f64> {
    // Compute the quartiles  of our observations.
    let (q1, q3) = {
        let n = values.len();
        let (low, _median, high) = values.select_nth_unstable(n / 2);
        let n_low = low.len();
        let n_high = high.len();
        debug_assert!(n_low >= 1);
        debug_assert!(n_high >= 1);
        let (_, q1, _) = low.select_nth_unstable(n_low / 2);
        let (_, q3, _) = high.select_nth_unstable(n_high / 2);

        (q1, q3)
    };

    // Compute the inter-quartile range (IQR) and use this to discard outliers.
    //
    // (Define IRQ = Q3-Q1. We'll allow all values that are no more than 1.5 IQR
    // outside the quartiles.)
    let iqr = (q1.as_secs_f64() - q3.as_secs_f64()).abs();
    let permissible_range = (q1.as_secs_f64() - iqr * 1.5)..=(q3.as_secs_f64() + iqr * 1.5);
    values
        .into_iter()
        .filter_map(|skew| Some(skew.as_secs_f64()).filter(|v| permissible_range.contains(v)))
        .collect()
}

/// Compute and return the mean and standard deviation of `values`.
///
/// Returns `(Nan,Nan)` if `values` is empty.
fn mean_and_standard_deviation(values: &[f64]) -> (f64, f64) {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values
        .iter()
        .map(|v| {
            let diff = v - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;

    (mean, variance.sqrt())
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
    use float_eq::assert_float_eq;

    /// Tolerance for float comparison.
    const TOL: f64 = 0.00001;

    #[test]
    fn mean_stddev() {
        // This case is trivial.
        let a = [17.0];
        let (m, s) = mean_and_standard_deviation(&a[..]);
        assert_float_eq!(m, 17.0, abs <= TOL);
        assert_float_eq!(s, 0.0, abs <= TOL);

        // Computed these by hand using a calculator.
        let a = [1.0, 2.0, 3.0, 4.0];
        let (m, s) = mean_and_standard_deviation(&a[..]);
        assert_float_eq!(m, 2.5, abs <= TOL);
        assert_float_eq!(s, 1.11803398, abs <= TOL);

        // Generated these using numpy from normal distribution with stddev=1,
        // mean=0.
        let a = [
            1.34528777,
            0.17855632,
            -0.08147599,
            0.14845672,
            0.6838537,
            -1.59034826,
            0.06777352,
            -2.42469117,
            -0.12017179,
            0.47098959,
        ];
        let (m, s) = mean_and_standard_deviation(&a[..]);
        assert_float_eq!(m, -0.132176959, abs <= TOL);
        assert_float_eq!(s, 1.0398321132, abs <= TOL);
    }

    #[test]
    fn outliers() {
        use ClockSkew::{Fast, Slow};
        let hour = Duration::from_secs(3600);
        // median will be 0. quartiles will ± 2 hours.  That makes
        // the IQR 4 hours, so nothing will be discarded.
        let a = vec![
            Slow(hour * 3),
            Slow(hour * 2),
            Slow(hour),
            ClockSkew::None,
            Fast(hour),
            Fast(hour * 2),
            Fast(hour * 3),
        ];
        let mut b = discard_outliers(a.clone());
        b.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(b.len(), 7);
        for (ai, bi) in a.iter().zip(b.iter()) {
            assert_float_eq!(ai.as_secs_f64(), bi, abs <= TOL);
        }

        // Now try with a case that does have some outliers. This time, the IQR
        // will be 1 hour, so the first and last times will be discarded as
        // outliers.
        let a = vec![
            Slow(hour * 4),
            Slow(hour / 2),
            Slow(hour / 3),
            ClockSkew::None,
            Fast(hour / 3),
            Fast(hour / 2),
            Fast(hour * 4),
        ];
        let mut b = discard_outliers(a.clone());
        b.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(b.len(), 5);
        for (ai, bi) in a[1..=5].iter().zip(b.iter()) {
            assert_float_eq!(ai.as_secs_f64(), bi, abs <= TOL);
        }
    }

    #[test]
    fn estimate_with_no_data() {
        // zero inputs -> output is none.
        let now = Instant::now();
        let est = SkewEstimate::estimate_skew([].iter(), now);
        assert!(est.is_none());

        // Same with fewer than min_observations.
        let year = Duration::from_secs(365 * 24 * 60 * 60);
        let obs = vec![
            SkewObservation {
                skew: ClockSkew::Fast(year),
                when: now
            };
            5
        ];
        let est = SkewEstimate::estimate_skew(obs.iter(), now);
        assert!(est.is_none());

        // Same with many observations all of which are obsolete.
        //
        // (advance the clock: not all Instant implementations let you go back a long time
        // before startup.)
        let now = now + year;
        let obs = vec![
            SkewObservation {
                skew: ClockSkew::Fast(year),
                when: now - year
            };
            100
        ];
        let est = SkewEstimate::estimate_skew(obs.iter(), now);
        assert!(est.is_none());
    }

    /// Construct a vector of SkewObservations from a slice of skew magnitudes
    /// expressed in minutes.
    fn from_minutes(mins: &[f64]) -> Vec<SkewObservation> {
        mins.iter()
            .map(|m| SkewObservation {
                skew: ClockSkew::from_secs_f64(m * 60.0).unwrap(),
                when: Instant::now(),
            })
            .collect()
    }

    #[test]
    fn estimate_skewed() {
        // The quartiles here are -22 and -10.  The IQR is therefore 12, so we
        // won't discard anything.
        //
        // The mean is -17.125: That's more than 15 minutes from zero, so we'll
        // say we're slow.
        //
        // The standard deviation is 7.67: that puts the mean between 2 and 3
        // standard deviations from zero, so we'll say we're skewed with "low"
        // confidence.
        let obs = from_minutes(&[-20.0, -10.0, -20.0, -25.0, 0.0, -18.0, -22.0, -22.0]);

        let est = SkewEstimate::estimate_skew(obs.iter(), Instant::now()).unwrap();
        assert_eq!(
            est.to_string(),
            "slow by around 17m 7s (based on 8 recent observations, with some confidence)"
        );
    }

    #[test]
    fn estimate_not_skewed() {
        // The quartiles here are -2 and 6: IRQ is 8, so we'll discard all the
        // huge values, leaving 8.
        //
        // Mean of the remaining items is 0.75 and standard deviation is 2.62:
        // we'll be pretty sure we're not much skewed.
        let obs = from_minutes(&[
            -100.0, 100.0, -3.0, -2.0, 0.0, 1.0, 0.5, 6.0, 3.0, 0.5, 99.0,
        ]);

        let est = SkewEstimate::estimate_skew(obs.iter(), Instant::now()).unwrap();
        assert_eq!(
            est.to_string(),
            "not skewed by more than 15m (based on 8 recent observations, with high confidence)"
        );
    }
}
