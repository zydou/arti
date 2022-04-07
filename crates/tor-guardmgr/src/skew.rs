//! Code for creating and manipulating observations about clock skew.

use std::time::{Duration, Instant};

use tor_proto::ClockSkew;

/// A single observation related to reported clock skew.
#[derive(Debug, Clone)]
#[allow(dead_code)] //XXXX Nothing reads these yet.
pub(crate) struct SkewObservation {
    /// The reported clock skew
    pub(crate) skew: ClockSkew,
    /// The time when we added this observation.
    pub(crate) when: Instant,
}

impl SkewObservation {
    /// Return true if this observation has been made more recently than
    /// `cutoff`.
    pub(crate) fn more_recent_than(&self, cutoff: Instant) -> bool {
        self.when > cutoff
    }
}

/// An estimate of how skewed our clock is, plus a summary of why we think so.
//
// XXXX This is a placeholder for now.
#[derive(Clone, Debug)]
pub struct SkewEstimate {
    /// Our best guess for the magnitude of the skew.
    estimate: ClockSkew,
    /// The number of observations leading to this estimate.
    n_observations: usize,
}

impl std::fmt::Display for SkewEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use humantime::format_duration;
        match self.estimate {
            ClockSkew::Slow(d) => write!(f, "slow by {}", format_duration(d)),
            ClockSkew::None => write!(f, "not skewed"),
            ClockSkew::Fast(d) => write!(f, "fast by {}", format_duration(d)),
        }?;

        write!(f, " (based on {} recent observations)", self.n_observations)
    }
}

impl SkewEstimate {
    /// Return our best estimate for the current clock skew.
    pub fn skew(&self) -> ClockSkew {
        self.estimate
    }

    /// Compute an estimate of how skewed we think our clock is, based on the
    /// reports in `skews`.
    pub(crate) fn estimate_skew<'a>(
        skews: impl Iterator<Item = &'a SkewObservation>,
        now: Instant,
    ) -> Option<Self> {
        // Only consider skew observations reported at least this recently.
        let cutoff = now - Duration::from_secs(3600);

        // Don't believe observations unless we have at least this many. (This
        // value is chosen somewhat arbitrarily.)
        //
        // Note that under normal client operation, we won't connect to this
        // many guards or fallbacks.  That's fine: clock skew is only a problem
        // when it keeps us from bootstrapping, and when we are having
        // bootstrapping problems, we _will_ connect to many guards or
        // fallbacks.
        let min_observations = 8;

        let mut skews: Vec<_> = skews
            .filter_map(|obs| obs.more_recent_than(cutoff).then(|| obs.skew))
            .collect();
        let n_observations = skews.len();
        if n_observations < min_observations {
            return None;
        }

        let (_, median, _) = skews.select_nth_unstable(n_observations / 2);
        // TODO: Consider the quartiles as well, as a rough estimate of confidence.
        Some(SkewEstimate {
            estimate: *median,
            n_observations,
        })
    }
}
