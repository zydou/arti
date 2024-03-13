//! Tools and types for reporting declared clock skew.

use std::time::{Duration, SystemTime};

/// A reported amount of clock skew from a relay or other source.
///
/// Note that this information may not be accurate or trustworthy: the relay
/// could be wrong, or lying.
///
/// The skews reported here are _minimum_ amounts; the actual skew may
/// be a little higher, depending on latency.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)]
pub enum ClockSkew {
    /// Our own clock is "running slow": the relay's clock is at least this far
    /// ahead of ours.
    Slow(Duration),
    /// Our own clock is not necessarily inconsistent with the relay's clock.
    None,
    /// Own own clock is "running fast": the relay's clock is at least this far
    /// behind ours.
    Fast(Duration),
}

/// We treat clock skew as "zero" if it less than this long.
///
/// (Since the relay only reports its time to the nearest second, we
/// can't reasonably infer that differences less than this much reflect
/// accurate differences in our clocks.)
const MIN: Duration = Duration::from_secs(2);

impl ClockSkew {
    /// Construct a ClockSkew from a set of channel handshake timestamps.
    ///
    /// Requires that `ours_at_start` is the timestamp at the point when we
    /// started the handshake, `theirs` is the timestamp the relay reported in
    /// its NETINFO cell, and `delay` is the total amount of time between when
    /// we started the handshake and when we received the NETINFO cell.
    pub(crate) fn from_handshake_timestamps(
        ours_at_start: SystemTime,
        theirs: SystemTime,
        delay: Duration,
    ) -> Self {
        // The relay may have generated its own timestamp any time between when
        // we sent the handshake, and when we got the reply.  Therefore, at the
        // time we started, it was between these values.
        let theirs_at_start_min = theirs - delay;
        let theirs_at_start_max = theirs;

        if let Ok(skew) = theirs_at_start_min.duration_since(ours_at_start) {
            ClockSkew::Slow(skew).if_above(MIN)
        } else if let Ok(skew) = ours_at_start.duration_since(theirs_at_start_max) {
            ClockSkew::Fast(skew).if_above(MIN)
        } else {
            // Either there is no clock skew, or we can't detect any.
            ClockSkew::None
        }
    }

    /// Return the magnitude of this clock skew.
    pub fn magnitude(&self) -> Duration {
        match self {
            ClockSkew::Slow(d) => *d,
            ClockSkew::None => Duration::from_secs(0),
            ClockSkew::Fast(d) => *d,
        }
    }

    /// Return this clock skew as a signed number of seconds, with slow values
    /// treated as negative and fast values treated as positive.
    pub fn as_secs_f64(&self) -> f64 {
        match self {
            ClockSkew::Slow(d) => -d.as_secs_f64(),
            ClockSkew::None => 0.0,
            ClockSkew::Fast(d) => d.as_secs_f64(),
        }
    }

    /// Return a clock skew computed from a signed number of seconds.
    ///
    /// Returns None if the value is degenerate.
    pub fn from_secs_f64(seconds: f64) -> Option<Self> {
        use std::num::FpCategory;
        let max_seconds = Duration::MAX.as_secs_f64();

        // I dislike working with floating point, and I dislike the current lack
        // of Duration::try_from_secs_f64() in stable Rust.  Look what they made
        // me do!
        match seconds.classify() {
            FpCategory::Nan => None,
            FpCategory::Zero | FpCategory::Subnormal => Some(ClockSkew::None),
            FpCategory::Normal | FpCategory::Infinite => Some(if seconds <= -max_seconds {
                ClockSkew::Slow(Duration::MAX)
            } else if seconds < 0.0 {
                ClockSkew::Slow(Duration::from_secs_f64(-seconds)).if_above(MIN)
            } else if seconds < max_seconds {
                ClockSkew::Fast(Duration::from_secs_f64(seconds)).if_above(MIN)
            } else {
                ClockSkew::Fast(Duration::MAX)
            }),
        }
    }

    /// Return this value if it is greater than `min`; otherwise return None.
    pub fn if_above(self, min: Duration) -> Self {
        if self.magnitude() > min {
            self
        } else {
            ClockSkew::None
        }
    }

    /// Return true if we're estimating any skew.
    pub fn is_skewed(&self) -> bool {
        !matches!(self, ClockSkew::None)
    }
}

impl Ord for ClockSkew {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        use ClockSkew::*;
        match (self, other) {
            // This is the reason we need to define this ordering rather than
            // deriving it: we want clock skews to sort by their signed distance
            // from the current time.
            (Slow(a), Slow(b)) => a.cmp(b).reverse(),
            (Slow(_), _) => Less,

            (None, None) => Equal,
            (None, Slow(_)) => Greater,
            (None, Fast(_)) => Less,

            (Fast(a), Fast(b)) => a.cmp(b),
            (Fast(_), _) => Greater,
        }
    }
}

impl PartialOrd for ClockSkew {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn make_skew() {
        let now = SystemTime::now();
        let later = now + Duration::from_secs(777);
        let earlier = now - Duration::from_secs(333);
        let window = Duration::from_secs(30);

        // Case 1: they say our clock is slow.
        let skew = ClockSkew::from_handshake_timestamps(now, later, window);
        // The window is only subtracted in this case, since we're reporting the _minimum_ skew.
        assert_eq!(skew, ClockSkew::Slow(Duration::from_secs(747)));

        // Case 2: they say our clock is fast.
        let skew = ClockSkew::from_handshake_timestamps(now, earlier, window);
        assert_eq!(skew, ClockSkew::Fast(Duration::from_secs(333)));

        // Case 3: The variation in our clock is less than the time window it took them to answer.
        let skew = ClockSkew::from_handshake_timestamps(now, now + Duration::from_secs(20), window);
        assert_eq!(skew, ClockSkew::None);

        // Case 4: The variation in our clock is less than the limits of the timer precision.
        let skew = ClockSkew::from_handshake_timestamps(
            now,
            now + Duration::from_millis(500),
            Duration::from_secs(0),
        );
        assert_eq!(skew, ClockSkew::None);
    }

    #[test]
    fn from_f64() {
        use ClockSkew as CS;
        use Duration as D;

        assert_eq!(CS::from_secs_f64(0.0), Some(CS::None));
        assert_eq!(CS::from_secs_f64(f64::MIN_POSITIVE / 2.0), Some(CS::None)); // subnormal
        assert_eq!(CS::from_secs_f64(1.0), Some(CS::None));
        assert_eq!(CS::from_secs_f64(-1.0), Some(CS::None));
        assert_eq!(CS::from_secs_f64(3.0), Some(CS::Fast(D::from_secs(3))));
        assert_eq!(CS::from_secs_f64(-3.0), Some(CS::Slow(D::from_secs(3))));

        assert_eq!(CS::from_secs_f64(1.0e100), Some(CS::Fast(D::MAX)));
        assert_eq!(CS::from_secs_f64(-1.0e100), Some(CS::Slow(D::MAX)));

        assert_eq!(CS::from_secs_f64(f64::NAN), None);
        assert_eq!(CS::from_secs_f64(f64::INFINITY), Some(CS::Fast(D::MAX)));
        assert_eq!(CS::from_secs_f64(f64::NEG_INFINITY), Some(CS::Slow(D::MAX)));
    }

    #[test]
    fn order() {
        use rand::seq::SliceRandom as _;
        use ClockSkew as CS;
        let sorted: Vec<ClockSkew> = vec![-10.0, -5.0, 0.0, 0.0, 10.0, 20.0]
            .into_iter()
            .map(|n| CS::from_secs_f64(n).unwrap())
            .collect();

        let mut rng = testing_rng();
        let mut v = sorted.clone();
        for _ in 0..100 {
            v.shuffle(&mut rng);
            v.sort();
            assert_eq!(v, sorted);
        }
    }
}
