//! Tools and types for reporting declared clock skew.

use std::time::{Duration, SystemTime};

/// A reported amount of clock skew from a relay or other source.
///
/// Note that this information may not be accurate or trustworthy: the relay
/// could be wrong, or lying.
///
/// The skews reported here are _minimum_ amounts; the actual skew may
/// be a little higher, depending on latency.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
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
        /// We treat clock skew as "zero" if it less than this long.
        ///
        /// (Since the relay only reports its time to the nearest second, we
        /// can't reasonably infer that differences less than this much reflect
        /// accurate differences in our clocks.)
        const MIN: Duration = Duration::from_secs(2);

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

    /// Return this value if it is greater than `min`; otherwise return None.
    pub fn if_above(self, min: Duration) -> Self {
        match self {
            ClockSkew::Slow(d) if d > min => ClockSkew::Slow(d),
            ClockSkew::Fast(d) if d > min => ClockSkew::Fast(d),
            _ => ClockSkew::None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
}
