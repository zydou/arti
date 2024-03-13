//! Round Trip Time measurement (§ 2.1)

use crate::err::Error;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tor_netdir::params::NetParameters;
use tor_units::Percentage;

/// Perform rounded integer division, in line with what C tor does (`round()` in the spec).
fn round_div(dividend: u64, divisor: u64) -> u64 {
    (dividend + divisor / 2) / divisor
}

/// The subset of `NetParameters` required for RTT estimation, after type conversion.
struct RttParameters {
    /// The minimum number of SENDME acks required to estimate RTT and/or bandwidth.
    // FIXME(eta): We don't actually use this any more after some C-tor changes. Should it just go
    //             away entirely??
    #[allow(dead_code)]
    min_sendme_acks: usize,
    /// The "N" parameter in N-EWMA smoothing of RTT and/or bandwidth estimation, specified as a
    /// percentage of the number of SENDME acks in a congestion window.
    ///
    /// A percentage over 100% indicates smoothing with more than one congestion window's worth
    /// of SENDMEs.
    ewma_n_by_sendme_acks: Percentage<u32>,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation.
    ewma_n_max: u64,
    /// How many cells a SENDME acks under the congestion-control regime.
    sendme_cell_ack_count: u64,
    /// How often we update our congestion window, per congestion window worth of packets.
    /// (For example, if this is 2, we will update the window twice every window.)
    cwnd_inc_rate: u64,
}

impl<'a> From<&'a NetParameters> for RttParameters {
    fn from(params: &'a NetParameters) -> Self {
        Self {
            min_sendme_acks: usize::try_from(params.cc_min_sendme_acks.get())
                .expect("cc_min_sendme_acks outside bounds"),
            ewma_n_by_sendme_acks: Percentage::new(
                u32::try_from(params.cc_ewma_n_by_sendme_acks.as_percent().get())
                    .expect("cc_ewma_n_by_sendme_acks outside bounds"),
            ),
            ewma_n_max: u64::try_from(params.cc_ewma_n_max.get())
                .expect("cc_ewma_n_max outside bounds"),
            sendme_cell_ack_count: u64::try_from(params.cc_sendme_cell_ack_count.get())
                .expect("cc_sendme_cell_ack_count outside bounds"),
            cwnd_inc_rate: u64::try_from(params.cc_cwnd_inc_rate.get())
                .expect("cc_cwnd_inc_rate outside bounds"),
        }
    }
}

/// Provides an estimate of the round-trip time (RTT) of a Tor circuit.
pub struct RoundtripTimeEstimator {
    /// A queue of times we sent a cell that we'd expect a SENDME for.
    sendme_expected_from: VecDeque<Instant>,
    /// The last *measured* round-trip time.
    last_rtt: Duration,
    /// The current smoothed *estimate* of what the round-trip time is.
    ///
    /// This is zero iff we have not managed to get any estimate yet.
    ewma_rtt: Duration,
    /// The minimum observed value of `last_rtt`.
    min_rtt: Duration,
    /// The maximum observed value of `last_rtt`.
    max_rtt: Duration,
    /// The number of values we've measured so far.
    measured: usize,
    /// The network parameters we're using.
    params: RttParameters,
    /// Whether or not we're in slow start mode.
    in_slow_start: bool,
    /// A reference to a shared boolean for storing clock stall data.
    clock_stalled: Arc<AtomicBool>,
}

impl RoundtripTimeEstimator {
    /// Create a new `RoundtripTimeEstimator`, using a set of `NetParameters` and a shared boolean
    /// to cache clock stalled state in.
    pub fn new(params: &NetParameters, clock_stalled: Arc<AtomicBool>) -> Self {
        Self {
            sendme_expected_from: Default::default(),
            last_rtt: Default::default(),
            ewma_rtt: Default::default(),
            min_rtt: Duration::MAX,
            max_rtt: Default::default(),
            measured: 0,
            params: params.into(),
            in_slow_start: true,
            clock_stalled,
        }
    }

    /// Inform the estimator that we did (at time `now) something that we'll expect a SENDME to
    /// be received for.
    pub fn expect_sendme(&mut self, now: Instant) {
        self.sendme_expected_from.push_back(now);
    }

    /// Inform the estimator that we've exited slow start mode.
    pub fn exit_slow_start(&mut self) {
        self.in_slow_start = false;
    }

    /// Reenter slow start mode (used in tests).
    #[cfg(test)]
    pub(crate) fn enter_slow_start(&mut self) {
        self.in_slow_start = true;
    }

    /// Return whether we can use heuristics to sanity-check RTT values against our EWMA value.
    fn can_crosscheck_with_current_estimate(&self) -> bool {
        if self.in_slow_start {
            // If we're in slow start, we don't perform any sanity checks, as per spec.
            return false;
        }

        if self.ewma_rtt.is_zero() {
            // If we don't have a current estimate, we can't use it for sanity checking, because
            // it doesn't exist.
            return false;
        }

        // If we've gotten here, we have a RTT estimate that's sane enough to check against.
        true
    }

    /// Given a raw RTT value we just observed, compute whether or not we think the clock has
    /// stalled or jumped, and we should throw it out as a result.
    fn is_clock_stalled(&self, raw_rtt: Duration) -> bool {
        if raw_rtt.is_zero() {
            // Clock is stalled.
            self.clock_stalled.store(true, Ordering::SeqCst);
            true
        } else if self.can_crosscheck_with_current_estimate() {
            // If we have enough data, check the sanity of our measurement against our EWMA value.
            if raw_rtt > self.ewma_rtt * 5000 {
                // The clock significantly jumped forward.
                //
                // Don't update the global cache, though, since this is triggerable over the
                // network.
                //
                // FIXME(eta): We should probably log something here?
                true
            } else if self.ewma_rtt > raw_rtt * 5000 {
                // The clock might have stalled. We can't really make a decision just off this
                // one measurement, though, so we'll use the stored stall value.
                self.clock_stalled.load(Ordering::SeqCst)
            } else {
                // If we got here, we're not stalled.
                self.clock_stalled.store(false, Ordering::SeqCst);
                false
            }
        } else {
            // If we don't have enough measurements to sanity check, assume it's okay.
            false
        }
    }

    /// Inform the estimator that we received a SENDME at time `now`, with the congestion window
    /// at `cwnd`.
    ///
    /// # Errors
    ///
    /// Returns an error if you didn't call `expect_sendme` first.
    pub fn sendme_received(&mut self, now: Instant, cwnd: u64) -> crate::Result<()> {
        let expected_at = self
            .sendme_expected_from
            .pop_front()
            .ok_or(Error::MismatchedEstimationCall)?;
        let raw_rtt = now.saturating_duration_since(expected_at);

        if self.is_clock_stalled(raw_rtt) {
            return Ok(());
        }

        if raw_rtt < self.min_rtt {
            self.min_rtt = raw_rtt;
        }
        if raw_rtt > self.max_rtt {
            self.max_rtt = raw_rtt;
        }
        self.measured += 1;
        self.last_rtt = raw_rtt;

        // The following formulae come from prop#324 § 2.1.2. Good luck.
        let cwnd_update_rate = if self.in_slow_start {
            round_div(cwnd, self.params.sendme_cell_ack_count)
        } else {
            round_div(
                cwnd,
                self.params.sendme_cell_ack_count * self.params.cwnd_inc_rate,
            )
        };

        // This is the "N" for N-EWMA.
        let ewma_n = max(
            min(
                (cwnd_update_rate * u64::from(self.params.ewma_n_by_sendme_acks.as_percent()))
                    / 100,
                self.params.ewma_n_max,
            ),
            2,
        );

        // FIXME(eta): This briefly goes via 128-bit integers, which aren't very fast.
        let raw_rtt_nsec: u64 = match raw_rtt.as_nanos().try_into() {
            Ok(v) => v,
            Err(_) => {
                // FIXME(eta): Uh oh, an integer overflow. I *guess* we should treat this
                //             as if the clock stalled or jumped, since that's what's probably
                //             going to cause this, and return early?
                return Ok(());
            }
        };
        // this one shouldn't overflow given it was created by this function previously
        let prev_rtt_nsec = self.ewma_rtt.as_nanos() as u64;

        // This is the actual EWMA calculation.
        // C-tor simplifies this as follows for rounding error reasons:
        //
        // EWMA = value*2/(N+1) + EMA_prev*(N-1)/(N+1)
        //      = (value*2 + EWMA_prev*(N-1))/(N+1)
        //
        // This calculation method is from (what is at the time of writing):
        //    https://gitlab.torproject.org/tpo/core/torspec/-/merge_requests/83
        let raw_rtt_nsec = if prev_rtt_nsec == 0 {
            raw_rtt_nsec
        } else {
            // (raw_rtt_nsec * 2) / (ewma_n + 1) + prev_rtt_nsec * (ewma_n - 1) / (ewma_n + 1)
            ((raw_rtt_nsec * 2) + ((ewma_n - 1) * prev_rtt_nsec)) / (ewma_n + 1)
        };

        self.ewma_rtt = Duration::from_nanos(raw_rtt_nsec);
        Ok(())
    }

    /// Get the current RTT estimate.
    pub fn estimate_rtt(&self) -> Duration {
        self.ewma_rtt
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::print_stderr)]
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
    use crate::rtt::RoundtripTimeEstimator;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tor_netdir::params::NetParameters;

    // Congestion window to use for tests.
    const CWND: u64 = 4 * 31;

    fn make_estimator() -> (RoundtripTimeEstimator, Arc<AtomicBool>) {
        let clock_stalled = Arc::new(AtomicBool::new(false));
        let params = NetParameters::default();
        (
            RoundtripTimeEstimator::new(&params, clock_stalled.clone()),
            clock_stalled,
        )
    }

    #[derive(Debug)]
    struct ClockTestSample {
        old_delta_in_nsec: u64,
        new_delta_in_nsec: u64,
        slow_start_in: bool,
        clock_stalled_out: bool,
        result_out: bool,
    }

    impl From<[u64; 5]> for ClockTestSample {
        fn from(arr: [u64; 5]) -> Self {
            Self {
                old_delta_in_nsec: arr[0],
                new_delta_in_nsec: arr[1],
                slow_start_in: arr[2] == 1,
                clock_stalled_out: arr[3] == 1,
                result_out: arr[4] == 1,
            }
        }
    }

    impl ClockTestSample {
        fn test(&self, estimator: &mut RoundtripTimeEstimator, stalled: &AtomicBool) {
            let raw_rtt = Duration::from_nanos(self.new_delta_in_nsec);
            if self.slow_start_in {
                estimator.enter_slow_start();
            } else {
                estimator.exit_slow_start();
            }
            estimator.ewma_rtt = Duration::from_nanos(self.old_delta_in_nsec);

            assert_eq!(estimator.is_clock_stalled(raw_rtt), self.result_out);
            assert_eq!(stalled.load(Ordering::SeqCst), self.clock_stalled_out);
        }
    }

    #[derive(Debug)]
    struct RttTestSample {
        sent_nsec: u64,
        sendme_received_nsec: u64,
        last_rtt_out_nsec: u64,
        ewma_rtt_out_nsec: u64,
        min_rtt_out_nsec: u64,
    }

    impl From<[u64; 5]> for RttTestSample {
        fn from(arr: [u64; 5]) -> Self {
            Self {
                sent_nsec: arr[0],
                sendme_received_nsec: arr[1],
                last_rtt_out_nsec: arr[2],
                ewma_rtt_out_nsec: arr[3],
                min_rtt_out_nsec: arr[4],
            }
        }
    }

    impl RttTestSample {
        fn test(&self, estimator: &mut RoundtripTimeEstimator, start: Instant) {
            let sent = start + Duration::from_nanos(self.sent_nsec);
            let sendme_received = start + Duration::from_nanos(self.sendme_received_nsec);
            estimator.expect_sendme(sent);
            estimator.sendme_received(sendme_received, CWND).unwrap();

            assert_eq!(
                estimator.last_rtt,
                Duration::from_nanos(self.last_rtt_out_nsec)
            );
            assert_eq!(
                estimator.estimate_rtt(),
                Duration::from_nanos(self.ewma_rtt_out_nsec)
            );
            assert_eq!(
                estimator.min_rtt,
                Duration::from_nanos(self.min_rtt_out_nsec)
            );
        }
    }

    #[test]
    fn clock_skew_test_vectors() {
        let (mut estimator, stalled) = make_estimator();

        // from C-tor src/test/test_congestion_control.c
        // (unmerged MR branch https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/578)
        // retrieved 2022-08-09 commitid a1735ac9c3e0ea435d21fac020744c0aa16688f1
        let vectors = [
            [0, 1, 1, 0, 0],    // old delta 0, slow start -> false
            [0, 0, 1, 1, 1],    // New delta 0 -> cache true, return true
            [1, 1, 1, 1, 0],    // In slow start -> keep cache, but return false
            [1, 4999, 0, 0, 0], // Not slow start, edge -> update cache, and false
            [4999, 1, 0, 0, 0], // Not slow start, other edge -> false
            [5001, 1, 0, 0, 0], // Not slow start w/ -5000x -> use cache (false)
            [5001, 0, 0, 1, 1], // New delta 0 -> cache true, return true
            [5001, 1, 0, 1, 1], // Not slow start w/ -5000x -> use cache (true)
            [5001, 1, 1, 1, 0], // In slow start w/ -5000x -> false
            [0, 5001, 0, 1, 0], // Not slow start w/ no EWMA -> false
            [1, 5001, 1, 1, 0], // In slow start w/ +5000x -> false
            [1, 1, 0, 0, 0],    // Not slow start -> update cache to false
            [5001, 1, 0, 0, 0], // Not slow start w/ -5000x -> use cache (false)
            [1, 5001, 0, 0, 1], // Not slow start w/ +5000x -> true
            [0, 5001, 0, 0, 0], // Not slow start w/ no EWMA -> false
            [5001, 1, 1, 0, 0], // In slow start w/ -5000x change -> false
            [1, 1, 0, 0, 0],    // Not slow start -> false
        ];
        for vect in vectors {
            let vect = ClockTestSample::from(vect);
            eprintln!("testing {:?}", vect);
            vect.test(&mut estimator, &stalled);
        }
    }

    // TODO RTT: this test is disabled for now because it does not work on
    // platforms where the granularity of Duration is greater than 1 nanosecond.
    //
    // See #574 for more information.
    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore)]
    fn rtt_test_vectors() {
        let (mut estimator, _) = make_estimator();
        let now = Instant::now();

        // from C-tor src/test/test_congestion_control.c
        let vectors = [
            [100_u64, 200, 100, 100, 100],
            [200, 300, 100, 100, 100],
            [350, 500, 150, 133, 100],
            [500, 550, 50, 77, 50],
            [600, 700, 100, 92, 50],
        ];
        for vect in vectors {
            let vect = RttTestSample::from(vect);
            eprintln!("testing {:?}", vect);
            vect.test(&mut estimator, now);
        }
    }
}
