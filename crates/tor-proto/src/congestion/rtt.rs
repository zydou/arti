//! Round Trip Time measurement (§ 2.1)

use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tor_units::Percentage;

use super::params::RoundTripEstimatorParams;
use super::{CongestionWindow, State};

use thiserror::Error;
use tor_error::{ErrorKind, HasKind};

/// An error originating from the tor-congestion crate.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub(crate) enum Error {
    /// A call to `RoundtripTimeEstimator::sendme_received` was made without calling
    /// `RoundtripTimeEstimator::expect_sendme` first.
    #[error("Informed of a SENDME we weren't expecting")]
    MismatchedEstimationCall,
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        match self {
            E::MismatchedEstimationCall => ErrorKind::TorProtocolViolation,
        }
    }
}

/// The subset of `NetParameters` required for RTT estimation, after type conversion.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct RttParameters {
    /// The "N" parameter in N-EWMA smoothing of RTT and/or bandwidth estimation, specified as a
    /// percentage of the number of SENDME acks in a congestion window.
    ///
    /// A percentage over 100% indicates smoothing with more than one congestion window's worth
    /// of SENDMEs.
    ewma_n_by_sendme_acks: Percentage<u32>,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation.
    ewma_n_max: u32,
    /// The maximum value of the "N" parameter in N-EWMA smoothing of RTT and/or bandwidth
    /// estimation in slow start.
    ewma_n_max_ss: u32,
    /// Percentage of the current RTT to use when resetting the minimum RTT for a circuit. (RTT is
    /// reset when the cwnd hits cwnd_min).
    rtt_reset_pct: Percentage<u32>,
}

impl From<&RoundTripEstimatorParams> for RttParameters {
    fn from(p: &RoundTripEstimatorParams) -> Self {
        Self {
            ewma_n_by_sendme_acks: p.ewma_cwnd_pct,
            ewma_n_max: p.ewma_max,
            ewma_n_max_ss: p.ewma_ss_max,
            rtt_reset_pct: p.rtt_reset_pct,
        }
    }
}

/// Provides an estimate of the round-trip time (RTT) of a Tor circuit.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct RoundtripTimeEstimator {
    /// A queue of times we sent a cell that we'd expect a SENDME for.
    ///
    /// When a data cell is sent and for which we expect a SENDME next, the timestamp at the send
    /// is kept in this queue so we can use it to measure the RTT when the SENDME is received.
    ///
    /// A queue is used here because the protocol allows to send all pending SENDMEs at once as
    /// long as it is within one congestion window.
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
    /// The network parameters we're using.
    params: RttParameters,
    /// A reference to a shared boolean for storing clock stall data.
    clock_stalled: AtomicBool,
}

#[allow(dead_code)]
impl RoundtripTimeEstimator {
    /// Create a new `RoundtripTimeEstimator`, using a set of `NetParameters` and a shared boolean
    /// to cache clock stalled state in.
    pub(crate) fn new(params: &RoundTripEstimatorParams) -> Self {
        Self {
            sendme_expected_from: Default::default(),
            last_rtt: Default::default(),
            ewma_rtt: Default::default(),
            min_rtt: Duration::ZERO,
            max_rtt: Default::default(),
            params: params.into(),
            clock_stalled: AtomicBool::default(),
        }
    }

    /// Return true iff the estimator is ready to be used or read.
    pub(crate) fn is_ready(&self) -> bool {
        !self.clock_stalled() && !self.last_rtt.is_zero()
    }

    /// Return the state of the clock stalled indicator.
    pub(crate) fn clock_stalled(&self) -> bool {
        self.clock_stalled.load(Ordering::SeqCst)
    }

    /// Return the EWMA RTT in usec or u32 MAX if we don't have an estimate yet.
    pub(crate) fn ewma_rtt_usec(&self) -> u32 {
        u32::try_from(self.ewma_rtt.as_micros()).unwrap_or(u32::MAX)
    }

    /// Return the Minimum RTT in usec or u32 MAX value if we don't have an estimate yet.
    pub(crate) fn min_rtt_usec(&self) -> u32 {
        u32::try_from(self.min_rtt.as_micros()).unwrap_or(u32::MAX)
    }

    /// Inform the estimator that we did (at time `now`) something that we'll expect a SENDME to
    /// be received for.
    pub(crate) fn expect_sendme(&mut self, now: Instant) {
        self.sendme_expected_from.push_back(now);
    }

    /// Return whether we can use heuristics to sanity-check RTT values against our EWMA value.
    /// Spec: 2.1.1. Clock Jump Heuristics CLOCK_HEURISTICS
    ///
    /// Used in [`is_clock_stalled`](RoundtripTimeEstimator::is_clock_stalled), to check the sanity of
    /// a newly measured RTT value.
    fn can_crosscheck_with_current_estimate(&self, in_slow_start: bool) -> bool {
        // If we're in slow start, we don't perform any sanity checks, as per spec. If we don't
        // have a current estimate, we can't use it for sanity checking, because it doesn't
        // exist.
        !(in_slow_start || self.ewma_rtt.is_zero())
    }

    /// Given a raw RTT value we just observed, compute whether or not we think the clock has
    /// stalled or jumped, and we should throw it out as a result.
    fn is_clock_stalled(&self, raw_rtt: Duration, in_slow_start: bool) -> bool {
        if raw_rtt.is_zero() {
            // Clock is stalled.
            self.clock_stalled.store(true, Ordering::SeqCst);
            true
        } else if self.can_crosscheck_with_current_estimate(in_slow_start) {
            /// Discrepency ratio of a new RTT value that we allow against the current RTT in order
            /// to declare if the clock has stalled or not. This value is taken from proposal 324
            /// section 2.1.1 CLOCK_HEURISTICS and has the same name as in C-tor.
            const DELTA_DISCREPENCY_RATIO_MAX: u32 = 5000;
            // If we have enough data, check the sanity of our measurement against our EWMA value.
            if raw_rtt > self.ewma_rtt * DELTA_DISCREPENCY_RATIO_MAX {
                // The clock significantly jumped forward.
                //
                // Don't update the global cache, though, since this is triggerable over the
                // network.
                //
                // FIXME(eta): We should probably log something here?
                true
            } else if self.ewma_rtt > raw_rtt * DELTA_DISCREPENCY_RATIO_MAX {
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

    /// Update the estimator on time `now` and at the congestion window `cwnd`.
    ///
    /// # Errors
    ///
    /// Each call to this function removes an entry from `sendme_expected_from` (the entries are
    /// added using [`sendme_expected_from`](Self::sendme_expected_from)).
    ///
    /// Returns an error if are not expecting any SENDMEs at this time (if `expect_sendme` was
    /// never called, or if we have exhausted all `sendme_expected_from` added by previous
    /// `expect_sendme` calls).
    ///
    /// Spec: prop324 section 2.1 C-tor: congestion_control_update_circuit_rtt() in
    /// congestion_control_common.c
    pub(crate) fn update(
        &mut self,
        now: Instant,
        state: &State,
        cwnd: &CongestionWindow,
    ) -> Result<(), Error> {
        let data_sent_at = self
            .sendme_expected_from
            .pop_front()
            .ok_or(Error::MismatchedEstimationCall)?;
        let raw_rtt = now.saturating_duration_since(data_sent_at);

        if self.is_clock_stalled(raw_rtt, state.in_slow_start()) {
            return Ok(());
        }

        self.max_rtt = self.max_rtt.max(raw_rtt);
        self.last_rtt = raw_rtt;

        // This is the "N" for N-EWMA.
        let ewma_n = u64::from(if state.in_slow_start() {
            self.params.ewma_n_max_ss
        } else {
            min(
                (cwnd.update_rate(state) * (self.params.ewma_n_by_sendme_acks.as_percent())) / 100,
                self.params.ewma_n_max,
            )
        });
        let ewma_n = max(ewma_n, 2);

        // Get the USEC values.
        let raw_rtt_usec = raw_rtt.as_micros() as u64;
        let prev_ewma_rtt_usec = self.ewma_rtt.as_micros() as u64;

        // This is the actual EWMA calculation.
        // C-tor simplifies this as follows for rounding error reasons:
        //
        // EWMA = value*2/(N+1) + EMA_prev*(N-1)/(N+1)
        //      = (value*2 + EWMA_prev*(N-1))/(N+1)
        //
        // Spec: prop324 section 2.1.2 (N_EWMA_SMOOTHING)
        let new_ewma_rtt_usec = if prev_ewma_rtt_usec == 0 {
            raw_rtt_usec
        } else {
            ((raw_rtt_usec * 2) + ((ewma_n - 1) * prev_ewma_rtt_usec)) / (ewma_n + 1)
        };
        self.ewma_rtt = Duration::from_micros(new_ewma_rtt_usec);

        if self.min_rtt.is_zero() {
            self.min_rtt = self.ewma_rtt;
        } else if cwnd.get() == cwnd.min() && !state.in_slow_start() {
            // The cast is OK even if lossy, we only care about the usec level.
            let max = max(self.ewma_rtt, self.min_rtt).as_micros() as u64;
            let min = min(self.ewma_rtt, self.min_rtt).as_micros() as u64;
            let rtt_reset_pct = u64::from(self.params.rtt_reset_pct.as_percent());
            self.min_rtt = Duration::from_micros(
                (rtt_reset_pct * max / 100) + (100 - rtt_reset_pct) * min / 100,
            );
        } else if self.ewma_rtt < self.min_rtt {
            self.min_rtt = self.ewma_rtt;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::print_stderr)]
mod test {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::congestion::test::{new_cwnd, new_rtt_estimator};

    #[derive(Debug)]
    struct RttTestSample {
        sent_usec_in: u64,
        sendme_received_usec_in: u64,
        cwnd_in: u32,
        ss_in: bool,
        last_rtt_usec_out: u64,
        ewma_rtt_usec_out: u64,
        min_rtt_usec_out: u64,
    }

    impl From<[u64; 7]> for RttTestSample {
        fn from(arr: [u64; 7]) -> Self {
            Self {
                sent_usec_in: arr[0],
                sendme_received_usec_in: arr[1],
                cwnd_in: arr[2] as u32,
                ss_in: arr[3] == 1,
                last_rtt_usec_out: arr[4],
                ewma_rtt_usec_out: arr[5],
                min_rtt_usec_out: arr[6],
            }
        }
    }
    impl RttTestSample {
        fn test(&self, estimator: &mut RoundtripTimeEstimator, start: Instant) {
            let state = if self.ss_in {
                State::SlowStart
            } else {
                State::Steady
            };
            let mut cwnd = new_cwnd();
            cwnd.set(self.cwnd_in);
            let sent = start + Duration::from_micros(self.sent_usec_in);
            let sendme_received = start + Duration::from_micros(self.sendme_received_usec_in);

            estimator.expect_sendme(sent);
            estimator
                .update(sendme_received, &state, &cwnd)
                .expect("Error on RTT update");
            assert_eq!(
                estimator.last_rtt,
                Duration::from_micros(self.last_rtt_usec_out)
            );
            assert_eq!(
                estimator.ewma_rtt,
                Duration::from_micros(self.ewma_rtt_usec_out)
            );
            assert_eq!(
                estimator.min_rtt,
                Duration::from_micros(self.min_rtt_usec_out)
            );
        }
    }

    #[test]
    fn test_vectors() {
        let mut rtt = new_rtt_estimator();
        let now = Instant::now();
        // from C-tor src/test/test_congestion_control.c
        let vectors = [
            [100000, 200000, 124, 1, 100000, 100000, 100000],
            [200000, 300000, 124, 1, 100000, 100000, 100000],
            [350000, 500000, 124, 1, 150000, 133333, 100000],
            [500000, 550000, 124, 1, 50000, 77777, 77777],
            [600000, 700000, 124, 1, 100000, 92592, 77777],
            [700000, 750000, 124, 1, 50000, 64197, 64197],
            [750000, 875000, 124, 0, 125000, 104732, 104732],
            [875000, 900000, 124, 0, 25000, 51577, 104732],
            [900000, 950000, 200, 0, 50000, 50525, 50525],
        ];
        for vect in vectors {
            let vect = RttTestSample::from(vect);
            eprintln!("Testing vector: {:?}", vect);
            vect.test(&mut rtt, now);
        }
    }
}
