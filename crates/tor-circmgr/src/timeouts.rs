//! Code for estimating good values for circuit timeouts.
//!
//! We need good circuit timeouts for two reasons: first, they help
//! user experience.  If user wait too long for their circuits, or if
//! they use exceptionally slow circuits, then Tor will feel really
//! slow.  Second, these timeouts are actually a security
//! property.
// TODO(nickm): explain why!

use std::time::Duration;

pub(crate) mod estimator;
pub(crate) mod pareto;
pub(crate) mod readonly;

pub(crate) use estimator::Estimator;

/// An object that calculates circuit timeout thresholds from the history
/// of circuit build times.
pub(crate) trait TimeoutEstimator {
    /// Record that a given circuit hop has completed.
    ///
    /// The `hop` number is a zero-indexed value for which hop just completed.
    ///
    /// The `delay` value is the amount of time after we first launched the
    /// circuit.
    ///
    /// If this is the last hop of the circuit, then `is_last` is true.
    fn note_hop_completed(&mut self, hop: u8, delay: Duration, is_last: bool);

    /// Record that a circuit failed to complete because it took too long.
    ///
    /// The `hop` number is a the number of hops that were successfully
    /// completed.
    ///
    /// The `delay` number is the amount of time after we first launched the
    /// circuit.
    fn note_circ_timeout(&mut self, hop: u8, delay: Duration);

    /// Return the current estimation for how long we should wait for a given
    /// [`Action`] to complete.
    ///
    /// This function should return a 2-tuple of `(timeout, abandon)`
    /// durations.  After `timeout` has elapsed since circuit launch,
    /// the circuit should no longer be used, but we should still keep
    /// building it in order see how long it takes.  After `abandon`
    /// has elapsed since circuit launch, the circuit should be
    /// abandoned completely.
    fn timeouts(&mut self, action: &Action) -> (Duration, Duration);

    /// Return true if we're currently trying to learn more timeouts
    /// by launching testing circuits.
    fn learning_timeouts(&self) -> bool;

    /// Replace the network parameters used by this estimator (if any)
    /// with ones derived from `params`.
    fn update_params(&mut self, params: &tor_netdir::params::NetParameters);

    /// Construct a new ParetoTimeoutState to represent the current state
    /// of this estimator, if it is possible to store the state to disk.
    ///
    /// TODO: change the type used for the state.
    fn build_state(&mut self) -> Option<pareto::ParetoTimeoutState>;
}

/// A possible action for which we can try to estimate a timeout.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Build a circuit of a given length.
    BuildCircuit {
        /// The length of the circuit to construct.
        ///
        /// (A 0-hop circuit takes no time.)
        length: usize,
    },
    /// Extend a given circuit from one length to another.
    ExtendCircuit {
        /// The current length of the circuit.
        initial_length: usize,
        /// The new length of the circuit.
        ///
        /// (Should typically be greater than `initial_length`; otherwise we
        /// estimate a zero timeout.)
        final_length: usize,
    },
    /// Send a message to the last hop of a circuit and receive a response
    RoundTrip {
        /// The length of the circuit.
        length: usize,
    },
}

impl Action {
    /// Compute a scaling factor for a given `Action`
    ///
    /// These values are arbitrary numbers such that if the correct
    /// timeout for an Action `a1` is `t`, then the correct timeout
    /// for an action `a2` is `t * a2.timeout_scale() /
    /// a1.timeout_scale()`.
    ///
    /// This function can return garbage if the circuit length is larger
    /// than actually supported on the Tor network.
    fn timeout_scale(&self) -> usize {
        /// An arbitrary value to use to prevent overflow.
        const MAX_LEN: usize = 64;

        /// Return the scale value for building a `len`-hop circuit.
        fn build_scale(len: usize) -> usize {
            len * (len + 1) / 2
        }
        // This is based on an approximation from Tor's
        // `circuit_expire_building()` code.
        //
        // The general principle here is that when you're waiting for
        // a round-trip through a circuit through three relays
        // 'a--b--c', it takes three units of time.  Thus, building a
        // three hop circuit requires you to send a message through
        // "a", then through "a--b", then through "a--b--c", for a
        // total of 6.
        //
        // This is documented in path-spec.txt under "Calculating
        // timeouts thresholds for circuits of different lengths".
        match *self {
            Action::BuildCircuit { length } => {
                // We never down-scale our estimates for building a circuit
                // below a 3-hop length.
                //
                // TODO: This is undocumented.
                let length = length.clamp(3, MAX_LEN);
                build_scale(length)
            }
            Action::ExtendCircuit {
                initial_length,
                final_length,
            } => {
                let initial_length = initial_length.clamp(0, MAX_LEN);
                let final_length = final_length.clamp(initial_length, MAX_LEN);
                build_scale(final_length) - build_scale(initial_length)
            }
            Action::RoundTrip { length } => length.clamp(0, MAX_LEN),
        }
    }
}

/// A safe variant of [`Duration::mul_f64`] that never panics.
///
/// For infinite or NaN or negative multipliers, the results might be
/// nonsensical, but at least they won't be a panic.
fn mul_duration_f64_saturating(d: Duration, mul: f64) -> Duration {
    let secs = d.as_secs_f64() * mul;
    // At this point I'd like to use Duration::try_from_secs_f64, but
    // that isn't stable yet. :p
    if secs.is_finite() && secs >= 0.0 {
        // We rely on the property that `f64 as uNN` is saturating.
        let seconds = secs.trunc() as u64;
        let nanos = if seconds == u64::MAX {
            0 // prevent any possible overflow.
        } else {
            (secs.fract() * 1e9) as u32
        };
        Duration::new(seconds, nanos)
    } else {
        Duration::from_secs(1)
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

    #[test]
    fn action_scale_values() {
        assert_eq!(Action::BuildCircuit { length: 1 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 2 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 3 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 4 }.timeout_scale(), 10);
        assert_eq!(Action::BuildCircuit { length: 5 }.timeout_scale(), 15);

        assert_eq!(
            Action::ExtendCircuit {
                initial_length: 3,
                final_length: 4
            }
            .timeout_scale(),
            4
        );
        assert_eq!(
            Action::ExtendCircuit {
                initial_length: 99,
                final_length: 4
            }
            .timeout_scale(),
            0
        );

        assert_eq!(Action::RoundTrip { length: 3 }.timeout_scale(), 3);
    }

    #[test]
    fn test_mul_duration() {
        // This is wrong because of leap years, but we'll fake it.
        let mega_year = Duration::from_secs(86400 * 365 * 1000 * 1000);

        // Multiply by zero.
        let v = mul_duration_f64_saturating(mega_year, 0.0);
        assert!(v.is_zero());

        // Multiply by one.
        assert_eq!(mul_duration_f64_saturating(mega_year, 1.0), mega_year);

        // Divide by 1000.
        let v = mul_duration_f64_saturating(mega_year, 1.0 / 1000.0);
        let s = v.as_secs_f64();
        assert!((s - (mega_year.as_secs_f64() / 1000.0)).abs() < 0.1);

        // This would overflow if we were using mul_f64.
        let v = mul_duration_f64_saturating(mega_year, 1e9);
        assert!(v > mega_year * 1000);

        // This would underflow.
        let v = mul_duration_f64_saturating(mega_year, -1.0);
        assert_eq!(v, Duration::from_secs(1));

        // These are just silly.
        let v = mul_duration_f64_saturating(mega_year, f64::INFINITY);
        assert_eq!(v, Duration::from_secs(1));
        let v = mul_duration_f64_saturating(mega_year, f64::NEG_INFINITY);
        assert_eq!(v, Duration::from_secs(1));
        let v = mul_duration_f64_saturating(mega_year, f64::NAN);
        assert_eq!(v, Duration::from_secs(1));
    }
}
