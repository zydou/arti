//! Tools for determining what circuits to preemptively build.

use crate::{TargetCircUsage, TargetPort};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Predicts what circuits might be used in future based on past activity, and suggests
/// circuits to preemptively build as a result.
pub(crate) struct PreemptiveCircuitPredictor {
    /// A map of every exit port we've observed being used (or `None` if we observed an exit being
    /// used to resolve DNS names instead of building a stream), to the last time we encountered
    /// such usage.
    usages: HashMap<Option<TargetPort>, Instant>,
}

impl PreemptiveCircuitPredictor {
    /// Create a new predictor, starting out with a set of ports we think are likely to be used.
    pub(crate) fn new(starting_ports: Vec<TargetPort>) -> Self {
        let mut usages = HashMap::new();
        for sp in starting_ports {
            usages.insert(Some(sp), Instant::now());
        }
        // We want to build circuits for resolving DNS, too.
        usages.insert(None, Instant::now());
        Self { usages }
    }

    /// Make some predictions for what circuits should be built.
    pub(crate) fn predict(&self) -> Vec<TargetCircUsage> {
        // path-spec.txt § 2.1.1: "[Tor] tries to have two fast exit circuits available for every
        // port seen within the past hour" (although they can be shared)
        let hour_ago = Instant::now() - Duration::from_secs(60 * 60);
        self.usages
            .iter()
            .filter(|(_, &time)| time > hour_ago)
            .map(|(&port, _)| TargetCircUsage::Preemptive { port })
            .collect()
    }

    /// Note the use of a new port at the provided `time`.
    pub(crate) fn note_usage(&mut self, port: Option<TargetPort>, time: Instant) {
        self.usages.insert(port, time);
    }
}

#[cfg(test)]
mod test {
    use crate::{PreemptiveCircuitPredictor, TargetCircUsage, TargetPort};
    use std::time::{Duration, Instant};

    #[test]
    fn predicts_starting_ports() {
        let predictor = PreemptiveCircuitPredictor::new(vec![]);

        let mut results = predictor.predict();
        results.sort();
        assert_eq!(
            predictor.predict(),
            vec![TargetCircUsage::Preemptive { port: None }]
        );

        let predictor =
            PreemptiveCircuitPredictor::new(vec![TargetPort::ipv4(80), TargetPort::ipv6(80)]);

        let mut results = predictor.predict();
        results.sort();
        assert_eq!(
            results,
            vec![
                TargetCircUsage::Preemptive { port: None },
                TargetCircUsage::Preemptive {
                    port: Some(TargetPort::ipv4(80))
                },
                TargetCircUsage::Preemptive {
                    port: Some(TargetPort::ipv6(80))
                },
            ]
        )
    }

    #[test]
    fn predicts_used_ports() {
        let mut predictor = PreemptiveCircuitPredictor::new(vec![]);

        assert_eq!(
            predictor.predict(),
            vec![TargetCircUsage::Preemptive { port: None }]
        );

        predictor.note_usage(Some(TargetPort::ipv4(1234)), Instant::now());

        let mut results = predictor.predict();
        results.sort();
        assert_eq!(
            results,
            vec![
                TargetCircUsage::Preemptive { port: None },
                TargetCircUsage::Preemptive {
                    port: Some(TargetPort::ipv4(1234))
                }
            ]
        );
    }

    #[test]
    fn does_not_predict_old_ports() {
        let mut predictor = PreemptiveCircuitPredictor::new(vec![]);
        let more_than_an_hour_ago = Instant::now() - Duration::from_secs(60 * 60 + 1);

        predictor.note_usage(Some(TargetPort::ipv4(2345)), more_than_an_hour_ago);

        assert_eq!(
            predictor.predict(),
            vec![TargetCircUsage::Preemptive { port: None }]
        );
    }
}
