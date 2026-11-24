//! Metrics for circuits.

use metrics::Counter;

/// The metrics counters of the circuits.
///
/// This is created once and shared between circuit reactors.
//
// TODO(relay): This is only used for relay circuits. Client circuit (for an actual arti
// client) aren't counted nor the relay client's circuits.
pub(crate) struct CircuitMetrics {
    /// Number of circuits opened.
    circuit_opened: Counter,
    /// Number of circuits closed.
    closed: Counter,
}

impl CircuitMetrics {
    /// Create a new instance of [`CircuitMetrics`].
    pub(crate) fn new() -> Self {
        Self {
            circuit_opened: metrics::counter!(
                description: "Total number of circuits opened",
                unit: metrics::Unit::Count,
                "arti_circuits_opened_total",
            ),
            closed: metrics::counter!(
                description: "Total number of circuits closed",
                unit: metrics::Unit::Count,
                "arti_circuits_closed_total",
            ),
        }
    }

    /// Count a circuit that opened.
    pub(crate) fn circuit_opened(&self) {
        self.circuit_opened.increment(1);
    }

    /// Count a circuit that closed.
    pub(crate) fn circuit_closed(&self) {
        self.closed.increment(1);
    }
}
