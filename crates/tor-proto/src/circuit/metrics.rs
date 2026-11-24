//! Metrics for circuits.

use metrics::Counter;

#[cfg(any(feature = "hs-service", feature = "relay"))]
use crate::stream::incoming::IncomingStreamRequest;

/// Name of the stream requests counter.
const STREAM_REQUESTS_TOTAL: &str = "arti_stream_requests_total";

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
    /// Number of BEGIN stream requests received.
    stream_requests_begin: Counter,
    /// Number of BEGIN_DIR stream requests received.
    stream_requests_begin_dir: Counter,
    /// Number of RESOLVE stream requests received.
    stream_requests_resolve: Counter,
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
            stream_requests_begin: metrics::counter!(
                description: "Total number of exit stream requests received",
                unit: metrics::Unit::Count,
                STREAM_REQUESTS_TOTAL,
                "type" => "begin",
            ),
            stream_requests_begin_dir: metrics::counter!(
                description: "Total number of directory requests received",
                unit: metrics::Unit::Count,
                STREAM_REQUESTS_TOTAL,
                "type" => "begin_dir",
            ),
            stream_requests_resolve: metrics::counter!(
                description: "Total number of DNS query requests received",
                unit: metrics::Unit::Count,
                STREAM_REQUESTS_TOTAL,
                "type" => "resolve",
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

    /// Count a stream request by its type.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    pub(crate) fn increment_stream_requests(&self, req: &IncomingStreamRequest) {
        match req {
            IncomingStreamRequest::Begin(_) => self.stream_requests_begin.increment(1),
            IncomingStreamRequest::BeginDir(_) => self.stream_requests_begin_dir.increment(1),
            IncomingStreamRequest::Resolve(_) => self.stream_requests_resolve.increment(1),
        }
    }
}
