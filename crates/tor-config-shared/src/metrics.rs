//! Configuration for metrics reporting via Prometheus / etc

use derive_deftly::Deftly;

use tor_config::Listen;
use tor_config::derive::prelude::*;

/// Configuration for exporting metrics (eg, perf data)
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[non_exhaustive]
pub struct MetricsConfig {
    /// Where to listen for incoming HTTP connections.
    #[deftly(tor_config(sub_builder))]
    pub prometheus: PrometheusConfig,
}

/// Configuration for one or more proxy listeners.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[non_exhaustive]
pub struct PrometheusConfig {
    /// Port on which to establish a Prometheus scrape endpoint
    ///
    /// We listen here for incoming HTTP connections.
    ///
    /// If just a port is provided, we don't support IPv6.
    /// Alternatively, (only) a single address and port can be specified.
    /// These restrictions are due to upstream limitations:
    /// <https://github.com/metrics-rs/metrics/issues/567>.
    #[deftly(tor_config(default))]
    pub listen: Listen,
}
