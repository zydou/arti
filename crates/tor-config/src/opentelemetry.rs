//! Configuration for OpenTelemetry exporter

use crate::derive::prelude::*;
use amplify::Getters;
use derive_deftly::Deftly;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tor_config_path::CfgPath;

/// Configuration for exporting spans with OpenTelemetry.
#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryConfig {
    /// Write spans to a file in OTLP JSON format.
    #[deftly(tor_config(default))]
    file: Option<OpentelemetryFileExporterConfig>,
    /// Export spans via HTTP.
    #[deftly(tor_config(default))]
    http: Option<OpentelemetryHttpExporterConfig>,
}

/// Configuration for the OpenTelemetry HTTP exporter.
#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryHttpExporterConfig {
    /// HTTP(S) endpoint to send spans to.
    ///
    /// For Jaeger, this should be something like: `http://localhost:4318/v1/traces`
    #[deftly(tor_config(no_default))]
    endpoint: String,
    /// Configuration for how to batch exports.
    #[deftly(tor_config(sub_builder))]
    batch: OpentelemetryBatchConfig,
    /// Timeout for sending data.
    ///
    /// If this is set to [`None`], it will be left at the OpenTelemetry default, which is
    /// currently 10 seconds unless overrided with a environment variable.
    #[deftly(tor_config(default, serde = r#"with = "humantime_serde::option" "#))]
    timeout: Option<Duration>,
    // TODO: Once opentelemetry-otlp supports more than one protocol over HTTP, add a config option
    // to choose protocol here.
}

/// Configuration for the OpenTelemetry File exporter.
#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryFileExporterConfig {
    /// The path to write the JSON file to.
    #[deftly(tor_config(no_default))]
    path: CfgPath,
    /// Configuration for how to batch writes.
    #[deftly(tor_config(sub_builder))]
    batch: OpentelemetryBatchConfig,
}

/// Configuration for the Opentelemetry batch exporting.
///
/// This is a copy of [`opentelemetry_sdk::trace::BatchConfig`].
#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryBatchConfig {
    /// Maximum queue size. See [`opentelemetry_sdk::trace::BatchConfig::max_queue_size`].
    #[deftly(tor_config(default))]
    max_queue_size: Option<usize>,
    /// Maximum export batch size. See [`opentelemetry_sdk::trace::BatchConfig::max_export_batch_size`].
    #[deftly(tor_config(default))]
    max_export_batch_size: Option<usize>,
    /// Scheduled delay. See [`opentelemetry_sdk::trace::BatchConfig::scheduled_delay`].
    #[deftly(tor_config(default, serde = r#"with = "humantime_serde::option" "#))]
    scheduled_delay: Option<Duration>,
}

#[cfg(feature = "opentelemetry")]
impl From<OpentelemetryBatchConfig> for opentelemetry_sdk::trace::BatchConfig {
    fn from(config: OpentelemetryBatchConfig) -> opentelemetry_sdk::trace::BatchConfig {
        let batch_config = opentelemetry_sdk::trace::BatchConfigBuilder::default();

        let batch_config = if let Some(max_queue_size) = config.max_queue_size {
            batch_config.with_max_queue_size(max_queue_size)
        } else {
            batch_config
        };

        let batch_config = if let Some(max_export_batch_size) = config.max_export_batch_size {
            batch_config.with_max_export_batch_size(max_export_batch_size)
        } else {
            batch_config
        };

        let batch_config = if let Some(scheduled_delay) = config.scheduled_delay {
            batch_config.with_scheduled_delay(scheduled_delay)
        } else {
            batch_config
        };

        batch_config.build()
    }
}
