//! Stub for configuration for OpenTelemetry exporter

use derive_deftly::Deftly;
use serde::{Deserialize, Serialize};
use tor_config::derive::prelude::*;

#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize)]
#[derive_deftly(TorConfig)]
/// Stub configuration for exporting spans with OpenTelemetry.
pub struct OpentelemetryConfig;

#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize)]
#[derive_deftly(TorConfig)]
/// Stub configuration for the OpenTelemetry HTTP exporter.
pub struct OpentelemetryFileExporterConfig;
