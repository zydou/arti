use derive_deftly::Deftly;
use serde::{Deserialize, Serialize};
use tor_config::derive::prelude::*;

#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryConfig;

#[derive(Debug, Clone, Deftly, Eq, PartialEq, Serialize, Deserialize)]
#[derive_deftly(TorConfig)]
pub struct OpentelemetryFileExporterConfig;
