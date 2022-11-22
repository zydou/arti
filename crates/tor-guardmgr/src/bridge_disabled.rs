//! Bridges (stub module, bridges disabled in cargo features)

use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use tor_config::ConfigBuildError;

#[path = "bridge/config/err.rs"]
mod err;
pub use err::BridgeParseError;

/// Configuration for a bridge - uninhabited placeholder type
///
/// This type appears in configuration APIs as a stand-in,
/// when the `bridge-client` cargo feature is not enabled.
///
/// The type is uninhabited: without this feature, you cannot create a `BridgeConfig`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BridgeConfig {}

/// Configuration builder for a bridge - dummy type
///
/// This type appears in configuration APIs as a stand-in,
/// when the `bridge-client` cargo feature is not enabled.
///
/// It can be deserialized, but you cannot actually build a `BridgeConfig` from it.
//
// Making this type inhabited significantly improves the error messages
// when bridges are requested when support isn't enabled.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[derive(Serialize)]
pub struct BridgeConfigBuilder {}

impl<'de> Deserialize<'de> for BridgeConfigBuilder {
    fn deserialize<D>(_: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(BridgeConfigBuilder {})
    }
}

impl BridgeConfigBuilder {
    /// Build (dummy function, cannot ever be called)
    pub fn build(&self) -> Result<BridgeConfig, ConfigBuildError> {
        Err(ConfigBuildError::Invalid {
            field: "(bridge)".into(),
            problem: BridgeParseError::BridgesNotSupported.to_string(),
        })
    }
}

impl FromStr for BridgeConfigBuilder {
    type Err = BridgeParseError;

    fn from_str(_: &str) -> Result<BridgeConfigBuilder, BridgeParseError> {
        Err(BridgeParseError::BridgesNotSupported)
    }
}
