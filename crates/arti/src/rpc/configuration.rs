//! Functionality for accessing and modifying configuration over RPC

/// A set of configuration options maintained by the RPC subsystem.
///
/// These are applied after all loaded configuration values.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[allow(unused)] // TODO RPC Config remove.
pub(crate) struct ConfigSettings(serde_json::Map<String, serde_json::Value>);
