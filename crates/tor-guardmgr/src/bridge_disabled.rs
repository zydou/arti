//! Bridges (stub module, bridges disabled in cargo features)

/// Configuration for a bridge - uninhabited placeholder type
///
/// This type appears in configuration APIs as a stand-in,
/// when the `bridge-client` cargo feature is not enabled.
///
/// The type is uninhabited: without this feature, you cannot create a `BridgeConfig`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BridgeConfig {}

/// Configuration builder for a bridge - uninhabited placeholder type
///
/// This type appears in configuration APIs as a stand-in,
/// when the `bridge-client` cargo feature is not enabled.
///
/// The type is uninhabited: without this feature, you cannot create a `BridgeConfigBuilder`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BridgeConfigBuilder {}
