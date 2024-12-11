//! Configure and activate RPC listeners from connect points.

use std::collections::BTreeMap;

use derive_builder::Builder;
use derive_deftly::Deftly;
use serde::{Deserialize, Serialize};
use tor_config::{
    define_map_builder, derive_deftly_template_ExtendBuilder, impl_standard_builder,
    ConfigBuildError,
};
use tor_config_path::CfgPath;

define_map_builder! {
    /// Builder for a map of RpcListenerConfig.
    pub(crate) struct RpcListenerMapBuilder =>
    pub(crate) type RpcListenerMap = BTreeMap<String, RpcListenerConfig>;

    defaults: listener_map_defaults();
}

/// Return defaults for RpcListenerMapBuilder.
fn listener_map_defaults() -> BTreeMap<String, RpcListenerConfigBuilder> {
    toml::from_str(
        r#"
        ["user-default"]
        enable = true
        dir = "${ARTI_LOCAL_DATA}/rpc/connect.d"

        ["system-default"]
        enable = false
        dir = "/etc/arti-rpc/connect.d"
        "#,
    )
    .expect("Could not parse defaults!")
}

/// Configuration for a single source of connect points
/// to use when configuring Arti as an RPC server.
#[derive(Debug, Clone, Deftly, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError", validate = "Self::validate"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[derive_deftly(ExtendBuilder)]
pub(crate) struct RpcListenerConfig {
    /// If true (the default), arti will try to listen at this connect point.
    #[builder(default = "true")]
    enable: bool,
    /// A path to a file on disk containing a connect string.
    ///
    /// Exactly one of `file` or `dir` may be set.
    #[builder(setter(strip_option), default)]
    file: Option<CfgPath>,
    /// A path to a directory on disk containing one or more connect strings.
    ///
    /// Only files whose names end with ``.toml` are considered.
    ///
    /// Exactly one of `file` or `dir` may be set.
    #[builder(setter(strip_option), default)]
    dir: Option<CfgPath>,
    /// Map from file name within `dir` to options to be set on the individual files.
    ///
    /// If this option is set, `dir` must be set.
    //
    // XXXX We want a way to set each of these options on RpcListenerConfig.  Will this involve duplication?
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    #[deftly(extend_builder(sub_builder))]
    // XXXX rename this field, I think.
    overrides: OverrideMap,
}
impl_standard_builder! { RpcListenerConfig: !Deserialize !Default }

impl RpcListenerConfigBuilder {
    /// Return an error if this builder isn't valid.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        match (&self.file, &self.dir, self.overrides.is_empty()) {
            // If "file" is present, dir and overrides must be absent.
            (Some(_), None, true) => Ok(()),
            // If "dir" is present, file must be absent and overrides can be whatever.
            (None, Some(_), _) => Ok(()),
            // Otherwise, there's an error.
            (None, None, _) => Err(ConfigBuildError::MissingField {
                field: "{file or dir}".into(),
            }),
            (_, _, _) => Err(ConfigBuildError::Inconsistent {
                fields: vec!["file".into(), "dir".into(), "overrides".into()],
                problem: "'file' is mutually exclusive with 'dir' and 'overrides'".into(),
            }),
        }
    }
}

define_map_builder! {
    /// Builder for the `OverrideMap` within an `RpcListenerConfig`.
    struct OverrideMapBuilder =>
    type OverrideMap = BTreeMap<String, OverrideConfig>;
}

/// Configuration for overriding a single item in a connect point directory.
///
/// This structure's corresponding builder appears at two points
/// in our configuration tree:
/// Once at the `RpcListenerConfig` level,
/// and once (for directories only!) under the `file_options` map.
///
/// When loading a connect point from an explicitly specified file,
/// we look at the `ConnectPointOptionsBuilder` under the `RpcListenerConfig` only.
///
/// When loading a connect point from a file within a specified directory,
/// we use the `ConnectPointOptionsBuilder` under the `RpcListenerConfig`
/// as a set of defaults,
/// and we extend those defaults from any entry we find in the `file_options` map
/// corresponding to the connect point's filename.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Deftly)]
#[derive_deftly(ExtendBuilder)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
struct OverrideConfig {
    /// Used to explicitly disable an entry in a connect point directory.
    #[builder(default = "true")]
    enable: bool,
}
impl_standard_builder! { OverrideConfig }

#[cfg(test)]
mod test {}
