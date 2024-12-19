//! Configure and activate RPC listeners from connect points.

use anyhow::Context;
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    str::FromStr as _,
    sync::Arc,
};
use tracing::debug;

use derive_builder::Builder;
use derive_deftly::Deftly;
use fs_mistrust::{anon_home::PathExt as _, Mistrust};
use serde::{Deserialize, Serialize};
use tor_basic_utils::PathExt as _;
use tor_config::{
    define_map_builder, derive_deftly_template_ExtendBuilder, extend_builder::ExtendBuilder as _,
    extend_builder::ExtendStrategy, impl_standard_builder, ConfigBuildError,
};
use tor_config_path::{CfgPath, CfgPathResolver};
use tor_error::internal;
use tor_rpc_connect::{
    auth::RpcAuth,
    load::{LoadOptions, LoadOptionsBuilder},
    server::Guard,
    ParsedConnectPoint,
};
use tor_rtcompat::{general, Runtime};

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
    /// An builder to determine default connect point options.
    ///
    /// If `file` is set, this builder is used directly
    /// to determine the options for the connect points.
    ///
    /// If `dir` is set, this builder defines a set of defaults
    /// that we can override for each connect point in `file_options`.
    #[builder(
        sub_builder(fn_name = "build"),
        field(
            // This lets us hold a Builder in the Config too,
            // so we can use `ExtendBuilder` on it.
            type = "ConnectPointOptionsBuilder",
            build = "self.listener_options.clone()"
        )
    )]
    #[builder_field_attr(serde(flatten, default))]
    #[deftly(extend_builder(sub_builder))]
    listener_options: ConnectPointOptionsBuilder,

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
    /// Map from file name within `dir` to builders for options on the individual files.
    ///
    /// We hold builders here so that we can use `ExtendBuilder` to derive settings
    /// using `listener_options` as the defaults.
    #[builder(
        sub_builder(fn_name = "build"),
        // This lets us hold a Builder in the Config too,
        // so we can use `ExtendBuilder` on it.
        field(type = "FileOptionsMapBuilder", build = "self.file_options.clone()")
    )]
    #[builder_field_attr(serde(default))]
    #[deftly(extend_builder(sub_builder))]
    file_options: FileOptionsMapBuilder,
}
impl_standard_builder! { RpcListenerConfig: !Deserialize !Default }

impl RpcListenerConfigBuilder {
    /// Return an error if this builder isn't valid.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        match (&self.file, &self.dir, self.file_options.is_empty()) {
            // If "file" is present, dir and file_options must be absent.
            (Some(_), None, true) => Ok(()),
            // If "dir" is present, file must be absent and file_options can be whatever.
            (None, Some(_), _) => Ok(()),
            // Otherwise, there's an error.
            (None, None, _) => Err(ConfigBuildError::MissingField {
                field: "{file or dir}".into(),
            }),
            (_, _, _) => Err(ConfigBuildError::Inconsistent {
                fields: vec!["file".into(), "dir".into(), "file_options".into()],
                problem: "'file' is mutually exclusive with 'dir' and 'file_options'".into(),
            }),
        }
    }
}

define_map_builder! {
    /// Builder for the `FileOptionsMap` within an `RpcListenerConfig`.
    #[derive(Eq, PartialEq)]
    struct FileOptionsMapBuilder =>
    type FileOptionsMap = BTreeMap<String, ConnectPointOptions>;
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
#[builder(derive(Debug, Serialize, Deserialize, Eq, PartialEq))]
pub(super) struct ConnectPointOptions {
    /// Used to explicitly disable an entry in a connect point directory.
    #[builder(default = "true")]
    enable: bool,
}
impl_standard_builder! { ConnectPointOptions }

impl ConnectPointOptionsBuilder {
    /// Return true if this builder represents an enabled connect point.
    fn is_enabled(&self) -> bool {
        self.enable != Some(false)
    }

    /// Return a [`LoadOptions`] corresponding to this OverrideConfig.
    ///
    /// The `LoadOptions` will contain a subset of our own options,
    /// set in order to make [`ParsedConnectPoint::load_dir`] behaved as configured here.
    fn load_options(&self) -> LoadOptions {
        LoadOptionsBuilder::default()
            .disable(!self.is_enabled())
            .build()
            .expect("Somehow constructed an invalid LoadOptions")
    }
}

/// Configuration information used to initialize RPC connections.
///
/// This information is derived from the configuration on the connect point,
/// and from the connect point itself.
#[derive(Clone, Debug)]
pub(super) struct RpcConnInfo {
    /// A human-readable name for the source of this RPC connection.
    ///
    /// We try to make this unique, but it might not be, depending on filesystem UTF-8 issues.
    pub(super) name: String,
    /// The authentication we require for this RPC connection.
    pub(super) auth: RpcAuth,
    /// The options for this connect point.
    #[allow(unused)] // TODO: Once there are more options than "enable", this will be used.
    pub(super) options: ConnectPointOptions,
}

impl RpcConnInfo {
    /// Initialize a new `RpcConnInfo`.
    ///
    /// Uses `config_key` (the name of the relevant section within our TOML config)
    /// and `filename` (a filename within a connect point directory)
    /// to name the connect point.
    ///
    /// Uses `auth` and `options` as settings to initialize new connections.
    #[allow(clippy::unnecessary_wraps)]
    fn new(
        config_key: &str,
        filename: Option<&Path>,
        auth: RpcAuth,
        options: ConnectPointOptions,
    ) -> anyhow::Result<Self> {
        let name = match filename {
            Some(p) => format!("{} ({})", config_key, p.display_lossy()),
            None => config_key.to_string(),
        };

        Ok(Self {
            name,
            auth,
            options,
        })
    }
}

impl RpcListenerConfig {
    /// Load every connect point from this file or directory,
    /// and bind to them.
    ///
    /// On success, returns a list of bound sockets,
    /// along with information about how to treat incoming connections on those sockets,
    /// and a guard object that must not be dropped until we are no longer listening on the socket.
    pub(super) async fn bind<R: Runtime>(
        &self,
        runtime: &R,
        config_key: &str,
        resolver: &CfgPathResolver,
        mistrust: &Mistrust,
    ) -> anyhow::Result<Vec<(general::Listener, Arc<RpcConnInfo>, Guard)>> {
        if !self.listener_options.is_enabled() {
            return Ok(vec![]);
        }

        if let Some(file) = &self.file {
            let file = file.path(resolver)?;
            debug!(
                "Binding to RPC connect point from {}",
                file.anonymize_home()
            );
            let ctx = |action| {
                format!(
                    "Can't {} RPC connect point from {}",
                    action,
                    file.anonymize_home()
                )
            };
            let options = self
                .listener_options
                .build()
                .with_context(|| ctx("interpret options"))?;

            let conn_pt = ParsedConnectPoint::load_file(file.as_ref(), mistrust)
                .with_context(|| ctx("load"))?
                .resolve(resolver)
                .with_context(|| ctx("resolve"))?;
            let tor_rpc_connect::server::Listener {
                listener,
                auth,
                guard,
                ..
            } = conn_pt
                .bind(runtime, mistrust)
                .await
                .with_context(|| ctx("bind to"))?;
            return Ok(vec![(
                listener,
                Arc::new(RpcConnInfo::new(config_key, None, auth, options)?),
                guard,
            )]);
        }

        if let Some(dir) = &self.dir {
            let dir = dir.path(resolver)?;
            debug!("Reading RPC connect directory at {}", dir.anonymize_home());
            // Make a map of instructions from our `file_options` telling
            // `ParsedConnectPoint::load_dir` about any filenames that might need special handling.
            let load_options: HashMap<std::path::PathBuf, LoadOptions> = self
                .file_options
                .iter()
                .map(|(s, or)| (s.into(), or.load_options()))
                .collect();
            let mut listeners = Vec::new();
            let dir_contents = ParsedConnectPoint::load_dir(dir.as_ref(), mistrust, &load_options)
                .with_context(|| {
                    format!(
                        "Can't read RPC connect point directory at {}",
                        dir.anonymize_home()
                    )
                })?;
            for (path, conn_pt_result) in dir_contents {
                debug!("Binding to connect point from {}", path.display_lossy());
                let ctx = |action| {
                    format!(
                        "Can't {} RPC connect point {} from dir {}",
                        action,
                        path.display_lossy(),
                        dir.anonymize_home()
                    )
                };

                let options = {
                    let mut bld = self.listener_options.clone();

                    if let Some(override_options) = path
                        .to_str()
                        .and_then(|fname_as_str| self.file_options.get(fname_as_str))
                    {
                        bld.extend_from(override_options.clone(), ExtendStrategy::ReplaceLists);
                    }
                    bld.build().with_context(|| ctx("interpret options"))?
                };

                let conn_pt = conn_pt_result
                    .with_context(|| ctx("load"))?
                    .resolve(resolver)
                    .with_context(|| ctx("resolve"))?;

                let tor_rpc_connect::server::Listener {
                    listener,
                    auth,
                    guard,
                    ..
                } = conn_pt
                    .bind(runtime, mistrust)
                    .await
                    .with_context(|| ctx("bind to"))?;
                listeners.push((
                    listener,
                    Arc::new(RpcConnInfo::new(
                        config_key,
                        Some(path.as_ref()),
                        auth,
                        options,
                    )?),
                    guard,
                ));
            }

            return Ok(listeners);
        }

        Err(internal!("Constructed RpcListenerConfig had neither 'dir' nor 'file' set.").into())
    }
}

/// As [`RpcListenerConfig`], but bind directly to a verbatim connect point given as a string.
pub(super) async fn bind_string<R: Runtime>(
    connpt: &str,
    index: usize,
    runtime: &R,
    resolver: &CfgPathResolver,
    mistrust: &Mistrust,
) -> anyhow::Result<(general::Listener, Arc<RpcConnInfo>, Guard)> {
    let ctx = |action| format!("Can't {action} RPC connect point from rpc.listen_default.#{index}");

    let conn_pt = ParsedConnectPoint::from_str(connpt)
        .with_context(|| ctx("parse"))?
        .resolve(resolver)
        .with_context(|| ctx("resolve"))?;
    let tor_rpc_connect::server::Listener {
        listener,
        auth,
        guard,
        ..
    } = conn_pt
        .bind(runtime, mistrust)
        .await
        .with_context(|| ctx("bind to"))?;
    Ok((
        listener,
        Arc::new(RpcConnInfo::new(
            "<default>",
            Some(format!("#{index}").as_ref()),
            auth,
            ConnectPointOptions::default(),
        )?),
        guard,
    ))
}

#[cfg(test)]
mod test {}
