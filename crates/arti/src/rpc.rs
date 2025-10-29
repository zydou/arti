//! Experimental RPC support.

use anyhow::Result;
use arti_rpcserver::RpcMgr;
use derive_builder::Builder;
use fs_mistrust::Mistrust;
use futures::{AsyncReadExt, stream::StreamExt, task::SpawnExt};
use listener::{RpcListenerMap, RpcListenerMapBuilder};
use serde::{Deserialize, Serialize};
use session::ArtiRpcSession;
use std::{io::Result as IoResult, sync::Arc};
use tor_config::{ConfigBuildError, define_list_builder_helper, impl_standard_builder};
use tor_config_path::CfgPathResolver;
use tracing::{debug, info};

use arti_client::TorClient;
use tor_rtcompat::{NetStreamListener as _, Runtime, general};

pub(crate) mod conntarget;
pub(crate) mod listener;
mod proxyinfo;
mod session;

pub(crate) use session::{RpcStateSender, RpcVisibleArtiState};

/// Configuration for Arti's RPC subsystem.
///
/// You cannot change this section on a running Arti client.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder_struct_attr(non_exhaustive)]
#[non_exhaustive]
pub struct RpcConfig {
    /// If true, then the RPC subsystem is enabled and will listen for connections.
    #[builder(default = "false")] // TODO RPC make this true once we are stable.
    enable: bool,

    /// A set of named locations in which to find connect files.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    listen: RpcListenerMap,

    /// A list of default connect points to bind
    /// if no enabled connect points are found under `listen`.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    listen_default: ListenDefaults,
}
impl_standard_builder! { RpcConfig }

/// Type alias to enable sub_builder to work.
type ListenDefaults = Vec<String>;

define_list_builder_helper! {
    pub struct ListenDefaultsBuilder {
        values: [String],
    }
    built: Vec<String> = values;
    default = listen_defaults_defaults();
    item_build: |item| Ok(item.clone());
}

/// Return default values for `RpcConfig.listen_default`
fn listen_defaults_defaults() -> Vec<String> {
    vec![tor_rpc_connect::USER_DEFAULT_CONNECT_POINT.to_string()]
}

/// Information about an incoming connection.
///
/// Yielded in a stream from our RPC listeners.
type IncomingConn = (
    general::Stream,
    general::SocketAddr,
    Arc<listener::RpcConnInfo>,
);

/// Bind to all configured RPC listeners in `cfg`.
///
/// On success, return a stream of `IncomingConn`.
#[allow(clippy::cognitive_complexity)] // TODO: Refactor?
async fn launch_all_listeners<R: Runtime>(
    runtime: &R,
    cfg: &RpcConfig,
    resolver: &CfgPathResolver,
    mistrust: &Mistrust,
) -> anyhow::Result<(
    impl futures::Stream<Item = IoResult<IncomingConn>> + Unpin + use<R>,
    Vec<tor_rpc_connect::server::ListenerGuard>,
)> {
    let mut listeners = Vec::new();
    let mut guards = Vec::new();
    for (name, listener_cfg) in cfg.listen.iter() {
        for (lis, info, guard) in listener_cfg
            .bind(runtime, name.as_str(), resolver, mistrust)
            .await?
        {
            // (Note that `bind` only returns enabled listeners, so we don't need to check here.
            debug!(
                "Listening at {} for {}",
                lis.local_addr()
                    .expect("general::listener without address?")
                    .display_lossy(),
                info.name,
            );
            listeners.push((lis, info));
            guards.push(guard);
        }
    }
    if listeners.is_empty() {
        for (idx, connpt) in cfg.listen_default.iter().enumerate() {
            let display_index = idx + 1; // One-indexed values are more human-readable.
            let (lis, info, guard) =
                listener::bind_string(connpt, display_index, runtime, resolver, mistrust).await?;
            debug!(
                "Listening at {} for {}",
                lis.local_addr()
                    .expect("general::listener without address?")
                    .display_lossy(),
                info.name,
            );
            listeners.push((lis, info));
            guards.push(guard);
        }
    }
    if listeners.is_empty() {
        info!("No RPC listeners configured.");
    }

    let streams = listeners.into_iter().map(|(listener, info)| {
        listener
            .incoming()
            .map(move |accept_result| match accept_result {
                Ok((netstream, addr)) => Ok((netstream, addr, Arc::clone(&info))),
                Err(e) => Err(e),
            })
    });

    Ok((futures::stream::select_all(streams), guards))
}

/// Create an RPC manager, bind to connect points, and open a listener task to accept incoming
/// RPC connections.
pub(crate) async fn launch_rpc_mgr<R: Runtime>(
    runtime: &R,
    cfg: &RpcConfig,
    resolver: &CfgPathResolver,
    mistrust: &Mistrust,
    client: TorClient<R>,
) -> Result<Option<RpcProxySupport>> {
    if !cfg.enable {
        return Ok(None);
    }
    let (rpc_state, rpc_state_sender) = RpcVisibleArtiState::new();

    let rpc_mgr = RpcMgr::new(move |auth| ArtiRpcSession::new(auth, &client, &rpc_state))?;
    // Register methods. Needed since TorClient is generic.
    //
    // TODO: If we accumulate a large number of generics like this, we should do this elsewhere.
    rpc_mgr.register_rpc_methods(TorClient::<R>::rpc_methods());
    rpc_mgr.register_rpc_methods(arti_rpcserver::rpc_methods::<R>());

    let rt_clone = runtime.clone();
    let rpc_mgr_clone = rpc_mgr.clone();

    let (incoming, guards) = launch_all_listeners(runtime, cfg, resolver, mistrust).await?;

    // TODO: Using spawn in this way makes it hard to report whether we
    // succeeded or not. This is something we should fix when we refactor
    // our service-launching code.
    runtime.spawn(async move {
        let result = run_rpc_listener(rt_clone, incoming, rpc_mgr_clone).await;
        if let Err(e) = result {
            tracing::warn!("RPC manager quit with an error: {}", e);
        }
        drop(guards);
    })?;
    Ok(Some(RpcProxySupport {
        rpc_mgr,
        rpc_state_sender,
    }))
}

/// Backend function to implement an RPC listener: runs in a loop.
async fn run_rpc_listener<R: Runtime>(
    runtime: R,
    mut incoming: impl futures::Stream<Item = IoResult<IncomingConn>> + Unpin,
    rpc_mgr: Arc<RpcMgr>,
) -> Result<()> {
    while let Some((stream, _addr, info)) = incoming.next().await.transpose()? {
        debug!("Received incoming RPC connection from {}", &info.name);

        let connection = rpc_mgr.new_connection(info.auth.clone());
        let (input, output) = stream.split();

        runtime.spawn(async {
            let result = connection.run(input, output).await;
            if let Err(e) = result {
                tracing::warn!("RPC session ended with an error: {}", e);
            }
        })?;
    }
    Ok(())
}

/// Information passed to a proxy or similar stream provider when running with RPC support.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct RpcProxySupport {
    /// An RPC manager to use for looking up objects as possible stream targets.
    pub(crate) rpc_mgr: Arc<arti_rpcserver::RpcMgr>,
    /// An RPCStateSender to use for registering the list of known proxy ports.
    pub(crate) rpc_state_sender: RpcStateSender,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use listener::{ConnectPointOptionsBuilder, RpcListenerSetConfigBuilder};
    use tor_config_path::CfgPath;
    use tor_rpc_connect::ParsedConnectPoint;

    use super::*;

    #[test]
    fn rpc_method_names() {
        // We run this from a nice high level module, to ensure that as many method names as
        // possible will be in-scope.
        let problems = tor_rpcbase::check_method_names([]);

        for (m, err) in &problems {
            eprintln!("Bad method name {m:?}: {err}");
        }
        assert!(problems.is_empty());
    }

    #[test]
    fn parse_listener_defaults() {
        for string in listen_defaults_defaults() {
            let _parsed: ParsedConnectPoint = string.parse().unwrap();
        }
    }

    #[test]
    fn parsing_and_building() {
        fn build(s: &str) -> Result<RpcConfig, anyhow::Error> {
            let b: RpcConfigBuilder = toml::from_str(s)?;
            Ok(b.build()?)
        }

        let mut user_defaults_builder = RpcListenerSetConfigBuilder::default();
        user_defaults_builder.listener_options().enable(true);
        user_defaults_builder.dir(CfgPath::new("${ARTI_LOCAL_DATA}/rpc/connect.d".to_string()));
        let mut system_defaults_builder = RpcListenerSetConfigBuilder::default();
        system_defaults_builder.listener_options().enable(false);
        system_defaults_builder.dir(CfgPath::new("/etc/arti-rpc/connect.d".to_string()));

        // Make sure that an empty configuration gets us the defaults.
        let defaults = build("").unwrap();
        assert_eq!(
            defaults,
            RpcConfig {
                enable: false,
                listen: vec![
                    (
                        "user-default".to_string(),
                        user_defaults_builder.build().unwrap()
                    ),
                    (
                        "system-default".to_string(),
                        system_defaults_builder.build().unwrap()
                    ),
                ]
                .into_iter()
                .collect(),
                listen_default: listen_defaults_defaults()
            }
        );

        // Make sure that overriding specific options works as expected.
        let altered = build(
            r#"
[listen."user-default"]
enable = false
[listen."system-default"]
dir = "/usr/local/etc/arti-rpc/connect.d"
file_options = { "tmp.toml" = { "enable" = false } }
[listen."my-connpt"]
file = "/home/dante/.paradiso/connpt.toml"
"#,
        )
        .unwrap();
        let mut altered_user_defaults = user_defaults_builder.clone();
        altered_user_defaults.listener_options().enable(false);
        let mut altered_system_defaults = system_defaults_builder.clone();
        altered_system_defaults.dir(CfgPath::new(
            "/usr/local/etc/arti-rpc/connect.d".to_string(),
        ));
        let mut opt = ConnectPointOptionsBuilder::default();
        opt.enable(false);
        altered_system_defaults
            .file_options()
            .insert("tmp.toml".to_string(), opt);
        let mut my_connpt = RpcListenerSetConfigBuilder::default();
        my_connpt.file(CfgPath::new(
            "/home/dante/.paradiso/connpt.toml".to_string(),
        ));

        assert_eq!(
            altered,
            RpcConfig {
                enable: false,
                listen: vec![
                    (
                        "user-default".to_string(),
                        altered_user_defaults.build().unwrap()
                    ),
                    (
                        "system-default".to_string(),
                        altered_system_defaults.build().unwrap()
                    ),
                    ("my-connpt".to_string(), my_connpt.build().unwrap()),
                ]
                .into_iter()
                .collect(),
                listen_default: listen_defaults_defaults()
            }
        );
    }
}
