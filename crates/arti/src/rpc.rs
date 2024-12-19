//! Experimental RPC support.

use anyhow::Result;
use arti_rpcserver::RpcMgr;
use derive_builder::Builder;
use fs_mistrust::Mistrust;
use futures::{stream::StreamExt, task::SpawnExt, AsyncReadExt};
use listener::{RpcListenerMap, RpcListenerMapBuilder};
use serde::{Deserialize, Serialize};
use session::ArtiRpcSession;
use std::{io::Result as IoResult, sync::Arc};
use tor_config::{define_list_builder_helper, impl_standard_builder, ConfigBuildError};
use tor_config_path::CfgPathResolver;
use tor_rpc_connect::auth::RpcAuth;
use tracing::{debug, info};

use arti_client::TorClient;
use tor_rtcompat::{general, NetStreamListener as _, Runtime};

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

    /// A list of default connect points to bind if none are found under `listen`.
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
async fn launch_all_listeners<R: Runtime>(
    runtime: &R,
    cfg: &RpcConfig,
    resolver: &CfgPathResolver,
    mistrust: &Mistrust,
) -> anyhow::Result<(
    impl futures::Stream<Item = IoResult<IncomingConn>> + Unpin,
    Vec<tor_rpc_connect::server::ListenerGuard>,
)> {
    let mut listeners = Vec::new();
    let mut guards = Vec::new();
    for (name, listener_cfg) in cfg.listen.iter() {
        for (lis, info, guard) in listener_cfg
            .bind(runtime, name.as_str(), resolver, mistrust)
            .await?
        {
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
            let (lis, info, guard) =
                listener::bind_string(connpt, idx + 1, runtime, resolver, mistrust).await?;
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
) -> Result<Option<(Arc<RpcMgr>, RpcStateSender)>> {
    if !cfg.enable {
        return Ok(None);
    }
    let (rpc_state, rpc_state_sender) = RpcVisibleArtiState::new();

    // TODO RPC: there should be an error return instead.
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
    Ok(Some((rpc_mgr, rpc_state_sender)))
}

/// Backend function to implement an RPC listener: runs in a loop.
async fn run_rpc_listener<R: Runtime>(
    runtime: R,
    mut incoming: impl futures::Stream<Item = IoResult<IncomingConn>> + Unpin,
    rpc_mgr: Arc<RpcMgr>,
) -> Result<()> {
    while let Some((stream, _addr, info)) = incoming.next().await.transpose()? {
        // TODO RPC: Perhaps we should have rpcmgr hold the client reference?
        // TODO RPC: We'll need to pass info (or part of it?) to rpc_mgr.
        debug!("Received incoming RPC connection from {}", &info.name);

        match info.auth {
            RpcAuth::None => {
                // "None" auth works trivially; there's nothing to do.
            }
            _ => {
                // TODO RPC: implement cookie auth, and reject other auth types earlier.
                debug!("Dropping RPC connection; auth type is not supported");
                continue;
            }
        }

        let connection = rpc_mgr.new_connection();
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
}
