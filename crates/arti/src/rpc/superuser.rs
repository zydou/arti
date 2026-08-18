//! Administrative RPC functionality.
//!
//! In general, RPC function is "administrative", and requires superuser access,
//! whenever it can affect other applications.
//!
//! This is not a perfect sandbox: applications can _always_ interfere with one another's traffic by
//! consuming resources (like bandwidth or CPU) in a way that introduces side channels.

use arti_client::{TorClient, rpc::ClientStatusInfo};
use derive_deftly::Deftly;
use futures::{FutureExt as _, SinkExt as _, StreamExt as _, select_biased};
use std::sync::Arc;
use tor_rpcbase::{self as rpc};
use tor_rtcompat::Runtime;

use crate::reload_cfg::{CfgMgr, LaunchableTorClient};

/// An object representing superuser access to Arti over an RPC session.
///
/// In general, RPC function is "administrative", and requires superuser access,
/// whenever it can affect other applications.
#[derive(Deftly)]
#[derive_deftly(rpc::Object)]
pub(super) struct RpcSuperuser<R: Runtime> {
    /// A view of the underlying TorClient managed by this RpcSuperuser object.
    tor_client: Arc<TorClient<R>>,

    /// A wrapper around `tor_client` with the ability to launch a deferred-bootstrap client.
    launchable: Arc<LaunchableTorClient<R>>,

    /// A handle to the manager for configuration information.
    #[allow(unused)] // TODO(rpc) remove
    cfg_mgr: Arc<CfgMgr<R>>,
}

impl<R: Runtime> RpcSuperuser<R> {
    /// Construct a new RpcSuperuser object.
    pub(super) fn new(
        tor_client: Arc<TorClient<R>>,
        launchable: Arc<LaunchableTorClient<R>>,
        cfg_mgr: Arc<CfgMgr<R>>,
    ) -> Self {
        RpcSuperuser {
            tor_client,
            launchable,
            cfg_mgr,
        }
    }

    /// Ensure that every RPC method is registered for this instantiation of TorClient.
    ///
    /// We can't use [`rpc::static_rpc_invoke_fn`] for these, since TorClient is
    /// parameterized.
    pub(super) fn rpc_methods() -> Vec<rpc::dispatch::InvokerEnt> {
        rpc::invoker_ent_list![
            enter_dormant_mode_on_rpcsuperuser::<R>,
            bootstrap_client_on_rpcsuperuser::<R>,
        ]
    }
}

/// Enter "dormant mode".
///
/// Currently, the only available dormant mode is "soft dormant mode",
/// which suspends most background operations until any client request
/// is received.
///
/// Since this method affects all applications using the Arti process,
/// it requires administrative permissions.
///
/// ## Limitations
///
/// As of 2026 March, this functionality is not perfectly implemented,
/// and likely does not interact well with onion services.
/// Additionally, there are likely background operations that
/// this operation doesn't cover.
///
/// This method returns a reply immediately, but it may take a little
/// while before all of the background tasks finish their work and stop.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:enter_dormant_mode"))]
struct EnterDormantMode {}

impl rpc::RpcMethod for EnterDormantMode {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implementation for [`EnterDormantMode`] on [`RpcSuperuser`].
async fn enter_dormant_mode_on_rpcsuperuser<R: Runtime>(
    session: Arc<RpcSuperuser<R>>,
    _method: Box<EnterDormantMode>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    use arti_client::DormantMode;
    session.tor_client.set_dormant(DormantMode::Soft);
    Ok(rpc::Nil::default())
}

/// Tell a client to connect to the network and bootstrap itself.
///
/// There is no need to invoke this method unless
/// was started with the `application.defer_bootstrap` option set to true.
/// By default, clients will automatically connect to the network and bootstrap
/// themselves.
///
/// Since this method affects all applications using the Arti process,
/// it requires administrative permissions.  We may someday relax this
/// property.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:bootstrap_client"))]
struct BootstrapClient {}

impl rpc::RpcMethod for BootstrapClient {
    type Output = rpc::Nil;
    type Update = ClientStatusInfo;
}

/// Implementation for [`BootstrapClient`] on [`RpcSuperuser`].
async fn bootstrap_client_on_rpcsuperuser<R: Runtime>(
    session: Arc<RpcSuperuser<R>>,
    _method: Box<BootstrapClient>,
    _ctx: Arc<dyn rpc::Context>,
    mut updates: rpc::UpdateSink<ClientStatusInfo>,
) -> Result<rpc::Nil, rpc::RpcError> {
    let mut events = session.tor_client.bootstrap_events().fuse();
    // Send the initial status unconditionally.
    updates
        .send(session.tor_client.bootstrap_status().into())
        .await?;

    let mut bootstrap = Box::pin(session.launchable.bootstrap()).fuse();

    loop {
        select_biased! {
            outcome = bootstrap => {
                 let () = outcome?;
                 return Ok(rpc::Nil::default());
            }
            e = events.next() => {
                // (If this returns None, then the `outcome` is about to fail.)
                if let Some(e) = e {
                    let status = e.into();
                    let _ignore_failure = updates.send(status).await;
                }
            }
        };
    }
}
