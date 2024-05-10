//! Declare RPC functionality on for the `arti-client` crate.

use async_trait::async_trait;
use derive_deftly::Deftly;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tor_proto::stream::DataStream;

use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

use crate::{StreamPrefs, TorAddr, TorClient};

impl<R: Runtime> TorClient<R> {
    /// Ensure that every RPC method is registered for this instantiation of TorClient.
    ///
    /// We can't use [`rpc::static_rpc_invoke_fn`] for these, since TorClient is
    /// parameterized.
    pub fn rpc_methods() -> Vec<rpc::dispatch::InvokerEnt> {
        rpc::invoker_ent_list![
            get_client_status::<R>,
            watch_client_status::<R>,
            isolated_client::<R>,
        ]
    }
}

/// RPC method: Return the current ClientStatusInfo.
#[derive(Deftly, Debug, Serialize, Deserialize)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get-client-status"))]
struct GetClientStatus {}

impl rpc::Method for GetClientStatus {
    type Output = ClientStatusInfo;
    type Update = rpc::NoUpdates;
}

/// RPC method: Run forever, delivering an updated view of the ClientStatusInfo whenever it changes.
///
/// (This method can return updates that have no visible changes.)
#[derive(Deftly, Debug, Serialize, Deserialize)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:watch-client-status"))]
struct WatchClientStatus {}

impl rpc::Method for WatchClientStatus {
    type Output = rpc::Nil;
    type Update = ClientStatusInfo;
}

/// RPC result: The reported status of a TorClient.
#[derive(Serialize, Deserialize)]
struct ClientStatusInfo {
    /// True if the client is ready for traffic.
    ready: bool,
    /// Approximate estimate of how close the client is to being ready for traffic.
    fraction: f32,
    /// If present, a description of possible problem(s) that may be stopping
    /// the client from using the Tor network.
    blocked: Option<String>,
}

impl From<crate::status::BootstrapStatus> for ClientStatusInfo {
    fn from(s: crate::status::BootstrapStatus) -> Self {
        let ready = s.ready_for_traffic();
        let fraction = s.as_frac();
        let blocked = s.blocked().map(|b| b.to_string());
        Self {
            ready,
            fraction,
            blocked,
        }
    }
}

// NOTE: These functions could be defined as methods on TorClient<R>.
// I'm defining them like this to make it more clear that they are never
// invoked as client.method(), but only via the RPC system.
// We can revisit this later if we want.

// TODO RPC: Once we have one or two more get/watch combinations,
// we should look into some facility for automatically declaring them,
// so that their behavior stays uniform.
//
// See https://gitlab.torproject.org/tpo/core/arti/-/issues/1384#note_3023659

/// Invocable function to run [`GetClientStatus`] on a [`TorClient`].
async fn get_client_status<R: Runtime>(
    client: Arc<TorClient<R>>,
    _method: Box<GetClientStatus>,
    _ctx: Box<dyn rpc::Context>,
) -> Result<ClientStatusInfo, rpc::RpcError> {
    Ok(client.bootstrap_status().into())
}

/// Invocable function to run [`WatchClientStatus`] on a [`TorClient`].
async fn watch_client_status<R: Runtime>(
    client: Arc<TorClient<R>>,
    _method: Box<WatchClientStatus>,
    _ctx: Box<dyn rpc::Context>,
    mut updates: rpc::UpdateSink<ClientStatusInfo>,
) -> Result<rpc::Nil, rpc::RpcError> {
    let mut events = client.bootstrap_events();

    // Send the _current_ status, no matter what.
    // (We do this after constructing er)
    updates.send(client.bootstrap_status().into()).await?;

    // Send additional updates whenever the status changes.
    while let Some(status) = events.next().await {
        updates.send(status.into()).await?;
    }

    // This can only happen if the client exits.
    Ok(rpc::NIL)
}

/// RPC method: Return an owned ID for a new isolated client instance.
#[derive(Deftly, Debug, Serialize, Deserialize)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti::isolated-client"))]
#[non_exhaustive]
pub struct IsolatedClient {}

impl rpc::Method for IsolatedClient {
    type Output = rpc::SingletonId;
    type Update = rpc::NoUpdates;
}

/// RPC method implementation: return a new isolated client based on a given client.
async fn isolated_client<R: Runtime>(
    client: Arc<TorClient<R>>,
    _method: Box<IsolatedClient>,
    ctx: Box<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    let new_client = Arc::new(client.isolated_client());
    let client_id = ctx.register_owned(new_client);
    Ok(rpc::SingletonId::from(client_id))
}

/// Type-erased error returned by ClientConnectionTarget.
pub trait ClientConnectionError: std::error::Error + tor_error::HasKind + Send + Sync {}
impl<E> ClientConnectionError for E where E: std::error::Error + tor_error::HasKind + Send + Sync {}
impl std::error::Error for Box<dyn ClientConnectionError> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.as_ref().source()
    }
}

/// Type alias for a Result return by ClientConnectionTarget
pub type ClientConnectionResult<T> = Result<T, Box<dyn ClientConnectionError>>;

/// An RPC-visible object that can be used as the target of SOCKS operations,
/// or other application-level connection attempts.
///
/// Only the RPC subsystem should use this type.
//
// TODO RPC: Conceivably, we would like to apply this trait to types in lower-level crates: for
// example, we could put it onto ClientCirc, and let the application launch streams on a circuit
// directly.  But if we did that, we wouldn't be able to downcast an ClientCirc from Arc<dyn Object>
// to this trait. Perhaps we need a clever solution.
//
// TODO RPC: This trait, along with ClientConnection{Error,Result},  have names that are just too
// long.
#[async_trait]
pub trait ClientConnectionTarget: Send + Sync {
    /// As [`TorClient::connect_with_prefs`].
    async fn connect_with_prefs(
        &self,
        target: &TorAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<DataStream>;

    /// As [`TorClient::resolve_with_prefs`].
    async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<IpAddr>>;

    /// As [`TorClient::resolve_ptr_with_prefs`].
    async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<String>>;
}

#[async_trait]
impl<R: Runtime> ClientConnectionTarget for TorClient<R> {
    async fn connect_with_prefs(
        &self,
        target: &TorAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<DataStream> {
        TorClient::connect_with_prefs(self, target, prefs)
            .await
            .map_err(|e| Box::new(e) as _)
    }
    async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<IpAddr>> {
        TorClient::resolve_with_prefs(self, hostname, prefs)
            .await
            .map_err(|e| Box::new(e) as _)
    }
    async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<String>> {
        TorClient::resolve_ptr_with_prefs(self, addr, prefs)
            .await
            .map_err(|e| Box::new(e) as _)
    }
}
