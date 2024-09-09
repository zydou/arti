//! Declare RPC functionality on for the `arti-client` crate.

use derive_deftly::Deftly;
use dyn_clone::DynClone;
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
            @special client_connect_with_prefs::<R>,
            @special client_resolve_with_prefs::<R>,
            @special client_resolve_ptr_with_prefs::<R>,
        ]
    }
}

/// RPC method: Return the current ClientStatusInfo.
#[derive(Deftly, Debug, Serialize, Deserialize)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_client_status"))]
struct GetClientStatus {}

impl rpc::RpcMethod for GetClientStatus {
    type Output = ClientStatusInfo;
    type Update = rpc::NoUpdates;
}

/// RPC method: Run forever, delivering an updated view of the ClientStatusInfo whenever it changes.
///
/// (This method can return updates that have no visible changes.)
#[derive(Deftly, Debug, Serialize, Deserialize)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:watch_client_status"))]
struct WatchClientStatus {}

impl rpc::RpcMethod for WatchClientStatus {
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
    _ctx: Arc<dyn rpc::Context>,
) -> Result<ClientStatusInfo, rpc::RpcError> {
    Ok(client.bootstrap_status().into())
}

/// Invocable function to run [`WatchClientStatus`] on a [`TorClient`].
async fn watch_client_status<R: Runtime>(
    client: Arc<TorClient<R>>,
    _method: Box<WatchClientStatus>,
    _ctx: Arc<dyn rpc::Context>,
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
#[deftly(rpc(method_name = "arti:isolated_client"))]
#[non_exhaustive]
pub struct IsolatedClient {}

impl rpc::RpcMethod for IsolatedClient {
    type Output = rpc::SingletonId;
    type Update = rpc::NoUpdates;
}

/// RPC method implementation: return a new isolated client based on a given client.
async fn isolated_client<R: Runtime>(
    client: Arc<TorClient<R>>,
    _method: Box<IsolatedClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    let new_client = Arc::new(client.isolated_client());
    let client_id = ctx.register_owned(new_client);
    Ok(rpc::SingletonId::from(client_id))
}

/// Type-erased error returned by ClientConnectionTarget.
//
// TODO RPC: It would be handy if this implemented HasErrorHint, but HasErrorHint is sealed.
// Perhaps we could go and solve our problem by implementing HasErrorHint on dyn StdError?
pub trait ClientConnectionError:
    std::error::Error + tor_error::HasKind + DynClone + Send + Sync + seal::Sealed
{
}
impl<E> seal::Sealed for E where E: std::error::Error + tor_error::HasKind + DynClone + Send + Sync {}
impl<E> ClientConnectionError for E where
    E: std::error::Error + tor_error::HasKind + DynClone + Send + Sync + seal::Sealed
{
}
impl std::error::Error for Box<dyn ClientConnectionError> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.as_ref().source()
    }
}
impl tor_error::HasKind for Box<dyn ClientConnectionError> {
    fn kind(&self) -> tor_error::ErrorKind {
        self.as_ref().kind()
    }
}
dyn_clone::clone_trait_object!(ClientConnectionError);

/// module to seal the ClientConnectionError trait.
mod seal {
    /// hidden trait to seal the ClientConnectionError trait.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// Type alias for a Result return by ClientConnectionTarget
pub type ClientConnectionResult<T> = Result<T, Box<dyn ClientConnectionError>>;

/// RPC special method: make a connection to a chosen address and preferences.
///
/// This method has no method name, and is not invoked by an RPC session
/// directly.  Instead, it is invoked in response to a SOCKS request.
/// It receives its target from the SOCKS `DEST` field.
/// The isolation information in its `SrreamPrefs`, if any, is taken from
/// the SOCKS username/password.
/// Other information in the `StreamPrefs` is inferred
/// from the SOCKS port configuration in the usual way.
///
/// When this method returns successfully,
/// the proxy code sends a SOCKS reply indicating success,
/// and links the returned `DataStream` with the application's incoming socket,
/// copying data back and forth.
/// (The `DataStream`` need not actually be connected at this point;
/// an in-progress connection will work fine.
/// Tor calls such streams, which report readiness before receiving a CONNECTED,
/// "optimistic".)
///
/// If instead this method returns an error,
/// the error is either used to generate a SOCKS error code,
///
/// Note 1: in the future, this method will likely be used to integrate RPC data streams
/// with other proxy types other than SOCKS.
/// When this happens, we will specify how those proxy types
/// will provide `target` and `prefs`.
///
/// Note 2: This has to be a special method, because
/// it needs to return a DataStream, which can't be serialized.
///
/// > TODO RPC: The above documentation still isn't quite specific enough,
/// > and a lot of it belongs in socks.rs where it could explain how a SOCKS request
/// > is interpreted and converted into a ConnectWithPrefs call.
/// > See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2373#note_3071833>
/// > for discussion.
#[derive(Deftly, Debug)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(no_method_name))]
#[allow(clippy::exhaustive_structs)]
pub struct ConnectWithPrefs {
    /// The target address
    pub target: TorAddr,
    /// The stream preferences implied by the SOCKS connect request.
    pub prefs: StreamPrefs,
}
impl rpc::Method for ConnectWithPrefs {
    // TODO RPC: I am not sure that this is the error type we truly want.
    type Output = Result<DataStream, Box<dyn ClientConnectionError>>;
    type Update = rpc::NoUpdates;
}

/// RPC special method: lookup an address with a chosen address and preferences.
///
/// This method has no method name, and is not invoked by an RPC connection
/// directly.  Instead, it is invoked in response to a SOCKS request.
//
// TODO RPC: We _could_ give this a method name so that it can be invoked as an RPC method, and
// maybe we should.  First, however, we would need to make `StreamPrefs` an RPC-visible serializable
// type, or replace it with an equivalent.
#[derive(Deftly, Debug)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(no_method_name))]
#[allow(clippy::exhaustive_structs)]
pub struct ResolveWithPrefs {
    /// The hostname to resolve.
    pub hostname: String,
    /// The stream preferences implied by the SOCKS resolve request.
    pub prefs: StreamPrefs,
}
impl rpc::Method for ResolveWithPrefs {
    // TODO RPC: I am not sure that this is the error type we truly want.
    type Output = Result<Vec<IpAddr>, Box<dyn ClientConnectionError>>;
    type Update = rpc::NoUpdates;
}

/// RPC special method: reverse-lookup an address with a chosen address and preferences.
///
/// This method has no method name, and is not invoked by an RPC connection
/// directly.  Instead, it is invoked in response to a SOCKS request.
//
// TODO RPC: We _could_ give this a method name so that it can be invoked as an RPC method, and
// maybe we should.  First, however, we would need to make `StreamPrefs` an RPC-visible serializable
// type, or replace it with an equivalent.
#[derive(Deftly, Debug)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(no_method_name))]
#[allow(clippy::exhaustive_structs)]
pub struct ResolvePtrWithPrefs {
    /// The address to resolve.
    pub addr: IpAddr,
    /// The stream preferences implied by the SOCKS resolve request.
    pub prefs: StreamPrefs,
}
impl rpc::Method for ResolvePtrWithPrefs {
    // TODO RPC: I am not sure that this is the error type we truly want.
    type Output = Result<Vec<String>, Box<dyn ClientConnectionError>>;
    type Update = rpc::NoUpdates;
}

/// RPC method implementation: start a connection on a `TorClient`.
async fn client_connect_with_prefs<R: Runtime>(
    client: Arc<TorClient<R>>,
    method: Box<ConnectWithPrefs>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<DataStream, Box<dyn ClientConnectionError>> {
    TorClient::connect_with_prefs(client.as_ref(), &method.target, &method.prefs)
        .await
        .map_err(|e| Box::new(e) as _)
}

/// RPC method implementation: perform a remote DNS lookup using a `TorClient`.
async fn client_resolve_with_prefs<R: Runtime>(
    client: Arc<TorClient<R>>,
    method: Box<ResolveWithPrefs>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<Vec<IpAddr>, Box<dyn ClientConnectionError>> {
    TorClient::resolve_with_prefs(client.as_ref(), &method.hostname, &method.prefs)
        .await
        .map_err(|e| Box::new(e) as _)
}

/// RPC method implementation: perform a remote DNS reverse lookup using a `TorClient`.
async fn client_resolve_ptr_with_prefs<R: Runtime>(
    client: Arc<TorClient<R>>,
    method: Box<ResolvePtrWithPrefs>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<Vec<String>, Box<dyn ClientConnectionError>> {
    TorClient::resolve_ptr_with_prefs(client.as_ref(), method.addr, &method.prefs)
        .await
        .map_err(|e| Box::new(e) as _)
}
