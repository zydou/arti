//! High-level APIs for an RPC session
//!
//! A "session" is created when a user authenticates on an RPC connection.  It
//! is the root for all other RPC capabilities.

use arti_client::{
    rpc::{ClientConnectionResult, ConnectWithPrefs, ResolvePtrWithPrefs, ResolveWithPrefs},
    TorClient,
};
use derive_deftly::Deftly;
use std::{net::IpAddr, sync::Arc};
use tor_rtcompat::Runtime;

use tor_rpcbase::{self as rpc, static_rpc_invoke_fn, templates::*};

/// An authenticated RPC session: a capability through which most other RPC functionality is available
///
/// This relates to [`Connection`](crate::Connection) as follows:
///
///  * A `Connection` exists prior to authentication;
///    whereas an `RpcSession` comes into being as a result of authentication.
///
///  * The `RpcSession` is principally owned by the `Connection`'s object table.
///
///  * Typically, after authentication, there is one `RpcSession` for the `Connection`.
///    But a client may authenticate more than once; each time produces a new `RpcSession`.
#[derive(Deftly)]
#[derive_deftly(Object)]
#[deftly(rpc(expose_outside_of_session))]
pub struct RpcSession {
    /// An inner TorClient object that we use to implement remaining
    /// functionality.
    #[allow(unused)]
    client: Arc<dyn Client>,
}

/// Type-erased `TorClient``, as used within an RpcSession.
trait Client: rpc::Object {
    /// Return a new isolated TorClient.
    fn isolated_client(&self) -> Arc<dyn rpc::Object>;

    /// Upcast `self` to an rpc::Object.
    fn upcast_arc(self: Arc<Self>) -> Arc<dyn rpc::Object>;
}

impl<R: Runtime> Client for TorClient<R> {
    fn isolated_client(&self) -> Arc<dyn rpc::Object> {
        Arc::new(TorClient::isolated_client(self))
    }

    fn upcast_arc(self: Arc<Self>) -> Arc<dyn rpc::Object> {
        self
    }
}

impl RpcSession {
    /// Create a new session object containing a single client object.
    pub fn new_with_client<R: Runtime>(client: Arc<arti_client::TorClient<R>>) -> Arc<Self> {
        Arc::new(Self { client })
    }

    /// Return a view of the client associated with this session, as an `Arc<dyn
    /// rpc::Object>.`
    fn client_as_object(&self) -> Arc<dyn rpc::Object> {
        self.client.clone().upcast_arc()
    }
}

/// RPC method to release a single strong reference.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:release"))]
struct RpcRelease {
    /// The object to release. Must be a strong reference.
    ///
    /// TODO RPC: Releasing a weak reference is perilous and hard-to-define
    /// based on how we have implemented our object ids.  If you tell the objmap
    /// to "release" a single name for a weak reference, you are releasing every
    /// name for that weak reference, which may have surprising results.
    ///
    /// This might be a sign of a design problem.
    obj: rpc::ObjectId,
}
/// RPC method to release a single strong reference, creating a weak reference
/// in its place.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RpcDowngrade {
    /// The object to downgrade
    obj: rpc::ObjectId,
}

impl rpc::RpcMethod for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "release" on a Session.
async fn rpc_release(
    _obj: Arc<RpcSession>,
    method: Box<RpcRelease>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    ctx.release_owned(&method.obj)?;
    Ok(rpc::Nil::default())
}

/// A simple temporary method to echo a reply.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:x_echo"))]
struct Echo {
    /// A message to echo.
    msg: String,
}

impl rpc::RpcMethod for Echo {
    type Output = Echo;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "echo" on a Session.
///
/// TODO RPC: Remove this. It shouldn't exist.
async fn echo_on_session(
    _obj: Arc<RpcSession>,
    method: Box<Echo>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<Echo, rpc::RpcError> {
    Ok(*method)
}

/// An RPC method to return the default client for a session.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:get_client"))]
struct GetClient {}

impl rpc::RpcMethod for GetClient {
    type Output = rpc::SingletonId;
    type Update = rpc::NoUpdates;
}

/// Implement GetClient on an RpcSession.
async fn get_client_on_session(
    session: Arc<RpcSession>,
    _method: Box<GetClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    Ok(rpc::SingletonId::from(
        // TODO RPC: This relies (somewhat) on deduplication properties for register_owned.
        ctx.register_owned(session.client.clone().upcast_arc()),
    ))
}

/// Implement IsolatedClient on an RpcSession.
async fn isolated_client_on_session(
    session: Arc<RpcSession>,
    _method: Box<arti_client::rpc::IsolatedClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    let new_client = session.client.isolated_client();
    Ok(rpc::SingletonId::from(ctx.register_owned(new_client)))
}

/// Implement ConnectWithPrefs on an RpcSession
///
/// (Delegates to TorClient.)
async fn session_connect_with_prefs(
    session: Arc<RpcSession>,
    method: Box<ConnectWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<arti_client::DataStream> {
    *rpc::invoke_special_method(ctx, session.client_as_object(), method)
        .await
        .map_err(|e| Box::new(e) as _)?
}

/// Implement ResolveWithPrefs on an RpcSession
///
/// (Delegates to TorClient.)
async fn session_resolve_with_prefs(
    session: Arc<RpcSession>,
    method: Box<ResolveWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<Vec<IpAddr>> {
    *rpc::invoke_special_method(ctx, session.client_as_object(), method)
        .await
        .map_err(|e| Box::new(e) as _)?
}

/// Implement ResolvePtrWithPrefs on an RpcSession
///
/// (Delegates to TorClient.)
async fn session_resolve_ptr_with_prefs(
    session: Arc<RpcSession>,
    method: Box<ResolvePtrWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<Vec<String>> {
    *rpc::invoke_special_method(ctx, session.client_as_object(), method)
        .await
        .map_err(|e| Box::new(e) as _)?
}

static_rpc_invoke_fn! {
    rpc_release;
    echo_on_session;
    get_client_on_session;
    isolated_client_on_session;
    @special session_connect_with_prefs;
    @special session_resolve_with_prefs;
    @special session_resolve_ptr_with_prefs;
}
