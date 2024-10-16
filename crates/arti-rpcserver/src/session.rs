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
use tor_error::into_internal;
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
///
/// ## In the arti rpc system
///
/// Base type for an authenticated RPC session.
///
/// Upon successful authentication via `auth:authenticate`,
/// a connection will return either a Session object of this type,
/// or a Session object that wraps this type.
/// All other useful objects are available via an RPC session.
///
/// This ObjectID for this object can be used as the target of a SOCKS stream.
#[derive(Deftly)]
#[derive_deftly(Object)]
#[deftly(rpc(expose_outside_of_session))]
pub struct RpcSession {
    /// An inner TorClient object that we use to implement remaining
    /// functionality.
    #[allow(unused)]
    client: Arc<dyn Client>,
}

/// Type-erased `TorClient`, as used within an RpcSession.
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

/// Return the default client for a session.
///
/// Allocates a new ObjectID,
/// but does not create a new underlying client object.
///
/// The returned ObjectID is a handle to a `TorClient`.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:get_client"))]
struct GetClient {}

impl rpc::RpcMethod for GetClient {
    type Output = rpc::SingleIdResponse;
    type Update = rpc::NoUpdates;
}

/// Implement GetClient on an RpcSession.
async fn get_client_on_session(
    session: Arc<RpcSession>,
    _method: Box<GetClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    Ok(rpc::SingleIdResponse::from(
        // TODO RPC: This relies (somewhat) on deduplication properties for register_owned.
        ctx.register_owned(session.client.clone().upcast_arc()),
    ))
}

/// Implement IsolatedClient on an RpcSession.
async fn isolated_client_on_session(
    session: Arc<RpcSession>,
    _method: Box<arti_client::rpc::IsolatedClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    let new_client = session.client.isolated_client();
    Ok(rpc::SingleIdResponse::from(ctx.register_owned(new_client)))
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
        .map_err(|e| Box::new(into_internal!("unable to delegate to TorClient")(e)) as _)?
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
        .map_err(|e| Box::new(into_internal!("unable to delegate to TorClient")(e)) as _)?
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
        .map_err(|e| Box::new(into_internal!("unable to delegate to TorClient")(e)) as _)?
}
static_rpc_invoke_fn! {
    get_client_on_session;
    isolated_client_on_session;
    @special session_connect_with_prefs;
    @special session_resolve_with_prefs;
    @special session_resolve_ptr_with_prefs;
}

#[cfg(feature = "describe-methods")]
mod list_all_methods {
    use std::{convert::Infallible, sync::Arc};

    use derive_deftly::Deftly;
    use tor_rpcbase::{self as rpc, static_rpc_invoke_fn, templates::*, RpcDispatchInformation};

    /// Return a description of all recognized RPC methods.
    ///
    /// Note that not every recognized method is necessarily invocable in practice.
    /// Depending on the session's access level, you might not be able to
    /// access any objects that the method might be invocable upon.
    ///
    /// **This is an experimental method.**
    /// Methods starting with "x_" are extra-unstable.
    /// See [`RpcDispatchInformation`] for caveats about type names.
    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "arti:x_list_all_rpc_methods"))]
    struct ListAllRpcMethods {}

    impl rpc::RpcMethod for ListAllRpcMethods {
        type Output = RpcDispatchInformation;
        type Update = rpc::NoUpdates;
    }

    /// Implement ListAllRpcMethods on an RpcSession.
    async fn session_list_all_rpc_methods(
        _session: Arc<super::RpcSession>,
        _method: Box<ListAllRpcMethods>,
        ctx: Arc<dyn rpc::Context>,
    ) -> Result<RpcDispatchInformation, Infallible> {
        Ok(ctx
            .dispatch_table()
            .read()
            .expect("poisoned lock")
            .dispatch_information())
    }

    static_rpc_invoke_fn! { session_list_all_rpc_methods; }
}
