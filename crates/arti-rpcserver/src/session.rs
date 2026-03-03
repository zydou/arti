//! High-level APIs for an RPC session
//!
//! A "session" is created when a user authenticates on an RPC connection.  It
//! is the root for all other RPC capabilities.

use arti_client::{
    TorClient,
    rpc::{ClientConnectionResult, ConnectWithPrefs, ResolvePtrWithPrefs, ResolveWithPrefs},
};
use derive_deftly::Deftly;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
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

    /// A superuser object representing administrative capability.
    ///
    /// If this object is absent, this session never had this capability,
    /// or dropped it.
    superuser: Mutex<Option<Arc<dyn rpc::Object>>>,
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
        Arc::new(Self {
            client,
            superuser: Mutex::new(None),
        })
    }

    /// Set the superuser object for this session to `superuser`.
    ///
    /// Calling this function indicates that this session has administrative privilege.
    pub fn provide_superuser_permission(&self, superuser: Arc<dyn rpc::Object>) {
        let mut su = self.superuser.lock().expect("Poisoned lock");
        *su = Some(superuser);
    }

    /// Return a view of the client associated with this session, as an `Arc<dyn
    /// rpc::Object>.`
    fn client_as_object(&self) -> Arc<dyn rpc::Object> {
        self.client.clone().upcast_arc()
    }
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

/// Return the superuser capability for a session.
///
/// Just as a session is the root object proving that
/// your program has authenticated
///
/// Returns an error if this session is not authorized for superuser access,
/// or if you have dropped superuser access via `arti:remove_superuser_permission`.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:get_superuser_capability"))]
struct GetSuperuserCapability {}

impl rpc::RpcMethod for GetSuperuserCapability {
    type Output = rpc::SingleIdResponse;
    type Update = rpc::NoUpdates;
}

/// Implement `arti::get_superuser_capability` on RpcSession.
async fn get_superuser_capability_on_session(
    session: Arc<RpcSession>,
    _method: Box<GetSuperuserCapability>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    let opt_su = session.superuser.lock().expect("Lock poisoned");
    match opt_su.as_ref() {
        Some(su) => {
            let su = Arc::clone(su);
            drop(opt_su);
            let id = ctx.register_owned(su);
            Ok(id.into())
        }
        None => Err(rpc::RpcError::new(
            "Superuser access not permitted on this session".into(),
            rpc::RpcErrorKind::RequestError,
        )),
    }
}

/// Remove the superuser permission from a session.
///
/// Calling this method on a session ensures that future calls to
/// `arti:get_superuser_capability` will return an error.`
///
/// This method does nothing if the session did not have superuser access.
///
/// This method does not drop existing superuser capability objects
/// previously returned from `arti:get_superuser_capability`,
/// or other privileged objects derived from them.
///
/// Additionally, it does not prevent you from from using `auth`
/// methods to create a new session from the same connection object.
///
/// Therefore, to ensure that you cannot acquire new superuser functionality
/// on a given connection, you must:
/// - Drop any existing superuser capabilities.
/// - Invoke this method on the session.
///
/// To ensure that an _application_ cannot reacquire superuser permission,
/// you also must prevent it from opening a new RPC connection to any
/// Arti RPC connect point that allows superuser access.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:remove_superuser_permission"))]
struct RemoveSuperuserPermission {}

impl rpc::RpcMethod for RemoveSuperuserPermission {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implement `arti::remove_superuser_permission` on RpcSession.
async fn remove_superuser_permission_on_session(
    session: Arc<RpcSession>,
    _method: Box<RemoveSuperuserPermission>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    let mut opt_su = session.superuser.lock().expect("Lock poisoned");
    *opt_su = None;
    Ok(rpc::Nil::default())
}

static_rpc_invoke_fn! {
    get_client_on_session;
    isolated_client_on_session;
    get_superuser_capability_on_session;
    remove_superuser_permission_on_session;
    @special session_connect_with_prefs;
    @special session_resolve_with_prefs;
    @special session_resolve_ptr_with_prefs;
}

#[cfg(feature = "describe-methods")]
#[allow(clippy::missing_docs_in_private_items)] // TODO
mod list_all_methods {
    use std::{convert::Infallible, sync::Arc};

    use derive_deftly::Deftly;
    use tor_rpcbase::{self as rpc, RpcDispatchInformation, static_rpc_invoke_fn, templates::*};

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
