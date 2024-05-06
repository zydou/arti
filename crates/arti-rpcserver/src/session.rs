//! High-level APIs for an RPC session
//!
//! A "session" is created when a user authenticates on an RPC connection.  It
//! is the root for all other RPC capabilities.

use arti_client::TorClient;
use derive_deftly::Deftly;
use std::sync::Arc;
use tor_rtcompat::Runtime;

use tor_rpcbase as rpc;
use tor_rpcbase::templates::*;

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
pub struct RpcSession<R: Runtime> {
    /// An inner TorClient object that we use to implement remaining
    /// functionality.
    #[allow(unused)]
    client: Arc<TorClient<R>>,
}

impl<R: Runtime> RpcSession<R> {
    /// Create a new session object containing a single client object.
    pub fn new_with_client(client: Arc<arti_client::TorClient<R>>) -> Arc<Self> {
        Arc::new(Self { client })
    }

    /// Ensure that every RPC method is registered for this instantiation of TorClient.
    ///
    /// We can't use [`rpc::static_rpc_invoke_fn`] for these, since TorClient is
    /// parameterized.
    pub fn rpc_methods() -> Vec<rpc::dispatch::InvokerEnt> {
        rpc::invoker_ent_list![rpc_release::<R>, echo_on_session::<R>]
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

impl rpc::Method for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "release" on a Session.
async fn rpc_release<R: Runtime>(
    _obj: Arc<RpcSession<R>>,
    method: Box<RpcRelease>,
    ctx: Box<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    ctx.release_owned(&method.obj)?;
    Ok(rpc::Nil::default())
}

/// A simple temporary method to echo a reply.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:x-echo"))]
struct Echo {
    /// A message to echo.
    msg: String,
}

impl rpc::Method for Echo {
    type Output = Echo;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "echo" on a Session.
///
/// TODO RPC: Remove this. It shouldn't exist.
async fn echo_on_session<R: Runtime>(
    _obj: Arc<RpcSession<R>>,
    method: Box<Echo>,
    _ctx: Box<dyn rpc::Context>,
) -> Result<Echo, rpc::RpcError> {
    Ok(*method)
}
