//! High-level APIs for an RPC session
//!
//! A "session" is created when a user authenticates on an RPC connection.  It
//! is the root for all other RPC capabilities.

use std::sync::Arc;

use tor_rpcbase as rpc;

/// An authenticated RPC session.
pub(crate) struct Session {
    /// An inner TorClient object that we use to implement remaining
    /// functionality.
    #[allow(unused)]
    client: Arc<dyn rpc::Object>,
}
impl rpc::Object for Session {
    fn expose_outside_of_session(&self) -> bool {
        // A session object can bue used to open a connection to its underlying
        // client, so it needs to be exported.
        true
    }
}
rpc::decl_object! {Session}

impl Session {
    /// Create a new session object.
    pub(crate) fn new(client: Arc<dyn rpc::Object>) -> Arc<Self> {
        Arc::new(Self { client })
    }
}

/// RPC method to release a single strong reference.
#[derive(Debug, serde::Deserialize)]
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

rpc::decl_method! { "rpc:release" => RpcRelease}
impl rpc::Method for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "release" on a Session.
async fn rpc_release(
    _obj: Arc<Session>,
    method: Box<RpcRelease>,
    ctx: Box<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    ctx.release_owned(&method.obj)?;
    Ok(rpc::Nil::default())
}
rpc::rpc_invoke_fn! {
    rpc_release(Session,RpcRelease);
}

/// A simple temporary method to echo a reply.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Echo {
    /// A message to echo.
    msg: String,
}
rpc::decl_method! { "arti:x-echo" => Echo}
impl rpc::Method for Echo {
    type Output = Echo;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "echo" on a Session.
///
/// TODO RPC: Remove this. It shouldn't exist.
async fn echo_on_session(
    _obj: Arc<Session>,
    method: Box<Echo>,
    _ctx: Box<dyn rpc::Context>,
) -> Result<Echo, rpc::RpcError> {
    Ok(*method)
}

rpc::rpc_invoke_fn! {
    echo_on_session(Session,Echo);
}
