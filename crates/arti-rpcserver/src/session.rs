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
impl rpc::Object for Session {}
rpc::decl_object! {Session}

impl Session {
    /// Create a new session object.
    pub(crate) fn new(client: Arc<dyn rpc::Object>) -> Arc<Self> {
        Arc::new(Self { client })
    }
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
