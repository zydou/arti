//! "Inherent" authentication, where the ability to establish a connection proves that the user is
//! authorized.
use std::sync::Arc;

use super::{AuthenticationFailure, AuthenticationScheme, RpcAuthentication};
use crate::Connection;
use derive_deftly::Deftly;
use tor_rpc_connect::auth::RpcAuth;
use tor_rpcbase as rpc;
use tor_rpcbase::templates::*;

/// Authenticate on an RPC Connection, returning a new Session.
///
/// After connecting to Arti, clients use this method to create a Session,
/// which they then use to access other functionality.
///
/// For now, only the `inherent:unix_path` method is supported;
/// other methods will be implemented in the future.
///
/// You typically won't need to invoke this method yourself;
/// instead, your RPC library (such as `arti-rpc-client-core`)
/// should handle it for you.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "auth:authenticate"))] // TODO RPC RENAME XXXX?
struct Authenticate {
    /// The authentication scheme as enumerated in the spec.
    ///
    /// TODO RPC: The only supported one for now is "inherent:unix_path" // TODO RPC RENAME XXXX?
    scheme: AuthenticationScheme,
}

/// A reply from the `Authenticate` method.
#[derive(Debug, serde::Serialize)]
struct AuthenticateReply {
    /// An handle for a `Session` object.
    session: rpc::ObjectId,
}

impl rpc::RpcMethod for Authenticate {
    type Output = AuthenticateReply;
    type Update = rpc::NoUpdates;
}

impl tor_error::HasKind for AuthenticationFailure {
    fn kind(&self) -> tor_error::ErrorKind {
        // TODO RPC not right.
        tor_error::ErrorKind::LocalProtocolViolation
    }
}

/// Invoke the "authenticate" method on a connection.
///
/// TODO RPC: This behavior is wrong; we'll need to fix it to be all
/// capabilities-like.
async fn authenticate_connection(
    unauth: Arc<Connection>,
    method: Box<Authenticate>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<AuthenticateReply, rpc::RpcError> {
    match (method.scheme, &unauth.require_auth) {
        // For now, we only support AF_UNIX connections, and we assume that if
        // you have permission to open such a connection to us, you have
        // permission to use Arti. We will refine this later on!
        (AuthenticationScheme::InherentUnixPath, RpcAuth::None) => {}
        (_, _) => return Err(AuthenticationFailure::IncorrectMethod.into()),
    }

    let auth = RpcAuthentication {};
    let session = {
        let mgr = unauth.mgr()?;
        mgr.create_session(&auth)
    };
    let session = ctx.register_owned(session);
    Ok(AuthenticateReply { session })
}
rpc::static_rpc_invoke_fn! {
    authenticate_connection;
}
