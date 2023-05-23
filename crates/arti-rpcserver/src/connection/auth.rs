//! RPC commands and related functionality for authentication.
//!
//! In Arti's RPC system, authentication is a kind of method that can be invoked
//! on the special "connection" object, which gives you an RPC _session_ as a
//! result.  The RPC session is the root for all other capabilities.

use std::sync::Arc;

use super::Connection;
use tor_rpcbase as rpc;

/// The authentication scheme as enumerated in the spec.
///
/// Conceptually, an authentication scheme answers the question "How can the
/// Arti process know you have permissions to use or administer it?"
///
/// TODO RPC: The only supported one for now is "inherent:unix_path"
#[derive(Debug, Copy, Clone, serde::Deserialize)]
enum AuthenticationScheme {
    /// Inherent authority based on the ability to access an AF_UNIX address.
    #[serde(rename = "inherent:unix_path")]
    InherentUnixPath,
}

/// Method to implement basic authentication.  Right now only "I connected to
/// you so I must have permission!" is supported.
#[derive(Debug, serde::Deserialize)]
struct Authenticate {
    /// The authentication scheme as enumerated in the spec.
    ///
    /// TODO RPC: The only supported one for now is "inherent:unix_path"
    scheme: AuthenticationScheme,
}

/// A reply from the `Authenticate` method.
#[derive(Debug, serde::Serialize)]
struct AuthenticateReply {
    /// An owned reference to a `TorClient` object.
    client: Option<rpc::ObjectId>,
}

rpc::decl_method! {"auth:authenticate" => Authenticate}
impl rpc::Method for Authenticate {
    type Output = AuthenticateReply;
    type Update = rpc::NoUpdates;
}

/// An error during authentication.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize)]
enum AuthenticationFailure {}

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
    ctx: Box<dyn rpc::Context>,
) -> Result<AuthenticateReply, rpc::RpcError> {
    match method.scheme {
        // For now, we only support AF_UNIX connections, and we assume that if
        // you have permission to open such a connection to us, you have
        // permission to use Arti. We will refine this later on!
        AuthenticationScheme::InherentUnixPath => {}
    }

    let client = Arc::clone(&unauth.inner.lock().expect("Poisoned lock").client);

    let client = Some(ctx.register_weak(client));
    Ok(AuthenticateReply { client })
}
rpc::rpc_invoke_fn! {
    authenticate_connection(Connection, Authenticate);
}
