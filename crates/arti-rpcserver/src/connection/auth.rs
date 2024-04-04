//! RPC commands and related functionality for authentication.
//!
//! In Arti's RPC system, authentication is a kind of method that can be invoked
//! on the special "connection" object, which gives you an RPC _session_ as a
//! result.  The RPC session is the root for all other capabilities.

use std::sync::Arc;

use super::Connection;
use derive_deftly::Deftly;
use tor_rpcbase as rpc;
use tor_rpcbase::templates::*;

/*
    TODO RPC: This is disabled because the design isn't really useful.
    If we're going to provide something here, it should probably
    contain a list of protocol elements/aspects, and it should be designed
    to enable compatibility, with a clear view of what applications are
    supposed to do about it.

/// Declare the get_rpc_protocol method.
mod get_rpc_protocol {
    use super::Connection;
    use std::sync::Arc;
    use tor_rpcbase as rpc;

    /// Method to inquire about the RPC protocol.
    #[derive(Debug, serde::Deserialize)]
    struct GetRpcProtocol {}

    /// Reply to the [`GetRpcProtocol`] method
    #[derive(Debug, serde::Serialize)]
    struct GetProtocolReply {
        /// The version of the RPC protocol that this server speaks.
        // TODO RPC: Should this be a list?
        version: RpcProtocolId,
    }

    /// Identifier for a version of this RPC meta-protocol.
    #[derive(Debug, Copy, Clone, serde::Serialize)]
    enum RpcProtocolId {
        /// Alpha version of the protocol.  Things might break between here and the
        /// stable protocol.
        ///
        /// TODO RPC: CHange this to v0.
        #[serde(rename = "alpha")]
        Alpha,
    }
    rpc::decl_method! {"auth:get_rpc_protocol" => GetRpcProtocol}
    impl rpc::Method for GetRpcProtocol {
        type Output = GetProtocolReply;
        type Update = rpc::NoUpdates;
    }

    /// Describe which version of the RPC protocol our connection implements.
    async fn conn_get_rpc_protocol(
        _conn: Arc<Connection>,
        _method: Box<GetRpcProtocol>,
        _ctx: Box<dyn rpc::Context>,
    ) -> Result<GetProtocolReply, rpc::RpcError> {
        Ok(GetProtocolReply {
            version: RpcProtocolId::Alpha,
        })
    }
    rpc::rpc_invoke_fn! {
        conn_get_rpc_protocol(Connection, GetRpcProtocol);
    }
}
*/

/// Information about how an RPC session has been authenticated.
///
/// Currently, this isn't actually used for anything, since there's only one way
/// to authenticate a connection.  It exists so that later we can pass
/// information to the session-creator function.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RpcAuthentication {}

/// The authentication scheme as enumerated in the spec.
///
/// Conceptually, an authentication scheme answers the question "How can the
/// Arti process know you have permissions to use or administer it?"
///
/// TODO RPC: The only supported one for now is "inherent:unix_path"
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
enum AuthenticationScheme {
    /// Inherent authority based on the ability to access an AF_UNIX address.
    #[serde(rename = "inherent:unix_path")]
    InherentUnixPath,
}

/// Method to ask which authentication methods are supported.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod, HasConstTypeId_)]
#[deftly(method_name = "auth:query")]
struct AuthQuery {}

/// A list of supported authentication schemes and their parameters.
#[derive(Debug, serde::Serialize)]
struct SupportedAuth {
    /// A list of the supported authentication schemes.
    ///
    /// TODO RPC: Actually, this should be able to contain strings _or_ maps,
    /// where the maps are additional information about the parameters needed
    /// for a particular scheme.  But I think that's a change we can make later
    /// once we have a scheme that takes parameters.
    ///
    /// TODO RPC: Should we indicate which schemes get you additional privileges?
    schemes: Vec<AuthenticationScheme>,
}

impl rpc::Method for AuthQuery {
    type Output = SupportedAuth;
    type Update = rpc::NoUpdates;
}
/// Implement `auth:AuthQuery` on a connection.
async fn conn_authquery(
    _conn: Arc<Connection>,
    _query: Box<AuthQuery>,
    _ctx: Box<dyn rpc::Context>,
) -> Result<SupportedAuth, rpc::RpcError> {
    // Right now, every connection supports the same scheme.
    Ok(SupportedAuth {
        schemes: vec![AuthenticationScheme::InherentUnixPath],
    })
}
rpc::rpc_invoke_fn! {
    conn_authquery(Connection, AuthQuery);
}

/// Method to implement basic authentication.  Right now only "I connected to
/// you so I must have permission!" is supported.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod, HasConstTypeId_)]
#[deftly(method_name = "auth:authenticate")]
struct Authenticate {
    /// The authentication scheme as enumerated in the spec.
    ///
    /// TODO RPC: The only supported one for now is "inherent:unix_path"
    scheme: AuthenticationScheme,
}

/// A reply from the `Authenticate` method.
#[derive(Debug, serde::Serialize)]
struct AuthenticateReply {
    /// An owned reference to a `Session` object.
    session: rpc::ObjectId,
}

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

    let auth = RpcAuthentication {};
    let session = {
        let mgr = unauth.mgr()?;
        mgr.create_session(&auth)
    };
    let session = ctx.register_owned(session);
    Ok(AuthenticateReply { session })
}
rpc::rpc_invoke_fn! {
    authenticate_connection(Connection, Authenticate);
}
