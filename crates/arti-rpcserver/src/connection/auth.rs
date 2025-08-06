//! RPC commands and related functionality for authentication.
//!
//! In Arti's RPC system, authentication is a kind of method that can be invoked
//! on the special "connection" object, which gives you an RPC _session_ as a
//! result.  The RPC session is the root for all other capabilities.

use tor_rpcbase as rpc;

mod cookie;
mod inherent;

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
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
enum AuthenticationScheme {
    /// Inherent authority based on the ability to open the connection to this address.
    #[serde(rename = "auth:inherent")]
    Inherent,

    /// Negotiation based on mutual proof of ability to read a file from disk.
    #[serde(rename = "auth:cookie")]
    Cookie,
}

/// An error during authentication.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize)]
enum AuthenticationFailure {
    /// The authentication method wasn't one we support.
    #[error("Tried to use unexpected authentication method")]
    IncorrectMethod,
    /// Tried to reuse a cookie authentication object
    #[error("Tried to re-authenticate with a cookie authentication object")]
    CookieNonceReused,
    /// Tried to provide a secret, MAC, or other object that wasn't correct.
    #[error("Incorrect authentication value")]
    IncorrectAuthentication,
    /// RPC system is shutting down; can't authenticate
    #[error("Shutting down; can't authenticate")]
    ShuttingDown,
}

/// A successful response from an authenticate method.
#[derive(Debug, serde::Serialize)]
struct AuthenticateReply {
    /// An handle for a `Session` object.
    session: rpc::ObjectId,
}

impl From<AuthenticationFailure> for rpc::RpcError {
    fn from(value: AuthenticationFailure) -> Self {
        use AuthenticationFailure as AF;
        use tor_error::ErrorKind as EK;

        let mut err = rpc::RpcError::new(value.to_string(), rpc::RpcErrorKind::RequestError);
        match value {
            AF::IncorrectMethod | AF::CookieNonceReused | AF::IncorrectAuthentication => {}
            AF::ShuttingDown => err.set_kind(EK::ArtiShuttingDown),
        }
        err
    }
}
