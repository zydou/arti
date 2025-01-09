//! Representations for types of required RPC connections.

use std::sync::Arc;

pub mod cookie;

/// A type of authentication required on an RPC connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RpcAuth {
    /// No authentication is expected on the connection:
    /// just being able to make the connection proves that the client is authorized.
    Inherent,
    /// RPC cookie authentication is expected on the connection.
    Cookie {
        /// A secret cookie value to use for authentication.
        secret: Arc<cookie::Cookie>,
        /// The address that the server is listening on,
        /// encoded as a string.
        server_address: String,
    },
    /// RPC cookie authentication is expected on this connection;
    /// the cookie should be loaded from disk immediately before using it.
    UnloadedCookie {
        /// The location on disk at which to load a secret cookie.
        secret_location: cookie::CookieLocation,
        /// The address that the server is listening on,
        /// encoded as a string.
        server_address: String,
    },
}
