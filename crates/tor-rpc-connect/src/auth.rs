//! Representations for types of required RPC connections.

pub mod cookie;

/// A type of authentication required on an RPC connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RpcAuth {
    /// No authentication is expected on the connection.
    None,
    /// RPC cookie authentication is expected on the connection.
    Cookie {
        /// A secret cookie value to use for authentication.
        secret: cookie::Cookie,
        /// The address that the server is listening on,
        /// encoded as a string.
        server_address: String,
    },
}
