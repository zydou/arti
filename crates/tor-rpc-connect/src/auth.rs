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
        /// A secret cookie to use for authentication.
        secret: RpcCookieSource,
        /// The address that the server is listening on,
        /// encoded as a string.
        server_address: String,
    },
}

/// A way to get an RPC cookie: Either in-memory, or by loading it from disk.
///
/// (We defer loading cookies when running as a client,
/// since clients should not actually load cookies from disk
/// until they have received the server's banner message.)
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RpcCookieSource {
    /// A cookie that is already loaded.
    Loaded(Arc<cookie::Cookie>),
    /// A cookie that's stored on disk and needs to be loaded.
    Unloaded(cookie::CookieLocation),
}

impl RpcCookieSource {
    /// Try to load this cookie from disk, if it is not already loaded.
    pub fn load(&self) -> Result<Arc<cookie::Cookie>, cookie::CookieAccessError> {
        match self {
            RpcCookieSource::Loaded(cookie) => Ok(Arc::clone(cookie)),
            RpcCookieSource::Unloaded(cookie_location) => Ok(Arc::new(cookie_location.load()?)),
        }
    }
}
