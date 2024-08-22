//! Implement RPC functionality for finding what ports are running as proxies.

use std::{net::SocketAddr, sync::Arc};
use tor_error::{ErrorKind, HasKind};
use tor_rpcbase::{self as rpc};

use super::session::ArtiRpcSession;

/// Representation of a single proxy address, as delivered by the RPC API.
#[derive(serde::Serialize, Clone, Debug)]
pub(super) enum Proxy {
    /// A SOCKS5 proxy.
    Socks5 {
        /// The address at which we're listening for SOCKS connections.
        address: SocketAddr,
    },
}

/// A representation of the set of proxy addresses available from the RPC API.
#[derive(serde::Serialize, Clone, Debug)]
pub(super) struct ProxyInfo {
    /// A list of the supported proxies.
    ///
    /// (So far, only SOCKS proxies are listed, but other kinds may be listed in the future.)
    pub(super) proxies: Vec<Proxy>,
}

/// RPC method: Get a list of the currently running proxies
/// that are integrated with the RPC system.
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:x_get_proxy_info"))]
struct GetProxyInfo {}

impl rpc::RpcMethod for GetProxyInfo {
    type Output = ProxyInfo;
    type Update = rpc::NoUpdates;
}

/// An error encountered while asking for the proxy addresses.
#[derive(Clone, Debug, thiserror::Error)]
enum GetProxyInfoError {
    /// The Proxy information has not yet been set.
    #[error("Proxy information not ready")]
    NotReady,
}
impl HasKind for GetProxyInfoError {
    fn kind(&self) -> ErrorKind {
        use GetProxyInfoError as E;
        match self {
            // This is transient because the Socks code should be setting as soon as it opens its
            // listeners.
            E::NotReady => ErrorKind::TransientFailure,
        }
    }
}

/// Implementation for GetProxyInfo on ArtiRpcSession.
async fn rpc_session_get_proxy_info(
    session: Arc<ArtiRpcSession>,
    _method: Box<GetProxyInfo>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<ProxyInfo, GetProxyInfoError> {
    let proxy_info = session.arti_state.proxy_info.get();

    match proxy_info {
        Some(info) => Ok(info.clone()),
        None => Err(GetProxyInfoError::NotReady),
    }
}
rpc::static_rpc_invoke_fn! {rpc_session_get_proxy_info;}
