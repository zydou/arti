//! Implement RPC functionality for finding what ports are running as proxies.

use std::{net::SocketAddr, sync::Arc};
use tor_error::{ErrorKind, HasKind};
use tor_rpcbase::{self as rpc};

use super::session::ArtiRpcSession;

/// Representation of a single proxy, as delivered by the RPC API.
#[derive(serde::Serialize, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) struct Proxy {
    /// Where the proxy is listening, and what protocol-specific options it expects.
    pub(super) listener: ProxyListener,
}

/// Representation of a single proxy's listener location, as delivered by the RPC API.
#[derive(serde::Serialize, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) enum ProxyListener {
    /// A SOCKS5 proxy.
    Socks5 {
        /// The address at which we're listening for SOCKS connections.
        address: SocketAddr,
    },
}

/// A representation of the set of proxy addresses available from the RPC API.
#[derive(serde::Serialize, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) struct ProxyInfo {
    /// A list of the supported proxies.
    ///
    /// (So far, only SOCKS proxies are listed, but other kinds may be listed in the future.)
    pub(super) proxies: Vec<Proxy>,
}

/// RPC method: Get a list of all the currently running proxies.
///
/// This method should not be used when deciding which proxy
/// an RPC application should connect to.  Instead it should use
/// [`arti:get_rpc_proxy_info`](GetRpcProxyInfo).
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_proxy_info"))]
struct GetProxyInfo {}

/// RPC method: Get a list of the currently running proxies
/// that are integrated with the RPC system.
///
/// This method returns a list of proxies.
/// The RPC application may be not be able to use all proxies from the list,
/// and may prefer some proxies over other.
/// When multiple proxies are equally preferred,
/// the application SHOULD use whichever appears first in the list.
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_rpc_proxy_info"))]
struct GetRpcProxyInfo {}

impl rpc::RpcMethod for GetProxyInfo {
    type Output = ProxyInfo;
    type Update = rpc::NoUpdates;
}

impl rpc::RpcMethod for GetRpcProxyInfo {
    type Output = ProxyInfo;
    type Update = rpc::NoUpdates;
}

/// An error encountered while asking for the proxy addresses.
#[derive(Clone, Debug, thiserror::Error)]
enum GetProxyInfoError {
    /// The Sender was dropped without setting any proxy info;
    /// likely, Arti is shutting down.
    #[error("Arti appears to be shutting down")]
    Shutdown,
}
impl HasKind for GetProxyInfoError {
    fn kind(&self) -> ErrorKind {
        use GetProxyInfoError as E;
        match self {
            E::Shutdown => ErrorKind::ArtiShuttingDown,
        }
    }
}

/// Implementation for GetProxyInfo on ArtiRpcSession.
async fn rpc_session_get_proxy_info(
    session: Arc<ArtiRpcSession>,
    _method: Box<GetProxyInfo>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<ProxyInfo, GetProxyInfoError> {
    let proxy_info = session.arti_state.get_proxy_info().await;

    match proxy_info {
        Ok(info) => Ok((*info).clone()),
        Err(()) => Err(GetProxyInfoError::Shutdown),
    }
}
rpc::static_rpc_invoke_fn! {rpc_session_get_proxy_info;}

/// Implementation for GetProxyInfo on ArtiRpcSession.
async fn rpc_session_get_rpc_proxy_info(
    session: Arc<ArtiRpcSession>,
    _method: Box<GetProxyInfo>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<ProxyInfo, GetProxyInfoError> {
    let proxy_info = session.arti_state.get_proxy_info().await;

    match proxy_info {
        Ok(info) => Ok((*info).clone()),
        Err(()) => Err(GetProxyInfoError::Shutdown),
    }
}
rpc::static_rpc_invoke_fn! {rpc_session_get_rpc_proxy_info;}
