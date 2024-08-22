//! Declare the RPC session object as exposed from the RPC server run by the `arti` crate.

use arti_client::TorClient;
use arti_rpcserver::RpcAuthentication;
use derive_deftly::Deftly;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tor_rpcbase::{self as rpc};
use tor_rtcompat::Runtime;

use super::proxyinfo::{self, ProxyInfo};

/// A top-level RPC session object.
///
/// This type wraps and delegates to [`arti_rpcserver::RpcSession`],
/// and exposes additional functionality not available at the
/// level of [`arti_rpcserver`].
#[derive(Deftly)]
#[derive_deftly(rpc::Object)]
#[deftly(rpc(delegate_with = "|this: &Self| Some(this.session.clone())"))]
#[deftly(rpc(expose_outside_of_session))]
pub(super) struct ArtiRpcSession {
    /// State about the `arti` server, as seen by the Rpc system.
    pub(super) arti_state: Arc<RpcVisibleArtiState>,
    /// The underlying RpcSession object that we delegate to.
    session: Arc<arti_rpcserver::RpcSession>,
}

/// Information about the current global top-level Arti state,
/// as exposed to an Rpc Session.
//
// TODO: This type is dangerously close to being a collection of globals.
// We should refactor it aggressively when we refactor the `arti` crate.
//
// TODO: Right now this is constructed in the same form that it's used in
// ArtiRpcSession.  Later on, we could split it into one type that
// the rest of this crate constructs, and another type that the
// ArtiRpcSession actually uses. We should do that if the needs seem to diverge.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct RpcVisibleArtiState {
    /// A `ProxyInfo` that we hand out when asked to list our proxy ports.
    ///
    /// Right now it only lists Socks; in the future it may list more.
    pub(super) proxy_info: OnceLock<ProxyInfo>,
}

impl ArtiRpcSession {
    /// Construct a new `ArtiRpcSession`.
    ///
    /// Privileges on the session (if any) are derived from `auth`, which describes
    /// how the user authenticated.
    ///
    /// The session receives a new isolated TorClient, based on `client_root`.
    pub(super) fn new<R: Runtime>(
        auth: &RpcAuthentication,
        client_root: &TorClient<R>,
        arti_state: &Arc<RpcVisibleArtiState>,
    ) -> Arc<Self> {
        let _ = auth; // This is currently unused; any authentication gives the same result.
        let client = client_root.isolated_client();
        let session = arti_rpcserver::RpcSession::new_with_client(Arc::new(client));
        let arti_state = Arc::clone(arti_state);
        Arc::new(ArtiRpcSession {
            session,
            arti_state,
        })
    }
}

impl RpcVisibleArtiState {
    /// Construct a new `RpcVisibleArtiState`.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            proxy_info: OnceLock::new(),
        })
    }

    /// Set the list of socks listener addresses on this state.
    ///
    /// This method may only be called once per state.
    pub(crate) fn set_socks_listeners(&self, addrs: &[SocketAddr]) -> anyhow::Result<()> {
        let info = ProxyInfo {
            proxies: addrs
                .iter()
                .map(|a| proxyinfo::Proxy::Socks5 { address: *a })
                .collect(),
        };
        self.proxy_info
            .set(info)
            .map_err(|_| anyhow::anyhow!("Tried to call set_socks_listeners twice"))?;

        Ok(())
    }
}
