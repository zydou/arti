//! Declare the RPC session object as exposed from the RPC server run by the `arti` crate.

use arti_client::TorClient;
use arti_rpcserver::RpcAuthentication;
use derive_deftly::Deftly;
use futures::stream::StreamExt as _;
use std::{net::SocketAddr, sync::Arc};
use tor_async_utils::{DropNotifyEofSignallable, DropNotifyWatchSender};
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
#[deftly(rpc(
    delegate_with = "|this: &Self| Some(this.session.clone())",
    delegate_type = "arti_rpcserver::RpcSession"
))]
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
pub(crate) struct RpcVisibleArtiState {
    /// A `ProxyInfo` that we hand out when asked to list our proxy ports.
    ///
    /// Right now it only lists Socks; in the future it may list more.
    proxy_info: postage::watch::Receiver<ProxyInfoState>,
}

/// Handle to set RPC state across RPC sessions.  (See `RpcVisibleArtiState`.)
#[derive(Debug)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct RpcStateSender {
    /// Sender for setting our list of proxy ports.
    proxy_info_sender: DropNotifyWatchSender<ProxyInfoState>,
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

/// Possible state for a watched proxy_info.
#[derive(Debug, Clone)]
enum ProxyInfoState {
    /// We haven't set it yet.
    Unset,
    /// We've set it to a given value.
    Set(Arc<ProxyInfo>),
    /// The sender has been dropped.
    Eof,
}

impl DropNotifyEofSignallable for ProxyInfoState {
    fn eof() -> Self {
        Self::Eof
    }
}

impl RpcVisibleArtiState {
    /// Construct a new `RpcVisibleArtiState`.
    pub(crate) fn new() -> (Arc<Self>, RpcStateSender) {
        let (proxy_info_sender, proxy_info) = postage::watch::channel_with(ProxyInfoState::Unset);
        let proxy_info_sender = DropNotifyWatchSender::new(proxy_info_sender);
        (
            Arc::new(Self { proxy_info }),
            RpcStateSender { proxy_info_sender },
        )
    }

    /// Return the latest proxy info, waiting until it is set.
    ///
    /// Return an error if the sender has been closed.
    pub(super) async fn get_proxy_info(&self) -> Result<Arc<ProxyInfo>, ()> {
        let mut proxy_info = self.proxy_info.clone();
        while let Some(v) = proxy_info.next().await {
            match v {
                ProxyInfoState::Unset => {
                    // Not yet set, try again.
                }
                ProxyInfoState::Set(proxyinfo) => return Ok(Arc::clone(&proxyinfo)),
                ProxyInfoState::Eof => return Err(()),
            }
        }
        Err(())
    }
}

impl RpcStateSender {
    /// Set the list of socks listener addresses on this state.
    ///
    /// This method may only be called once per state.
    pub(crate) fn set_socks_listeners(&mut self, addrs: &[SocketAddr]) {
        let info = ProxyInfo {
            proxies: addrs
                .iter()
                .map(|a| proxyinfo::Proxy {
                    listener: proxyinfo::ProxyListener::Socks5 {
                        tcp_address: Some(*a),
                    },
                })
                .collect(),
        };
        *self.proxy_info_sender.borrow_mut() = ProxyInfoState::Set(Arc::new(info));
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use futures::task::SpawnExt as _;
    use tor_rtmock::MockRuntime;

    use super::*;

    #[test]
    fn set_proxy_info() {
        MockRuntime::test_with_various(|rt| async move {
            let (state, mut sender) = RpcVisibleArtiState::new();
            let _task = rt.clone().spawn_with_handle(async move {
                sender.set_socks_listeners(&["8.8.4.4:99".parse().unwrap()]);
                sender // keep sender alive
            });

            let value = state.get_proxy_info().await;

            // At this point, we've returned once, so this will test that we get a fresh answer even
            // if we already set the inner value.
            let value_again = state.get_proxy_info().await;
            assert_eq!(value.unwrap(), value_again.unwrap());
        });
    }
}
