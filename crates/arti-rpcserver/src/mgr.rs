//! Top-level `RpcMgr` to launch sessions.

use std::sync::Arc;

use arti_client::TorClient;
use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

use crate::connection::Connection;

/// Shared state, configuration, and data for all RPC sessions.
///
/// An RpcMgr knows how to listen for incoming RPC connections, and launch sessions based on them.
///
/// TODO RPC: Actually not all of the above functionality is implemented yet. But it should be.
pub struct RpcMgr {
    /// Our reference to the dispatch table used to look up the functions that
    /// implement each object on each
    dispatch_table: Arc<rpc::DispatchTable>,
}

impl RpcMgr {
    /// Create a new RpcMgr.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        RpcMgr {
            dispatch_table: Arc::new(rpc::DispatchTable::from_inventory()),
        }
    }

    /// Start a new session based on this RpcMgr, with a given TorClient.
    ///
    /// TODO RPC: If `client` is not a `TorClient<PreferredRuntime>`, it won't
    /// be possible to invoke any of its methods. See #837.
    pub fn new_session<R: Runtime>(&self, client: TorClient<R>) -> Connection {
        let client_obj = Arc::new(client);
        Connection::new(self.dispatch_table.clone(), client_obj)
    }
}
