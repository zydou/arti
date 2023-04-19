//! Top-level `RpcMgr` to launch sessions.

use std::sync::Arc;

use arti_client::TorClient;
use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

use crate::session::Session;

/// Shared state, configuration, and data for all RPC sessions.
///
/// An RpcMgr knows how to listen for incoming RPC connections, and launch sessions based on them.
///
/// TODO RPC: Actually not all of the above functionality is implemented yet. But it should be.
pub struct RpcMgr {
    // DOCDOC
    // TODO: I think we're going to need a non-generic version of this, and a general pattern for declaring
    // non-generic wrappers for some of our Runtime-parameterized things.
    //
    // `base_client: TorClient<R>,`
    /// DOCDOC
    dispatch_table: Arc<rpc::DispatchTable>,
}

impl RpcMgr {
    /// Create a new RpcMgr.
    pub fn new<R: Runtime>(_: TorClient<R>) -> Self {
        RpcMgr {
            dispatch_table: Arc::new(rpc::DispatchTable::from_inventory()),
        }
    }

    /// Start a new session based on this RpcMgr.
    pub(crate) fn new_session(&self) -> Session {
        Session::new(self.dispatch_table.clone())
    }
}
