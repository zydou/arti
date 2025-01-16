//! Implementations for methods on Connection.

use derive_deftly::Deftly;
use std::sync::Arc;
use tor_rpcbase::{self as rpc, templates::*};

use super::Connection;

/// Cancel a single request.
///
/// Note that calling this method does not guarantee that the request is actually cancelled:
/// the request might finish first.
///
/// What we do guarantee is that either this method returns successfully and the request is cancelled,
/// or that this method fails and the request is not cancelled.
/// We also guarantee that both the request and this method will finish "fairly quickly"
/// after this method is called.
///
/// For more information see `rpc-meta-draft.md`.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:cancel"))]
struct RpcCancel {
    /// The ID for the request that we should try to cancel.
    request_id: crate::msgs::RequestId,
}

impl rpc::RpcMethod for RpcCancel {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implement `RpcCancel` on a connection.
async fn connection_rpc_cancel(
    conn: Arc<Connection>,
    cancel: Box<RpcCancel>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, super::RequestNotFound> {
    conn.cancel_request(&cancel.request_id).map(|()| rpc::NIL)
}

rpc::static_rpc_invoke_fn! {
    connection_rpc_cancel;
}
