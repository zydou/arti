//! Implementations for rpc methods that interact with
//! object IDs directly.
//!
//! (These methods do not use the regular dispatch system
//! because they interact with the object map system in special ways.)

use derive_deftly::Deftly;
use futures::FutureExt as _;
use std::sync::Arc;
use tor_rpcbase::{self as rpc, templates::*};

/// Release a single ObjectID.
///
/// After calling this method, the provided ObjectID will no longer be usable,
/// but other ObjectIDs for the same object may still exist.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:release", bypass_method_dispatch))]
struct RpcRelease {}

impl rpc::RpcMethod for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

impl rpc::DynMethod for RpcRelease {
    fn invoke_without_dispatch(
        &self,
        ctx: Arc<dyn rpc::Context>,
        obj_id: &rpc::ObjectId,
    ) -> Result<tor_rpcbase::dispatch::RpcResultFuture, tor_rpcbase::InvokeError> {
        let result = match ctx.release(obj_id) {
            Ok(()) => Ok(Box::new(rpc::NIL) as _),
            Err(e) => Err(rpc::RpcError::from(e)),
        };
        Ok(futures::future::ready(result).boxed())
    }
}
