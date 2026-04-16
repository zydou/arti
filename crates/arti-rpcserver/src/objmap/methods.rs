//! Implementations for rpc methods that interact with
//! object IDs directly.
//!
//! (These methods do not use the regular dispatch system
//! because they interact with the object map system in special ways.)

use derive_deftly::Deftly;
use futures::FutureExt as _;
use std::sync::Arc;
use tor_rpcbase::{self as rpc, SingleIdResponse, templates::*};

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

/// Return a new object ID referring to an existing object.
///
/// This method does not clone the underlying object itself:
/// the new ID as well as the old ID both refer to the same object.
///
/// Releases the original object ID if the `release` flag is true.
/// Otherwise, makes no change to the original object ID.
///
/// This method can be used to create a weak ID from a strong ID,
/// or vice versa.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:clone_id", bypass_method_dispatch))]
struct RpcCloneId {
    /// If true, the new ID should be a weak reference.
    /// If false, the new ID should be a strong reference.
    ///
    /// Defaults to "false".
    #[serde(default)]
    weak: bool,

    /// If true, the original ID should be dropped.
    #[serde(default)]
    release: bool,
}

impl rpc::RpcMethod for RpcCloneId {
    type Output = rpc::SingleIdResponse;
    type Update = rpc::NoUpdates;
}

impl rpc::DynMethod for RpcCloneId {
    fn invoke_without_dispatch(
        &self,
        ctx: Arc<dyn rpc::Context>,
        obj_id: &rpc::ObjectId,
    ) -> Result<tor_rpcbase::dispatch::RpcResultFuture, tor_rpcbase::InvokeError> {
        let result = match ctx.lookup_object(obj_id) {
            Ok(obj) => {
                let new_id = if self.weak {
                    ctx.register_weak(&obj)
                } else {
                    ctx.register_owned(obj)
                };
                if self.release {
                    let _ignore = ctx.release(obj_id);
                }
                Ok(Box::new(SingleIdResponse::from(new_id)) as _)
            }
            Err(e) => Err(rpc::RpcError::from(e)),
        };

        Ok(futures::future::ready(result).boxed())
    }
}
