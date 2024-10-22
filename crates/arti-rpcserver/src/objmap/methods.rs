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
/// Only works if the ObjectID is strong reference (also known as a "handle"):
/// see RPC specification for more information on the distinction.
/// (We intend to relax this requirement in the future.)
///
/// After calling this method, the provided ObjectID will no longer be usable,
/// but other ObjectIDs for the same object may still exist.
///
/// TODO RPC: Releasing a weak reference is perilous and hard-to-define
/// based on how we have implemented our object ids.  If you tell the objmap
/// to "release" a single name for a weak reference, you are releasing every
/// name for that weak reference, which may have surprising results.
/// See also #838.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:release", bypass_method_dispatch))]
struct RpcRelease {}

impl rpc::RpcMethod for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

impl rpc::DynMethod for RpcRelease {
    fn bypass_method_dispatch(&self) -> bool {
        true
    }

    fn invoke_without_dispatch(
        &self,
        ctx: Arc<dyn rpc::Context>,
        obj_id: &rpc::ObjectId,
    ) -> Result<tor_rpcbase::dispatch::RpcResultFuture, tor_rpcbase::InvokeError> {
        let result = match ctx.release_owned(obj_id) {
            Ok(()) => Ok(Box::new(rpc::NIL) as _),
            Err(e) => Err(rpc::RpcError::from(e)),
        };
        Ok(futures::future::ready(result).boxed())
    }
}
