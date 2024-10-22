//! Implementations for rpc methods that interact with
//! object IDs directly.
//!
//! (These methods do not use the regular dispatch system
//! because they interact with the object map system in special ways.)

use derive_deftly::Deftly;
use std::sync::Arc;
use tor_rpcbase::{self as rpc, templates::*};

use crate::RpcSession;

/// Release a single ObjectID.
///
/// Only works if the ObjectID is strong reference (also known as a "handle"):
/// see RPC specification for more information on the distinction.
/// (We intend to relax this requirement in the future.)
///
/// After calling this method, the provided ObjectID will no longer be usable,
/// but other ObjectIDs for the same object may still exist.
///
/// TODO RPC BREAKING: We're going to move this method, turn it into a
/// globally implemented
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "rpc:release"))]
struct RpcRelease {
    /// The object to release. Must be a strong reference.
    ///
    /// TODO RPC: Releasing a weak reference is perilous and hard-to-define
    /// based on how we have implemented our object ids.  If you tell the objmap
    /// to "release" a single name for a weak reference, you are releasing every
    /// name for that weak reference, which may have surprising results.
    ///
    /// This might be a sign of a design problem.
    obj: rpc::ObjectId,
}

impl rpc::RpcMethod for RpcRelease {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "release" on a Session.
async fn rpc_release(
    _obj: Arc<RpcSession>,
    method: Box<RpcRelease>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    ctx.release_owned(&method.obj)?;
    Ok(rpc::Nil::default())
}
