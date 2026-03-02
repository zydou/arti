//! Administrative RPC functionality.
//!
//! In general, RPC function is "administrative", and requires superuser access,
//! whenever it can affect other applications.
//!
//! This is not a perfect sandbox: applications can _always_ interfere with one another's traffic by
//! consuming resources (like bandwidth or CPU) in a way that introduces side channels.

use derive_deftly::Deftly;
// use std::sync::Arc;
use tor_rpcbase::{self as rpc};

/// An object representing superuser access to Arti over an RPC session.
///
/// In general, RPC function is "administrative", and requires superuser access,
/// whenever it can affect other applications.
#[derive(Deftly)]
#[derive_deftly(rpc::Object)]
pub(super) struct RpcSuperuser {
    // This doesn't do anything yet.
}

impl RpcSuperuser {
    /// Construct a new RpcSuperuser object.
    pub(super) fn new() -> Self {
        RpcSuperuser {}
    }
}
