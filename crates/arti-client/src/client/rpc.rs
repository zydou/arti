//! RPC-based interfaces for TorClient.

use super::TorClient;
use tor_rpcbase as rpc;

/// A TorClient object that is legible to the RPC system.
///
/// Sadly, for now, only one runtime per build is supported
/// TODO RPC: See #837 for info on fixing this.
type Client = super::TorClient<tor_rtcompat::PreferredRuntime>;

// We shouldn't have to use this here...
rpc::impl_const_type_id!(Client);

rpc::decl_object! {
    @expose TorClient [R] [R: tor_rtcompat::Runtime] : []
}
