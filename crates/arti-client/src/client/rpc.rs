//! RPC-based interfaces for TorClient.

use tor_rpcbase as rpc;

/// A TorClient object that is legible to the RPC system.
///
/// Sadly, for now, only one runtime per build is supported
/// TODO RPC: See #837 for info on fixing this.
type Client = super::TorClient<tor_rtcompat::PreferredRuntime>;
rpc::impl_const_type_id! { Client } // XXXX

// Make sure that every instantiation of TorClient<R> can be shoved into an
// Arc<dyn Object>.  This lets us keep some of the above limitations out of the
// API for arti_rpcserver.
impl<R: tor_rtcompat::Runtime> rpc::Object for super::TorClient<R> {}
