//! Stub replacement for the rpc module when compiled without RPC support.

/// An uninhabited type, for use when constructing a proxy listener.
///
/// (This type _is_ inhabited when we're built with RPC support.)
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum RpcProxySupport {}
