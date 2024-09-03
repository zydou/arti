//! A wrapper around an RPC Object that can be used as a connection target.

use arti_client::{
    rpc::{ClientConnectionResult, ConnectWithPrefs, ResolvePtrWithPrefs, ResolveWithPrefs},
    DataStream, StreamPrefs, TorAddr, TorClient,
};
use std::{net::IpAddr, sync::Arc};
use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

/// Wrapper around an RPC object that can be used as a connection target,
/// or around a TorClient if no RPC object is given.
///
/// Provides an API similar to TorClient, for use when opening SOCKS connections.
pub(crate) enum ConnTarget<R: Runtime> {
    /// An RPC object with accompanying context.
    Rpc {
        /// The RPC object on which to build our connections.
        object: Arc<dyn rpc::Object>,
        /// The RPC context in which to invoke methods
        context: Arc<dyn rpc::Context>,
    },
    /// A Tor client, without RPC information
    Client(TorClient<R>),
}

impl<R: Runtime> ConnTarget<R> {
    /// As [`TorClient::connect_with_prefs`].
    pub(crate) async fn connect_with_prefs(
        &self,
        target: &TorAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<DataStream> {
        match self {
            ConnTarget::Rpc {
                object: obj,
                context,
            } => {
                let method = ConnectWithPrefs {
                    target: target.clone(),
                    prefs: prefs.clone(),
                };
                *rpc::invoke_special_method(context.clone(), obj.clone(), Box::new(method) as _)
                    .await
                    .map_err(|e| Box::new(e) as _)?
            }
            ConnTarget::Client(client) => client
                .connect_with_prefs(target, prefs)
                .await
                .map_err(|e| Box::new(e) as _),
        }
    }

    /// As [`TorClient::resolve_with_prefs`]
    pub(crate) async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<IpAddr>> {
        match self {
            ConnTarget::Rpc {
                object: obj,
                context,
            } => {
                let method = ResolveWithPrefs {
                    hostname: hostname.to_string(),
                    prefs: prefs.clone(),
                };
                *rpc::invoke_special_method(context.clone(), obj.clone(), Box::new(method) as _)
                    .await
                    .map_err(|e| Box::new(e) as _)?
            }
            ConnTarget::Client(client) => client
                .resolve_with_prefs(hostname, prefs)
                .await
                .map_err(|e| Box::new(e) as _),
        }
    }

    /// As [`TorClient::resolve_ptr_with_prefs`]
    pub(crate) async fn resolve_ptr_with_prefs(
        self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> ClientConnectionResult<Vec<String>> {
        match self {
            ConnTarget::Rpc {
                object: obj,
                context,
            } => {
                let method = ResolvePtrWithPrefs {
                    addr,
                    prefs: prefs.clone(),
                };
                *rpc::invoke_special_method(context.clone(), obj.clone(), Box::new(method) as _)
                    .await
                    .map_err(|e| Box::new(e) as _)?
            }
            ConnTarget::Client(client) => client
                .resolve_ptr_with_prefs(addr, prefs)
                .await
                .map_err(|e| Box::new(e) as _),
        }
    }
}
