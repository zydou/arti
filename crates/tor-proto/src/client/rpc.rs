//! RPC support for client tor-proto objects.

use std::{net::SocketAddr, sync::Arc};

use derive_deftly::Deftly;
use tor_linkspec::{HasAddrs, HasRelayIds};
use tor_llcrypto::pk;
use tor_rpcbase::{self as rpc, SingleIdResponse};

use crate::{
    ClientTunnel,
    client::stream::{ClientDataStreamCtrl, ClientStreamCtrl},
};

/// RPC method that returns the tunnel for a given object.
///
/// This is currently implemented for Data streams,
/// but could in the future be implemented for other types.
///
/// # In the Arti RPC System
///
/// Return a tunnel associated with a given object.
///
/// (A tunnel is a collection of one or more circuits
/// used to transmit data.)
///
/// Gives an error if the object is not associated with a tunnel,
/// or if the tunnel was closed.
///
/// The returned ObjectId is a handle to a `ClientTunnel`.
/// The caller should drop this ObjectId when they are done with the ClientTunnel.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_tunnel"))]
#[non_exhaustive]
pub struct GetTunnel {}

impl rpc::RpcMethod for GetTunnel {
    type Output = rpc::SingleIdResponse;
    type Update = rpc::NoUpdates;
}

/// RPC method to describe the path for an object.
///
/// This is currently implemented for [`ClientTunnel`],
/// but could in the future be implemented for other types.
///
/// # In the Arti RPC System
///
/// Describe the path(s) of a tunnel through the Tor network.
///
/// (Because of [Conflux], a tunnel can have multiple paths.
/// This method describes the members of each one.)
///
/// If `include_deprecated_ids` is true,
/// the output includes deprecated node identity types,
/// including the RSA identity.
/// Otherwise, only non-deprecated identities are included.
///
/// [Conflux]: https://spec.torproject.org/proposals/329-traffic-splitting.html
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:describe_path"))]
#[non_exhaustive]
pub struct DescribePath {
    /// If true, the output will include deprecated node identity types.
    #[serde(default)]
    include_deprecated_ids: bool,
}

impl rpc::RpcMethod for DescribePath {
    type Output = PathDescription;
    type Update = rpc::NoUpdates;
}

/// A RPC-level description for a single entry in a tunnel or circuit path.
#[derive(serde::Serialize, Clone, Debug)]
pub struct PathEntry {
    /// A set of IDs for this Tor relay.
    ///
    /// Each ID represents a long-term public key used to identify the relay.
    /// Deprecated ID types are not included, unless they were specifically requested.
    ///
    /// This is absent for a virtual hop.
    ids: Option<RelayIds>,

    /// A list of the relay's addresses.
    ///
    /// This is absent for a virtual hop.
    addrs: Vec<SocketAddr>,

    /// If true, this is a "virtual" hop, not corresponding to a relay.
    ///
    /// It typically represents the other party of a rendezvous circuit.
    is_virtual: bool,
}

/// Serializable container of relay identities.
///
/// Differs from [`tor_linkspec::RelayIds`] in is serialize behavior;
/// See <https://gitlab.torproject.org/tpo/core/arti/-/issues/2477>.
#[derive(Clone, Debug, serde::Serialize)]
struct RelayIds {
    /// Copy of the ed25519 id from the underlying ChanTarget.
    #[serde(rename = "ed25519", skip_serializing_if = "Option::is_none")]
    ed_identity: Option<pk::ed25519::Ed25519Identity>,

    /// Copy of the rsa id from the underlying ChanTarget.
    #[serde(rename = "rsa", skip_serializing_if = "Option::is_none")]
    rsa_identity: Option<pk::rsa::RsaIdentity>,
}

/// A description of a tunnel's path.
///
/// Note that tunnels are potentially made of multiple circuits, even though
/// Arti (as of April 2026) does not yet build Conflux tunnels.
/// Therefore, users should make sure to handle multi-path tunnels here.
#[derive(serde::Serialize, Clone, Debug)]
pub struct PathDescription {
    /// The entries in a given tunnel's path(s).
    ///
    /// Within each path, entries are ordered from first (closest to the client)
    /// to last (farthest from the client).
    ///
    /// The order of paths is unspecified but, consistent for each single tunnel.
    /// (That is, if you query a tunnel's path description twice,
    /// you will get the paths in the same order each time.)
    path: Vec<Vec<PathEntry>>,
}

impl PathEntry {
    /// Construct a PathEntry from a PathEntry returned by a circuit.
    fn from_client_entry(
        detail: &crate::client::circuit::PathEntry,
        command: &DescribePath,
    ) -> Self {
        let Some(owned_chan_target) = detail.as_chan_target() else {
            return PathEntry {
                ids: None,
                addrs: vec![],
                is_virtual: true,
            };
        };

        let ids = tor_linkspec::RelayIds::from_relay_ids(owned_chan_target);
        let ids = RelayIds {
            ed_identity: ids.ed_identity().cloned(),
            rsa_identity: if command.include_deprecated_ids {
                ids.rsa_identity().cloned()
            } else {
                None
            },
        };
        let addrs = owned_chan_target.addrs().collect();
        PathEntry {
            ids: Some(ids),
            addrs,
            is_virtual: false,
        }
    }
}

/// Helper: Return the [`ClientTunnel`] for a [`ClientDataStreamCtrl`],
/// or an RPC error if the stream isn't attached to a tunnel.
fn client_stream_tunnel(stream: &ClientDataStreamCtrl) -> Result<Arc<ClientTunnel>, rpc::RpcError> {
    stream.tunnel().ok_or_else(|| {
        rpc::RpcError::new(
            "Stream was not attached to a tunnel".to_string(),
            rpc::RpcErrorKind::RequestError,
        )
    })
}

/// Helper: Return a [`PathDescription`] for a [`ClientTunnel`]
fn tunnel_path(tunnel: &ClientTunnel, method: &DescribePath) -> PathDescription {
    let path = tunnel
        .all_paths()
        .iter()
        .map(|path| {
            path.iter()
                .map(|hop| PathEntry::from_client_entry(hop, method))
                .collect()
        })
        .collect();
    PathDescription { path }
}

/// Implementation function: implements GetTunnel on ClientDataStreamCtrl.
async fn client_data_stream_ctrl_get_tunnel(
    target: Arc<ClientDataStreamCtrl>,
    _method: Box<GetTunnel>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    let tunnel: Arc<dyn rpc::Object> = client_stream_tunnel(&target)? as _;
    let id = ctx.register_owned(tunnel);
    Ok(SingleIdResponse::from(id))
}

/// Implementation function: implements DescribePath on a ClientTunnel.
async fn client_tunnel_describe_path(
    target: Arc<ClientTunnel>,
    method: Box<DescribePath>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<PathDescription, rpc::RpcError> {
    Ok(tunnel_path(&target, &method))
}

/// Implementation function: implements DescribePath on a ClientDataStreamCtrl.
async fn client_data_stream_ctrl_describe_path(
    target: Arc<ClientDataStreamCtrl>,
    method: Box<DescribePath>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<PathDescription, rpc::RpcError> {
    let tunnel = client_stream_tunnel(&target)?;
    Ok(tunnel_path(&tunnel, &method))
}

rpc::static_rpc_invoke_fn! {
    client_data_stream_ctrl_get_tunnel;
    client_tunnel_describe_path;
    client_data_stream_ctrl_describe_path;
}
