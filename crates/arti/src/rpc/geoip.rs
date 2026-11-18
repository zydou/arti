//! RPC methods for access to the Geoip DB.

use std::sync::Arc;

use derive_deftly::Deftly;
use tor_rpcbase as rpc;

use super::session::ArtiRpcSession;

/// Return a Geoip database, if one is associated with this object.
///
/// This database is used to map IP addresses to a best-effort
/// guess of the country in which they are located.
///
/// If Arti was built without geoip support,
/// or if no geoip database is available,
/// returns an error.
///
/// ## Notes
///
/// Currently, if Arti was built with geoip support,
/// then there is necessarily a geoip database available,
/// since the database is linked into Arti at compile time.
/// This may change in the future.
///
/// This method returns the latest geoip database
/// at the time that it is called.
/// (As of Nov 2026, Arti has no ability at all to change the Geoip database
/// while it's running.)
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_geoip_db"))]
struct GetGeoipDb {}

impl rpc::RpcMethod for GetGeoipDb {
    type Output = rpc::SingleIdResponse;

    type Update = rpc::NoUpdates;
}

/// Implement [`GetGeoipDb`] on [`ArtiRpcSession`]
async fn get_geoip_db_on_session(
    _session: Arc<ArtiRpcSession>,
    _method: Box<GetGeoipDb>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "geoip")] {
            let db = tor_geoip::GeoipDb::new_embedded();
            let id = ctx.register_owned(db);
            Ok(id.into())
        } else {
            todo!()
        }
    }
}

rpc::static_rpc_invoke_fn! {
    get_geoip_db_on_session;
}
