//! RPC APIs for geoip functionality.

use std::{collections::HashMap, sync::Arc};

use tor_rpcbase as rpc;
use tor_rpcbase::derive_deftly::Deftly;

use crate::{CountryCode, GeoipDb};

/// Look up the country codes for a list of IP addresses.
///
/// The caller passes a list of addresses in the `address` field;
/// the method returns a map from addresses to country code.
///
/// If a country code is not known for some address,
/// then it is omitted from the map.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:geoip_lookup_countries"))]
#[non_exhaustive]
struct GeoipLookupCountries {
    /// The addresses to look countries for.
    ///
    /// It is an error to include an entry here that is not an IP address.
    //
    // Note: we take these arguments as strings so that we can preserve
    // them exactly as keys in the output map.  Otherwise, it would get
    // confusing for any clients that provided non-normalized IPs.
    #[serde(default)]
    addresses: Vec<String>,
}

impl rpc::RpcMethod for GeoipLookupCountries {
    type Output = GeoipLookupResult;

    type Update = rpc::NoUpdates;
}

/// Result returned by the `arti:geoip_lookup_countries` method.
#[derive(Debug, serde::Serialize)]
#[non_exhaustive]
struct GeoipLookupResult {
    /// A map from addresses to country codes.
    ///
    /// Countries without known addresses are omitted.
    countries: HashMap<String, CountryCode>,
}

impl GeoipDb {
    /// Actually perform the geoip lookup for a given [`GeoipLookupCountries`] request.
    fn rpc_lookup_countries(
        &self,
        request: GeoipLookupCountries,
    ) -> Result<GeoipLookupResult, std::net::AddrParseError> {
        let countries: Result<HashMap<_, _>, _> = request
            .addresses
            .into_iter()
            .filter_map(|s| {
                s.parse()
                    .map(|ip| Some((s, *self.lookup_country_code(ip)?)))
                    .transpose()
            })
            .collect();

        Ok(GeoipLookupResult {
            countries: countries?,
        })
    }
}

/// Implementation for [`GeoipLookupCountries`] on [`GeoipDb`].
async fn geoip_lookup_on_geoipdb(
    db: Arc<GeoipDb>,
    method: Box<GeoipLookupCountries>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<GeoipLookupResult, rpc::RpcError> {
    db.rpc_lookup_countries(*method)
        .map_err(|e| rpc::RpcError::new(e.to_string(), rpc::RpcErrorKind::RequestError))
}

rpc::static_rpc_invoke_fn! {
    geoip_lookup_on_geoipdb;
}
