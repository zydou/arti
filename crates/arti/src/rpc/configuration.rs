//! Functionality for accessing and modifying configuration over RPC

use std::sync::Arc;

use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

use crate::rpc::RpcSuperuser;

/// A set of configuration options maintained by the RPC subsystem.
///
/// These are applied after all loaded configuration values.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct ConfigSettings(serde_json::Value);

impl Default for ConfigSettings {
    fn default() -> Self {
        Self(serde_json::Value::Object(Default::default()))
    }
}

impl ConfigSettings {
    /// Replace the value at `key` within this object with `value`.
    ///
    /// `key` is interpreted as a dot-separated sequence of dictionary keys.
    ///
    /// Either "." or "" can be used to refer to the root of the tree.
    ///
    /// Note this function can easily create an invalid configuration.
    fn apply_key_value(&mut self, key: &str, value: serde_json::Value) {
        use serde_json::{Map, Value};

        if ["", "."].contains(&key) {
            self.0 = value;
            return;
        }

        let mut v: &mut Value = &mut self.0;
        for path_elt in key.split('.') {
            if v.is_object() {
                let map = v.as_object_mut().expect("No longer an object");
                v = map.entry(path_elt).or_insert(Value::Null);
            } else {
                let mut map: Map<String, Value> = Default::default();
                map.insert(path_elt.to_string(), Value::Null);
                *v = Value::Object(map);
                v = v
                    .as_object_mut()
                    .expect("value stopped being an object")
                    .get_mut(path_elt)
                    .expect("entry in object disappeared");
            }
        }

        *v = value;
    }
}

/// One or more configuration settings returned by the RPC subsystem.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct ConfigValue(serde_json::Value);

/// Change the value of a part of the configuration tree.
///
/// This method requires superuser capability,
/// since it affects all Arti sessions.
///
/// ## Semantics
///
/// Arti takes its configuration from the following sources:
///
/// 1. A set of default values
/// 2. Configuration files on disk
/// 3. Command-line configuration arguments
/// 4. Options provided via RPC
///
/// These sources are applied in order,
/// with later options possibly overriding earlier ones.
/// (When a set of options is stored in a map, the maps are merged,
/// with the later map getting precedence.)
/// The set of options forms a tree.
/// In the RPC system, we represent this tree as a JSON Object.
///
/// > TODO: Explain all of this more clearly.
///
/// _This RPC method_ lets you change the set of options provided via RPC.
/// (source 4 in the list above).
///
/// When you use this method, it _replaces_ part the the RPC configuration
/// options at the path in the tree represented by `key`
/// with the provided `value`.
///
/// ## Error behavior
///
/// This method will fail if:
///
/// - Any provided option is invalid
/// - The transition from the current set of options
///   to the new set is not allowed
/// - Or something goes wrong when trying to transition.
///
/// If this method fails,
/// and the configuration will (if possible[^original-state])
/// stay in its original state,
/// and the method will return an error.
///
/// > The current error type contains no machine-readable elements
/// > describing how it failed;
/// > we do intend to add some in the future.
///
/// **NOTE**: This method currently **will not fail** for any unrecognized options.
/// We will, later, add options to require only recognized options,
/// or to list unrecognized options.
///
/// [^original-state]: If arti can reject the configuration changes
///    before it starts trying to apply them, we guarantee that
///    the configuration will stay in its original state.
///    Otherwise, arti will try its best to apply configuration
///    changes on an all-or-nothing basis,
///    but bugs or system limitations may prevent this from working completely.
///
/// ## Examples
///
/// ### Setting a single option
///
/// This invocation will disable client connections to "local"
/// addresses over the Tor network.  It will override any
/// value for this option set in any other configuration source.
///
/// ```json
/// { "key": "address_filter.allow_local_addrs", "value": false }
/// ```
///
/// ### Setting several options at a given path.
///
/// This invocation will disable client connections to local
/// addresses.
///
/// This replaces the whole sub-tree of RPC-provided options at `address_filter`.
/// Therefore, if there are any other RPC-provided options for `address_filter.*`,
/// **this invocation will remove them**.
///
/// > We might add optional "merge" semantics (instead of replace) in the future.
///
/// ```json
/// { "key": "address_filter",
///   "value": { "allow_local_addrs": false } }
/// ```
///
/// ### Clearing all RPC-provided options
///
/// This invocation will restore the configuration to the state
/// of having _no_ RPC-provided options:
///
/// ```json
/// { "key": '', "value": {} }
/// ```
///
/// It works by replacing the root of the RPC option tree with an empty Object,
/// so that only options from the other sources will remain.
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:set_config"))]
pub(super) struct SetConfig {
    /// A path in the RPC configuration tree to override.
    ///
    /// This path is either the empty string,
    /// or a sequence of period-separated configuration identifiers.
    /// The root of the tree can be represented as "." or as "".
    ///
    /// No validation is done to ensure that the identifiers are actually
    /// a recognized configuration option.
    key: String,

    /// A value to replace part of the RPC configuration tree.
    ///
    /// See the method description for an overview of the semantics
    /// of the RPC configuration tree.
    /// Notably, this method _replaces_ parts of the RPC configuration tree,
    /// and the RPC configuration tree is _merged into_
    /// the configuration from other sources.
    value: ConfigValue,
}

impl rpc::RpcMethod for SetConfig {
    type Output = rpc::Nil;
    type Update = rpc::NoUpdates;
}

/// Return the value of part of the configuration tree.
///
/// This method requires superuser access, since some options
/// (like onion service configurations) can be sensitive.
///
/// This method can return either the value for a single option,
/// or multiple values of the tree.
///
/// It returns the actual configuration values _as used_:
///
/// - All defaults are filled in.
/// - Any renamed options are replaced with their real names.
/// - Unrecognized options are omitted.
#[derive(Debug, serde::Deserialize, derive_deftly::Deftly)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "arti:get_config"))]
pub(super) struct GetConfig {
    /// A path in the RPC configuration tree to retrieve.
    ///
    /// This path is either the empty string,
    /// or a sequence of period-separated configuration identifiers.
    /// The root of the tree can be represented as "." or as "".
    key: String,
}

/// The result from a call to `arti:get_config`
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct GetConfigResult {
    /// A JSON value representing part of the configuration tree,
    /// or `null` if there is no value at that position in the tree.
    value: Option<ConfigValue>,
}

impl rpc::RpcMethod for GetConfig {
    type Output = GetConfigResult;
    type Update = rpc::NoUpdates;
}

/// RPC method implementation: invoke `arti:set_config` on a superuser session.
pub(super) async fn set_config_on_rpcsuperuser<R: Runtime>(
    session: Arc<RpcSuperuser<R>>,
    method: Box<SetConfig>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::Nil, rpc::RpcError> {
    let cfg_mgr = &session.cfg_mgr;
    cfg_mgr.try_modify_cfg(
        |cfg| {
            cfg.apply_key_value(method.key.as_str(), method.value.0);
            Ok(())
        },
        tor_config::Reconfigure::AllOrNothing,
    )?;
    Ok(rpc::Nil::default())
}

/// RPC method implementation: invoke `arti:get_config` on a supuruser session.
pub(super) async fn get_config_on_rpcsuperuser<R: Runtime>(
    session: Arc<RpcSuperuser<R>>,
    method: Box<GetConfig>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<GetConfigResult, rpc::RpcError> {
    let cfg_mgr = &session.cfg_mgr;
    let value = cfg_mgr
        .get_cfg_setting(method.key.as_str())
        .map_err(|e| rpc::RpcError::new(e.to_string(), rpc::RpcErrorKind::RequestError))?;
    Ok(GetConfigResult { value })
}
