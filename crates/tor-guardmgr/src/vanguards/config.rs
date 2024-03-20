//! Vanguard manager configuration

use std::time::Duration;

use serde::{Deserialize, Serialize};

use tor_config::ConfigBuildError;
use tor_netdir::params::NetParameters;

use crate::VanguardMode;

/// The default L2 pool size.
const DEFAULT_L2_POOL_SIZE: usize = 4;

/// The default minimum lifetime of L2 guards.
const DEFAULT_L2_GUARD_LIFETIME_MIN: Duration = Duration::from_secs(3600 * 24);

/// The default maximum lifetime of L2 guards.
const DEFAULT_L2_GUARD_LIFETIME_MAX: Duration = Duration::from_secs(3600 * 24 * 12);

/// The default L3 pool size.
const DEFAULT_L3_POOL_SIZE: usize = 8;

/// The default minimum lifetime of L3 guards.
const DEFAULT_L3_GUARD_LIFETIME_MIN: Duration = Duration::from_secs(3600);

/// The default maximum lifetime of L3 guards.
const DEFAULT_L3_GUARD_LIFETIME_MAX: Duration = Duration::from_secs(3600 * 48);

/// Vanguards configuration.
#[derive(Debug, Default, Clone, Eq, PartialEq, derive_builder::Builder)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[derive(amplify::Getters)]
pub struct VanguardConfig {
    /// The kind of vanguards to use.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    #[getter(as_copy)]
    pub(super) mode: VanguardMode,
}

/// A set of parameters, derived from the consensus document,
/// controlling the behavior of a [`VanguardMgr`](crate::vanguards::VanguardMgr).
///
/// Note: these are not part of [`VanguardConfig`],
/// because like all Tor network parameters,
/// they can be overridden via the `TorClientConfig::override_net_params`.
#[allow(unused)] // TODO HS-VANGUARDS
#[derive(Debug, Clone)]
pub struct VanguardParams {
    /// The number of guards in the L2 guardset
    l2_pool_size: usize,
    /// The minimum lifetime of L2 guards
    l2_lifetime_min: Duration,
    /// The maximum lifetime of L2 guards
    l2_lifetime_max: Duration,
    /// The number of guards in the L3 guardset
    l3_pool_size: usize,
    /// The minimum lifetime of L3 guards
    l3_lifetime_min: Duration,
    /// The maximum lifetime of L3 guards
    l3_lifetime_max: Duration,
}

impl Default for VanguardParams {
    fn default() -> Self {
        Self {
            l2_pool_size: DEFAULT_L2_POOL_SIZE,
            l2_lifetime_min: DEFAULT_L2_GUARD_LIFETIME_MIN,
            l2_lifetime_max: DEFAULT_L2_GUARD_LIFETIME_MAX,
            l3_pool_size: DEFAULT_L3_POOL_SIZE,
            l3_lifetime_min: DEFAULT_L3_GUARD_LIFETIME_MIN,
            l3_lifetime_max: DEFAULT_L3_GUARD_LIFETIME_MAX,
        }
    }
}

impl TryFrom<&NetParameters> for VanguardParams {
    type Error = tor_units::Error;

    fn try_from(_p: &NetParameters) -> Result<VanguardParams, Self::Error> {
        // TODO: add the vanguards params to NetParameters
        Ok(Default::default())
    }
}
