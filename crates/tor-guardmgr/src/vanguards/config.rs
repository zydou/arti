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
#[derive(Debug, Clone, amplify::Getters)]
pub struct VanguardParams {
    /// The type of vanguards to use by default when building onion service circuits.
    #[getter(as_copy)]
    vanguards_enabled: VanguardMode,
    /// If higher than `vanguards-enabled`,
    /// and we are running an onion service,
    /// we use this level for all our onion service circuits.
    #[getter(as_copy)]
    vanguards_hs_service: VanguardMode,
    /// The number of guards in the L2 guardset
    #[getter(as_copy)]
    l2_pool_size: usize,
    /// The minimum lifetime of L2 guards
    #[getter(as_copy)]
    l2_lifetime_min: Duration,
    /// The maximum lifetime of L2 guards
    #[getter(as_copy)]
    l2_lifetime_max: Duration,
    /// The number of guards in the L3 guardset
    #[getter(as_copy)]
    l3_pool_size: usize,
    /// The minimum lifetime of L3 guards
    #[getter(as_copy)]
    l3_lifetime_min: Duration,
    /// The maximum lifetime of L3 guards
    #[getter(as_copy)]
    l3_lifetime_max: Duration,
}

impl Default for VanguardParams {
    fn default() -> Self {
        Self {
            vanguards_enabled: VanguardMode::Lite,
            vanguards_hs_service: VanguardMode::Full,
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

    fn try_from(p: &NetParameters) -> Result<VanguardParams, Self::Error> {
        // TODO HS-VANGUARDS: move the VanguardMode a VanguardParam too and consider removing
        // VanguardConfig altogether.

        /// Return a pair of `(min, max)` values representing a closed interval.
        ///
        /// If `min <= max`, returns `(min, max)`.
        /// Otherwise, returns `(default_min, default_max)`.
        fn lifetime_or_default(
            min: Duration,
            max: Duration,
            default_min: Duration,
            default_max: Duration,
        ) -> (Duration, Duration) {
            if min <= max {
                (min, max)
            } else {
                (default_min, default_max)
            }
        }

        let (l2_lifetime_min, l2_lifetime_max) = lifetime_or_default(
            p.guard_hs_l2_lifetime_min.try_into()?,
            p.guard_hs_l2_lifetime_max.try_into()?,
            DEFAULT_L2_GUARD_LIFETIME_MIN,
            DEFAULT_L2_GUARD_LIFETIME_MAX,
        );

        let (l3_lifetime_min, l3_lifetime_max) = lifetime_or_default(
            p.guard_hs_l3_lifetime_min.try_into()?,
            p.guard_hs_l3_lifetime_max.try_into()?,
            DEFAULT_L3_GUARD_LIFETIME_MIN,
            DEFAULT_L3_GUARD_LIFETIME_MAX,
        );

        Ok(VanguardParams {
            vanguards_enabled: VanguardMode::from_net_parameter(p.vanguards_enabled),
            vanguards_hs_service: VanguardMode::from_net_parameter(p.vanguards_hs_service),
            l2_pool_size: p.guard_hs_l2_number.try_into()?,
            l2_lifetime_min,
            l2_lifetime_max,
            l3_pool_size: p.guard_hs_l3_number.try_into()?,
            l3_lifetime_min,
            l3_lifetime_max,
        })
    }
}
