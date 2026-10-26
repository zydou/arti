//! Relay bandwidth rate limiting configuration.

use derive_deftly::Deftly;

use tor_basic_utils::ByteQty;
use tor_config::ConfigBuildError;
use tor_config::derive::prelude::*;

/// Minimum allowed `rate`: 10 Mbps (in bytes per second).
//
// TODO(relay): This limit is what I (dgoulet) think it should be an absolute minimum for
// any relays in the network. That is 1.25MB/sec which is even very low from what kind of
// capacity the network needs. C-tor is at 75KB/sec which is absurdly low. We can revisit
// this based on better metrics from the network but I would be on the fence to reduce
// it, happy to raise it ;). Remember that HSDir get picked on hashring position, not
// bandwidth weighted so overall slow relays are NOT helping onion services.
const MIN_RATE: ByteQty = ByteQty(10_000_000 / 8);

/// Global bandwidth management configuration.
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
#[derive_deftly(TorConfig)]
#[deftly(tor_config(post_build = "BandwidthConfig::post_build_validate"))]
pub(crate) struct BandwidthConfig {
    /// Average bandwidth limit in bytes per second.
    ///
    /// Example: "10 MB" for 10 megabytes per second. "MiB" can also be used for
    /// mebibytes per second.
    ///
    /// Must be at least 10 Mbps ("1.25 MB"). If unset, the relay bandwidth is not
    /// rate limited.
    #[deftly(tor_config(default))]
    pub(crate) rate: Option<ByteQty>,

    /// The bandwidth limit burst which is the maximum number of bytes that can be sent
    /// at once above the above `rate`.
    ///
    /// Must be greater than or equal to `rate`. Defaults to `rate` if unset.
    #[deftly(tor_config(default))]
    pub(crate) burst: Option<ByteQty>,
}

impl BandwidthConfig {
    /// Validate the config after building it.
    fn post_build_validate(mut self) -> Result<Self, ConfigBuildError> {
        let invalid = |field: &str, problem: &str| ConfigBuildError::Invalid {
            field: field.to_owned(),
            problem: problem.to_owned(),
        };

        let Some(rate) = self.rate else {
            if self.burst.is_some() {
                return Err(invalid("burst", "burst is set but not rate"));
            }
            return Ok(self);
        };
        if rate < MIN_RATE {
            return Err(invalid(
                "rate",
                &format!("rate must be at least {MIN_RATE} per second"),
            ));
        }
        let burst = *self.burst.get_or_insert(rate);
        if burst < rate {
            return Err(invalid(
                "burst",
                "burst must be greater than or equal to rate",
            ));
        }
        Ok(self)
    }
}
