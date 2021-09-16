//! Configuration logic for launching a circuit manager.

use derive_builder::Builder;
use serde::Deserialize;

use std::time::Duration;

/// Configuration for circuit timeouts and retries.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`RequestTimingBuilder`].
#[derive(Debug, Clone, Builder, Deserialize)]
#[builder]
pub struct RequestTiming {
    /// When a circuit is requested, we stop retrying new circuits
    /// after this much time.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "Duration::from_secs(60)")]
    #[serde(with = "humantime_serde")]
    pub(crate) request_timeout: Duration,

    /// When a circuit is requested, we stop retrying new circuits after
    /// this many attempts.
    // TODO: Impose a maximum or minimum?
    #[builder(default = "32")]
    pub(crate) request_max_retries: u32,

    /// When waiting for requested circuits, wait at least this long
    /// before using a suitable-looking circuit launched by some other
    /// request.
    #[builder(default = "Duration::from_millis(50)")]
    #[serde(with = "humantime_serde")]
    pub(crate) request_loyalty: Duration,
}

// NOTE: it seems that `unwrap` may be safe because of builder defaults
// check `derive_builder` documentation for details
// https://docs.rs/derive_builder/0.10.2/derive_builder/#default-values
#[allow(clippy::unwrap_used)]
impl Default for RequestTiming {
    fn default() -> Self {
        RequestTimingBuilder::default().build().unwrap()
    }
}

/// Rules for building paths over the network.
///
/// This type is immutable once constructed.  To build one, use
/// [`PathConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize, Default)]
#[builder]
pub struct PathConfig {
    /// Override the default required distance for two relays to share
    /// the same circuit.
    #[builder(default)]
    pub(crate) enforce_distance: tor_netdir::SubnetConfig,
}

/// Configuration for circuit timeouts, expiration, and so on.
///
/// This type is immutable once constructd. To create an object of this
/// type, use [`CircuitTimingBuilder`].
#[derive(Debug, Clone, Builder, Deserialize)]
#[builder]
pub struct CircuitTiming {
    /// How long after a circuit has first been used should we give
    /// it out for new requests?
    #[builder(default = "Duration::from_secs(60 * 10)")]
    #[serde(with = "humantime_serde")]
    pub(crate) max_dirtiness: Duration,
}

// NOTE: it seems that `unwrap` may be safe because of builder defaults
// check `derive_builder` documentation for details
// https://docs.rs/derive_builder/0.10.2/derive_builder/#default-values
#[allow(clippy::unwrap_used)]
impl Default for CircuitTiming {
    fn default() -> Self {
        CircuitTimingBuilder::default().build().unwrap()
    }
}

/// Configuration for a circuit manager.
///
/// This type is immutable once constructed.  To create an object of
/// this type, use [`CircMgrConfigBuilder`].
#[derive(Debug, Clone, Builder)]
#[builder]
pub struct CircMgrConfig {
    /// Override the default required distance for two relays to share
    /// the same circuit.
    #[builder(default)]
    pub(crate) path_config: PathConfig,

    /// Timing and retry information related to requests for circuits.
    #[builder(default)]
    pub(crate) request_timing: RequestTiming,

    /// Timing and retry information related to circuits themselves.
    #[builder(default)]
    pub(crate) circuit_timing: CircuitTiming,
}
