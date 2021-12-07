//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use derive_builder::Builder;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tor_config::CfgPath;

pub use tor_config::ConfigBuildError;

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
        PathConfigBuilder, PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
    };
}

/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dirmgr::{
        Authority, AuthorityBuilder, DirMgrConfig, DirMgrConfigBuilder, DownloadSchedule,
        DownloadScheduleConfig, DownloadScheduleConfigBuilder, FallbackDir, FallbackDirBuilder,
        NetworkConfig, NetworkConfigBuilder,
    };
}

/// Configuration for client behavior relating to addresses.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientAddrConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[serde(deny_unknown_fields)]
pub struct ClientAddrConfig {
    /// Should we allow attempts to make Tor connections to local addresses?
    ///
    /// This option is off by default, since (by default) Tor exits will
    /// always reject connections to such addresses.
    #[builder(default)]
    #[serde(default)]
    pub(crate) allow_local_addrs: bool,
}

/// Configuration for client behavior relating to connection timeouts
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientTimeoutConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientTimeoutConfig {
    /// How long should we wait before timing out a stream when connecting
    /// to a host?
    #[builder(default = "default_connect_timeout()")]
    #[serde(with = "humantime_serde", default = "default_connect_timeout")]
    pub(crate) connect_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS record?
    #[builder(default = "default_dns_resolve_timeout()")]
    #[serde(with = "humantime_serde", default = "default_dns_resolve_timeout")]
    pub(crate) resolve_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS
    /// PTR record?
    #[builder(default = "default_dns_resolve_ptr_timeout()")]
    #[serde(with = "humantime_serde", default = "default_dns_resolve_ptr_timeout")]
    pub(crate) resolve_ptr_timeout: Duration,
}

// NOTE: it seems that `unwrap` may be safe because of builder defaults
// check `derive_builder` documentation for details
// https://docs.rs/derive_builder/0.10.2/derive_builder/#default-values
#[allow(clippy::unwrap_used)]
impl Default for ClientAddrConfig {
    fn default() -> Self {
        ClientAddrConfigBuilder::default().build().unwrap()
    }
}

impl From<ClientAddrConfig> for ClientAddrConfigBuilder {
    fn from(cfg: ClientAddrConfig) -> ClientAddrConfigBuilder {
        let mut builder = ClientAddrConfigBuilder::default();
        builder.allow_local_addrs(cfg.allow_local_addrs);
        builder
    }
}

impl ClientAddrConfig {
    /// Return a new [`ClientAddrConfigBuilder`].
    pub fn builder() -> ClientAddrConfigBuilder {
        ClientAddrConfigBuilder::default()
    }
}

#[allow(clippy::unwrap_used)]
impl Default for ClientTimeoutConfig {
    fn default() -> Self {
        ClientTimeoutConfigBuilder::default().build().unwrap()
    }
}

impl From<ClientTimeoutConfig> for ClientTimeoutConfigBuilder {
    fn from(cfg: ClientTimeoutConfig) -> ClientTimeoutConfigBuilder {
        let mut builder = ClientTimeoutConfigBuilder::default();
        builder
            .connect_timeout(cfg.connect_timeout)
            .resolve_timeout(cfg.resolve_timeout)
            .resolve_ptr_timeout(cfg.resolve_ptr_timeout);

        builder
    }
}

impl ClientTimeoutConfig {
    /// Return a new [`ClientTimeoutConfigBuilder`].
    pub fn builder() -> ClientTimeoutConfigBuilder {
        ClientTimeoutConfigBuilder::default()
    }
}

/// Return the default stream timeout
fn default_connect_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default resolve timeout
fn default_dns_resolve_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default PTR resolve timeout
fn default_dns_resolve_ptr_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Configuration for where information should be stored on disk.
///
/// By default, cache information will be stored in `${ARTI_CACHE}`, and
/// persistent state will be stored in `${ARTI_LOCAL_DATA}`.  That means that
/// _all_ programs using these defaults will share their cache and state data.
/// If that isn't what you want,  you'll need to override these directories.
///
/// On unix, the default directories will typically expand to `~/.cache/arti`
/// and `~/.local/share/arti/` respectively, depending on the user's
/// environment. Other platforms will also use suitable defaults. For more
/// information, see the documentation for [`CfgPath`].
///
/// This section is for read/write storage.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct StorageConfig {
    /// Location on disk for cached directory information.
    #[builder(setter(into), default = "default_cache_dir()")]
    #[serde(default = "default_cache_dir")]
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    #[builder(setter(into), default = "default_state_dir()")]
    #[serde(default = "default_state_dir")]
    state_dir: CfgPath,
}

/// Return the default cache directory.
fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_CACHE}".to_owned())
}

/// Return the default state directory.
fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}".to_owned())
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::builder().build().expect("Default builder failed")
    }
}

impl StorageConfig {
    /// Return a new StorageConfigBuilder.
    pub fn builder() -> StorageConfigBuilder {
        StorageConfigBuilder::default()
    }

    /// Try to expand `state_dir` to be a path buffer.
    pub(crate) fn expand_state_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "state_dir".to_owned(),
                problem: e.to_string(),
            })
    }
    /// Try to expand `cache_dir` to be a path buffer.
    pub(crate) fn expand_cache_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "cache_dir".to_owned(),
                problem: e.to_string(),
            })
    }
}

impl From<StorageConfig> for StorageConfigBuilder {
    fn from(cfg: StorageConfig) -> StorageConfigBuilder {
        let mut builder = StorageConfigBuilder::default();
        builder.state_dir(cfg.state_dir).cache_dir(cfg.cache_dir);
        builder
    }
}

/// A configuration used to bootstrap a [`TorClient`](crate::TorClient).
///
/// In order to connect to the Tor network, Arti needs to know a few
/// well-known directory caches on the network, and the public keys of the
/// network's directory authorities.  It also needs a place on disk to
/// store persistent state and cached directory information. (See [`StorageConfig`]
/// for default directories.)
///
/// Most users will create a TorClientConfig by running
/// [`TorClientConfig::default`].
///
/// If you need to override the locations where Arti stores its
/// information, you can make a TorClientConfig with
/// [`TorClientConfigBuilder::from_directories`].
///
/// Finally, you can get fine-grained control over the members of a a
/// TorClientConfig using [`TorClientConfigBuilder`].
///
/// NOTE: These are NOT the final options or their final layout.
/// Expect NO stability here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorClientConfig {
    /// Information about the Tor network we want to connect to.
    tor_network: dir::NetworkConfig,

    /// Directories for storing information on disk
    pub(crate) storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: dir::DownloadScheduleConfig,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    override_net_params: HashMap<String, i32>,

    /// Information about how to build paths through the network.
    path_rules: circ::PathConfig,

    /// Information about preemptive circuits.
    preemptive_circuits: circ::PreemptiveCircuitConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    circuit_timing: circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    pub(crate) address_filter: ClientAddrConfig,

    /// Information about timing out client requests.
    pub(crate) stream_timeouts: ClientTimeoutConfig,
}

impl Default for TorClientConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("Could not build TorClientConfig from default configuration.")
    }
}

impl TorClientConfig {
    /// Return a new TorClientConfigBuilder.
    pub fn builder() -> TorClientConfigBuilder {
        TorClientConfigBuilder::default()
    }

    /// Build a DirMgrConfig from this configuration.
    pub(crate) fn get_dirmgr_config(&self) -> Result<dir::DirMgrConfig, ConfigBuildError> {
        let mut dircfg = dir::DirMgrConfigBuilder::default();
        dircfg.network_config(self.tor_network.clone());
        dircfg.schedule_config(self.download_schedule.clone());
        dircfg.cache_path(self.storage.expand_cache_dir()?);
        for (k, v) in &self.override_net_params {
            dircfg.override_net_param(k.clone(), *v);
        }
        dircfg.build()
    }

    /// Return a [`CircMgrConfig`](circ::CircMgrConfig) object based on the user's selected
    /// configuration.
    pub(crate) fn get_circmgr_config(&self) -> Result<circ::CircMgrConfig, ConfigBuildError> {
        let mut builder = circ::CircMgrConfigBuilder::default();
        builder
            .path_rules(self.path_rules.clone())
            .circuit_timing(self.circuit_timing.clone())
            .build()
    }
}

/// Builder object used to construct a [`TorClientConfig`].
///
/// Unlike other builder types in Arti, this builder works by exposing an
/// inner builder for each section in the [`TorClientConfig`].
#[derive(Clone, Default)]
pub struct TorClientConfigBuilder {
    /// Inner builder for the `tor_network` section.
    tor_network: dir::NetworkConfigBuilder,
    /// Inner builder for the `storage` section.
    storage: StorageConfigBuilder,
    /// Inner builder for the `download_schedule` section.
    download_schedule: dir::DownloadScheduleConfigBuilder,
    /// Inner builder for the `override_net_params` section.
    override_net_params: HashMap<String, i32>,
    /// Inner builder for the `path_rules` section.
    path_rules: circ::PathConfigBuilder,
    /// Inner builder for the `circuit_timing` section.
    preemptive_circuits: circ::PreemptiveCircuitConfigBuilder,
    /// Inner builder for the `circuit_timing` section.
    circuit_timing: circ::CircuitTimingBuilder,
    /// Inner builder for the `address_filter` section.
    address_filter: ClientAddrConfigBuilder,
    /// Inner builder for the `stream_timeouts
    //` section.
    stream_timeouts: ClientTimeoutConfigBuilder,
}

impl TorClientConfigBuilder {
    /// Construct a [`TorClientConfig`] from this builder.
    pub fn build(&self) -> Result<TorClientConfig, ConfigBuildError> {
        let tor_network = self
            .tor_network
            .build()
            .map_err(|e| e.within("tor_network"))?;
        let storage = self.storage.build().map_err(|e| e.within("storage"))?;
        let download_schedule = self
            .download_schedule
            .build()
            .map_err(|e| e.within("download_schedule"))?;
        let override_net_params = self.override_net_params.clone();
        let path_rules = self
            .path_rules
            .build()
            .map_err(|e| e.within("path_rules"))?;
        let preemptive_circuits = self
            .preemptive_circuits
            .build()
            .map_err(|e| e.within("preemptive_circuits"))?;
        let circuit_timing = self
            .circuit_timing
            .build()
            .map_err(|e| e.within("circuit_timing"))?;
        let address_filter = self
            .address_filter
            .build()
            .map_err(|e| e.within("address_filter"))?;
        let stream_timeouts = self
            .stream_timeouts
            .build()
            .map_err(|e| e.within("stream_timeouts"))?;

        Ok(TorClientConfig {
            tor_network,
            storage,
            download_schedule,
            override_net_params,
            path_rules,
            preemptive_circuits,
            circuit_timing,
            address_filter,
            stream_timeouts,
        })
    }

    /// Returns a `TorClientConfigBuilder` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults.
    pub fn from_directories<P, Q>(state_dir: P, cache_dir: Q) -> Self
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let mut builder = Self::default();
        builder
            .storage()
            .cache_dir(CfgPath::from_path(cache_dir))
            .state_dir(CfgPath::from_path(state_dir));
        builder
    }

    /// Return a mutable reference to a
    /// [`NetworkConfigBuilder`](dir::NetworkConfigBuilder)
    /// to use in configuring the underlying Tor network.
    ///
    /// Most programs shouldn't need to alter this configuration: it's only for
    /// cases when you need to use a nonstandard set of Tor directory authorities
    /// and fallback caches.
    pub fn tor_network(&mut self) -> &mut dir::NetworkConfigBuilder {
        &mut self.tor_network
    }

    /// Return a mutable reference to a [`StorageConfigBuilder`].
    ///
    /// This section is used to configure the locations where Arti should
    /// store files on disk.
    pub fn storage(&mut self) -> &mut StorageConfigBuilder {
        &mut self.storage
    }

    /// Return a mutable reference to a
    /// [`DownloadScheduleConfigBuilder`](dir::DownloadScheduleConfigBuilder).
    ///
    /// This section is used to override Arti's schedule when attempting and
    /// retrying to download directory objects.
    pub fn download_schedule(&mut self) -> &mut dir::DownloadScheduleConfigBuilder {
        &mut self.download_schedule
    }

    /// Return a mutable reference to a [`HashMap`] of network parameters
    /// that should be used to override those specified in the consensus
    /// directory.
    ///
    /// This section should not usually be used for anything but testing:
    /// if you find yourself needing to configure an override here for
    /// production use, please consider opening a feature request for it
    /// instead.
    ///
    /// For a complete list of Tor's defined network parameters (not all of
    /// which are yet supported by Arti), see
    /// [`path-spec.txt`](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/param-spec.txt).
    pub fn override_net_params(&mut self) -> &mut HashMap<String, i32> {
        &mut self.override_net_params
    }

    /// Return a mutable reference to a [`PathConfigBuilder`](circ::PathConfigBuilder).
    ///
    /// This section is used to override Arti's rules for selecting which
    /// relays should be used in a given circuit.
    pub fn path_rules(&mut self) -> &mut circ::PathConfigBuilder {
        &mut self.path_rules
    }

    /// Return a mutable reference to a [`PreemptiveCircuitConfigBuilder`](circ::PreemptiveCircuitConfigBuilder).
    ///
    /// This section overrides Arti's rules for preemptive circuits.
    pub fn preemptive_circuits(&mut self) -> &mut circ::PreemptiveCircuitConfigBuilder {
        &mut self.preemptive_circuits
    }

    /// Return a mutable reference to a [`CircuitTimingBuilder`](circ::CircuitTimingBuilder).
    ///
    /// This section overrides Arti's rules for deciding how long to use
    /// circuits, and when to give up on attempts to launch them.
    pub fn circuit_timing(&mut self) -> &mut circ::CircuitTimingBuilder {
        &mut self.circuit_timing
    }

    /// Return a mutable reference to a [`ClientAddrConfigBuilder`].
    ///
    /// This section controls which addresses Arti is willing to launch connections
    /// to over the Tor network.  Any addresses rejected by this section cause
    /// stream attempts to fail before any traffic is sent over the network.
    pub fn address_filter(&mut self) -> &mut ClientAddrConfigBuilder {
        &mut self.address_filter
    }
}

impl From<TorClientConfig> for TorClientConfigBuilder {
    fn from(cfg: TorClientConfig) -> TorClientConfigBuilder {
        let TorClientConfig {
            tor_network,
            storage,
            download_schedule,
            override_net_params,
            path_rules,
            preemptive_circuits,
            circuit_timing,
            address_filter,
            stream_timeouts,
        } = cfg;

        TorClientConfigBuilder {
            tor_network: tor_network.into(),
            storage: storage.into(),
            download_schedule: download_schedule.into(),
            override_net_params,
            path_rules: path_rules.into(),
            preemptive_circuits: preemptive_circuits.into(),
            circuit_timing: circuit_timing.into(),
            address_filter: address_filter.into(),
            stream_timeouts: stream_timeouts.into(),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn defaults() {
        let dflt = TorClientConfig::default();
        let b2 = TorClientConfigBuilder::from(dflt.clone());
        let dflt2 = b2.build().unwrap();
        assert_eq!(&dflt, &dflt2);
    }

    #[test]
    fn builder() {
        use tor_dirmgr::DownloadSchedule;
        let sec = std::time::Duration::from_secs(1);

        let auth = dir::Authority::builder()
            .name("Fred")
            .v3ident([22; 20].into())
            .build()
            .unwrap();
        let fallback = dir::FallbackDir::builder()
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports(vec!["127.0.0.7:7".parse().unwrap()])
            .build()
            .unwrap();

        let mut bld = TorClientConfig::builder();
        bld.tor_network()
            .authorities(vec![auth])
            .fallback_caches(vec![fallback]);
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.download_schedule()
            .retry_certs(DownloadSchedule::new(10, sec, 3))
            .retry_microdescs(DownloadSchedule::new(30, 10 * sec, 9));
        bld.override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        // Reconstruct, rebuild, and validate.
        let bld2 = TorClientConfigBuilder::from(val.clone());
        let val2 = bld2.build().unwrap();
        assert_eq!(val, val2);

        assert_ne!(val, TorClientConfig::default());
    }
}
