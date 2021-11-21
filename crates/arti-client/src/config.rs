//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use derive_builder::Builder;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use tor_config::CfgPath;

pub use tor_config::ConfigBuildError;

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
        PathConfigBuilder,
    };
}

/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dirmgr::{
        Authority, AuthorityBuilder, DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig,
        DownloadScheduleConfigBuilder, FallbackDir, FallbackDirBuilder, NetworkConfig,
        NetworkConfigBuilder,
    };
}

/// Configuration for client behaviour relating to addresses.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientAddrConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct ClientAddrConfig {
    /// Should we allow attempts to make Tor connections to local addresses?
    ///
    /// This option is off by default, since (by default) Tor exits will
    /// always reject connections to such addresses.
    #[builder(default)]
    pub(crate) allow_local_addrs: bool,
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

/// Configuration for where information should be stored on disk.
///
/// This section is for read/write storage.
#[derive(Deserialize, Debug, Clone, Builder)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct StorageConfig {
    /// Location on disk for cached directory information
    #[builder(setter(into))]
    cache_dir: CfgPath,
    #[builder(setter(into))]
    /// Location on disk for less-sensitive persistent state information.
    state_dir: CfgPath,
}

impl StorageConfig {
    /// Return a new StorageConfigBuilder.
    pub fn builder() -> StorageConfigBuilder {
        StorageConfigBuilder::default()
    }

    /// Try to expand `state_dir` to be a path buffer.
    // TODO(nickm): This won't be public once we're done.
    pub fn expand_state_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "state_dir".to_owned(),
                problem: e.to_string(),
            })
    }
    /// Try to expand `cache_dir` to be a path buffer.
    // TODO(nickm): This won't be public once we're done.
    pub fn expand_cache_dir(&self) -> Result<PathBuf, ConfigBuildError> {
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
/// well-known directories on the network, and the public keys of the
/// network's directory authorities.  It also needs a place on disk to
/// store persistent state and cached directory information.
///
/// Most users will create a TorClientConfig by running
/// [`TorClientConfig::sane_defaults`].
///
/// If you need to override the locations where Arti stores its information,
/// you can make a TorClientConfig with [`TorClientConfig::with_directories`].
///
/// Finally, you can get fine-grained control over the members of a a
/// TorClientConfig using [`TorClientConfigBuilder`].
#[derive(Clone, Debug, Builder)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct TorClientConfig {
    /// Information about the Tor network we want to connect to.
    #[builder(default)]
    tor_network: dir::NetworkConfig,

    /// Directories for storing information on disk
    pub(crate) storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: dir::DownloadScheduleConfig,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[builder(default)]
    override_net_params: HashMap<String, i32>,

    /// Information about how to build paths through the network.
    path_rules: circ::PathConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    circuit_timing: circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    pub(crate) address_filter: ClientAddrConfig,
}

impl TorClientConfig {
    /// Return a new TorClientConfigBuilder.
    pub fn builder() -> TorClientConfigBuilder {
        TorClientConfigBuilder::default()
    }

    /// Returns a `TorClientConfig` using reasonably sane defaults.
    ///
    /// This gies the same result as using `tor_config`'s definitions
    /// for `APP_LOCAL_DATA` and `APP_CACHE` for the state and cache
    /// directories respectively.
    ///
    /// (On unix, this usually works out to `~/.local/share/arti` and
    /// `~/.cache/arti`, depending on your environment.  We use the
    /// `directories` crate for reasonable defaults on other platforms.)
    pub fn sane_defaults() -> Result<Self, ConfigBuildError> {
        // Note: this must stay in sync with project_dirs() in the
        // tor-config crate.
        let dirs =
            directories::ProjectDirs::from("org", "torproject", "Arti").ok_or_else(|| {
                ConfigBuildError::Invalid {
                    field: "directories".to_string(),
                    problem: "Could not determine default directories".to_string(),
                }
            })?;

        let state_dir = dirs.data_local_dir();
        let cache_dir = dirs.cache_dir();

        Self::with_directories(state_dir, cache_dir)
    }

    /// Returns a `TorClientConfig` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults.
    pub fn with_directories<P, Q>(state_dir: P, cache_dir: Q) -> Result<Self, ConfigBuildError>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let storage_cfg = StorageConfig::builder()
            .cache_dir(
                CfgPath::from_path(cache_dir).map_err(|e| ConfigBuildError::Invalid {
                    field: "cache_dir".to_owned(),
                    problem: e.to_string(),
                })?,
            )
            .state_dir(
                CfgPath::from_path(state_dir).map_err(|e| ConfigBuildError::Invalid {
                    field: "state_dir".to_owned(),
                    problem: e.to_string(),
                })?,
            )
            .build()
            .map_err(|e| e.within("storage"))?;

        Self::builder().storage(storage_cfg).build()
    }

    /// Build a DirMgrConfig from this configuration.
    pub(crate) fn get_dirmgr_config(&self) -> Result<dir::DirMgrConfig, ConfigBuildError> {
        let mut dircfg = dir::DirMgrConfigBuilder::default();
        dircfg.network_config(self.tor_network.clone());
        dircfg.schedule_config(self.download_schedule.clone());
        dircfg.cache_path(self.storage.expand_cache_dir()?);
        for (k, v) in self.override_net_params.iter() {
            dircfg.override_net_param(k.clone(), *v);
        }
        dircfg.build()
    }

    /// Return a [`CircMgrConfig`] object based on the user's selected
    /// configuration.
    pub(crate) fn get_circmgr_config(&self) -> Result<circ::CircMgrConfig, ConfigBuildError> {
        let mut builder = circ::CircMgrConfigBuilder::default();
        builder
            .path_rules(self.path_rules.clone())
            .circuit_timing(self.circuit_timing.clone())
            .build()
    }
}
