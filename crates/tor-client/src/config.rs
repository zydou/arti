//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use crate::{Error, Result};
use derive_builder::Builder;
use serde::Deserialize;
use std::path::PathBuf;

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
        PathConfigBuilder, RequestTiming, RequestTimingBuilder,
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
/// use [`ClientConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize)]
#[builder]
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

/// Configuration used to bootstrap a `TorClient`.
#[derive(Clone, Debug, Builder)]
pub struct TorClientConfig {
    /// A directory suitable for storing persistent Tor state in.
    pub(crate) state_cfg: PathBuf,
    /// Configuration for the network directory manager.
    pub(crate) dir_cfg: dir::DirMgrConfig,
    /// Configuration for the network circuit manager.
    pub(crate) circ_cfg: circ::CircMgrConfig,
    /// Other client configuration.
    pub(crate) addr_cfg: ClientAddrConfig,
}

impl TorClientConfig {
    /// Returns a `TorClientConfig` using reasonably sane defaults.
    ///
    /// This uses `tor_config`'s definitions for `APP_LOCAL_DATA` and `APP_CACHE` for the state and
    /// cache directories respectively.
    pub fn sane_defaults() -> Result<Self> {
        let state_dir = tor_config::CfgPath::new("${APP_LOCAL_DATA}".into())
            .path()
            .map_err(|e| Error::Configuration(format!("failed to find APP_LOCAL_DATA: {:?}", e)))?;
        let cache_dir = tor_config::CfgPath::new("${APP_CACHE}".into())
            .path()
            .map_err(|e| Error::Configuration(format!("failed to find APP_CACHE: {:?}", e)))?;

        Self::with_directories(state_dir, cache_dir)
    }

    /// Returns a `TorClientConfig` using the specified state and cache directories, with other
    /// configuration options set to defaults.
    pub fn with_directories<P, Q>(state_dir: P, cache_dir: Q) -> Result<Self>
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        Ok(Self {
            state_cfg: state_dir.into(),
            dir_cfg: dir::DirMgrConfig::builder()
                .cache_path(cache_dir.into())
                .build()
                .map_err(|e| {
                    Error::Configuration(format!("failed to build DirMgrConfig: {}", e))
                })?,
            circ_cfg: Default::default(),
            addr_cfg: Default::default(),
        })
    }

    /// Return a new builder to construct a `TorClientConfig`.
    pub fn builder() -> TorClientConfigBuilder {
        TorClientConfigBuilder::default()
    }
}
