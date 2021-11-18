//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use crate::{Error, Result};
use derive_builder::Builder;
use serde::Deserialize;
use std::path::PathBuf;

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
    /// A directory suitable for storing persistent Tor state in.
    ///
    /// This is distinct from the cache directory set in `dir_cfg`:
    /// it is _not_ safe to delete this information regularly.
    ///
    /// Multiple instances of Arti may share the same state directory.
    pub(crate) state_cfg: PathBuf,

    /// Configuration for the network directory manager.
    ///
    /// This includes information on how to find and authenticate the
    /// Tor network, how to frequently to retry directory downloads,
    /// and where to store cached directory information.
    pub(crate) dir_cfg: dir::DirMgrConfig,

    /// Configuration for the network circuit manager.
    ///
    /// This includes information about how to build paths through the
    /// Tor network, and how to retry failed circuits.
    pub(crate) circ_cfg: circ::CircMgrConfig,

    /// Configures how the client interprets addresses on the network.
    pub(crate) addr_cfg: ClientAddrConfig,
}

impl TorClientConfig {
    /// Returns a `TorClientConfig` using reasonably sane defaults.
    ///
    /// This gies the same result as using `tor_config`'s definitions
    /// for `APP_LOCAL_DATA` and `APP_CACHE` for the state and cache
    /// directories respectively.
    ///
    /// (On unix, this usually works out to `~/.local/share/arti` and
    /// `~/.cache/arti`, depending on your environment.  We use the
    /// `directories` crate for reasonable defaults on other platforms.)
    pub fn sane_defaults() -> Result<Self> {
        // Note: this must stay in sync with project_dirs() in the
        // tor-config crate.
        let dirs =
            directories::ProjectDirs::from("org", "torproject", "Arti").ok_or_else(|| {
                Error::Configuration("Could not determine default directories".to_string())
            })?;

        let state_dir = dirs.data_local_dir();
        let cache_dir = dirs.cache_dir();

        Self::with_directories(state_dir, cache_dir)
    }

    /// Returns a `TorClientConfig` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults.
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
