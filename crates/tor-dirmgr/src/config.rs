//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.

use crate::retry::RetryConfig;
use crate::storage::sqlite::SqliteStore;
use crate::Authority;
use crate::{Error, Result};
use tor_netdir::fallback::FallbackDir;
use tor_netdoc::doc::netstatus;

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Configuration information about the Tor network itself; used as
/// part of Arti's configuration.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information,
    /// if we don't actually have a directory yet.
    ///
    /// (If we do have a cached directory, we use directory caches
    /// listed there instead.)
    #[serde(default = "fallbacks::default_fallbacks")]
    fallback_cache: Vec<FallbackDir>,

    /// List of directory authorities which we expect to sign
    /// consensus documents.
    #[serde(default = "crate::authority::default_authorities")]
    authority: Vec<Authority>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            fallback_cache: fallbacks::default_fallbacks(),
            authority: crate::authority::default_authorities(),
        }
    }
}

impl NetworkConfig {
    /// Return a new builder to construct a NetworkConfig.
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::new()
    }
    /// Return the configured directory authorities
    pub fn authorities(&self) -> &[Authority] {
        &self.authority[..]
    }
    /// Return the configured fallback directories
    pub fn fallbacks(&self) -> &[FallbackDir] {
        &self.fallback_cache[..]
    }
}

/// An object used to build a network configuration.  You shouldn't
/// need to use one of these directly for working on the standard Tor
/// network; the defaults are correct for use there.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfigBuilder {
    /// See [`NetworkConfig::fallback_cache`].  This is an option because
    /// we need to distinguish "no fallback directories" from "default
    /// fallback directories".
    fallbacks: Option<Vec<FallbackDir>>,
    /// See [`NetworkConfig::authority`].  This is an option because
    /// we need to distinguish "no fallback directories" from "default
    /// fallback authorities".
    authorities: Option<Vec<Authority>>,
}

impl NetworkConfigBuilder {
    /// Return a new NetworkConfigBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `fallback` as a fallback directory.
    ///
    /// Fallback directories are used to reach the Tor network if the
    /// client has not yet retrieved any other directory information.
    ///
    /// By default, if we are using the default set of authorities, we
    /// use a hardcoded set of fallback directories chosen from the
    /// Tor network.  Using this function or the `authority()`
    /// function means that we will not be using the default set of
    /// fallback directories.
    pub fn fallback(&mut self, fallback: FallbackDir) -> &mut Self {
        self.fallbacks.get_or_insert_with(Vec::new).push(fallback);
        self
    }

    /// Add `authority` as a directory authority.
    ///
    /// Directory authorities are a trusted set of servers that
    /// periodically sign documents attesting to the state of the Tor
    /// network.
    ///
    /// By default, we use the set of authorities that maintains the real
    /// Tor network.  Calling this function opts out of using that set.
    pub fn authority(&mut self, auth: Authority) -> &mut Self {
        self.authorities.get_or_insert_with(Vec::new).push(auth);
        self
    }

    /// Try to build a network configuration corresponding to the
    /// information in this builder.
    pub fn build(&self) -> Result<NetworkConfig> {
        let using_default_authorities = self.authorities.is_none();
        let authority = self
            .authorities
            .clone()
            .unwrap_or_else(crate::authority::default_authorities);
        let fallback_cache = if using_default_authorities {
            self.fallbacks
                .clone()
                .unwrap_or_else(fallbacks::default_fallbacks)
        } else {
            self.fallbacks.clone().unwrap_or_else(Vec::new)
        };

        Ok(NetworkConfig {
            fallback_cache,
            authority,
        })
    }
}

/// Configuration information for how exactly we download things from the
/// Tor directory caches.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DownloadScheduleConfig {
    /// Top-level configuration for how to retry our initial bootstrap attempt.
    #[serde(default = "default_retry_bootstrap")]
    retry_bootstrap: RetryConfig,

    /// Configuration for how to retry a consensus download.
    #[serde(default)]
    retry_consensus: RetryConfig,

    /// Configuration for how to retry an authority cert download.
    #[serde(default)]
    retry_certs: RetryConfig,

    /// Configuration for how to retry a microdescriptor download.
    #[serde(default)]
    retry_microdescs: RetryConfig,

    /// Number of microdescriptor downloads to attempt in parallel
    #[serde(default = "default_microdesc_parallelism")]
    microdesc_parallelism: u8,
}

/// Default value for retry_bootstrap in DownloadScheduleConfig.
fn default_retry_bootstrap() -> RetryConfig {
    RetryConfig::new(128, std::time::Duration::new(1, 0))
}
/// Default value for microdesc_parallelism in DownloadScheduleConfig.
fn default_microdesc_parallelism() -> u8 {
    4
}

impl Default for DownloadScheduleConfig {
    fn default() -> Self {
        DownloadScheduleConfig {
            retry_bootstrap: default_retry_bootstrap(),
            retry_consensus: Default::default(),
            retry_certs: Default::default(),
            retry_microdescs: Default::default(),
            microdesc_parallelism: default_microdesc_parallelism(),
        }
    }
}

impl DownloadScheduleConfig {
    /// Return a new builder to make a [`DownloadScheduleConfig`]
    pub fn builder() -> DownloadScheduleConfigBuilder {
        DownloadScheduleConfigBuilder::new()
    }
}

/// Builder for a [`DownloadScheduleConfig`].
#[derive(Debug, Clone, Default)]
pub struct DownloadScheduleConfigBuilder {
    /// The DownloadScheduleConfig we're building.
    ///
    /// (There aren't currently any inconsistent partially constructed
    /// states for this object, so we can just use an internal object.
    /// We don't precisely need a builder here, but let's keep it for
    /// consistency.)
    inner: DownloadScheduleConfig,
}

impl DownloadScheduleConfigBuilder {
    /// Construct a new builder to make a [`DownloadScheduleConfig`].
    ///
    /// All fields are optional, and are set to reasonable defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the configuration for retrying our initial bootstrap attempt.
    ///
    /// Unlike other retry configurations, this should have a higher number
    /// of attempts: if we were to 'give up' here, we would never get a
    /// usable directory.
    pub fn retry_bootstrap(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_bootstrap = sched;
        self
    }

    /// Configure the schedule for retrying a consensus download.
    pub fn retry_consensus(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_consensus = sched;
        self
    }

    /// Configure the schedule for retrying an authority certificate
    /// download.
    pub fn retry_certs(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_certs = sched;
        self
    }

    /// Configure the schedule for retrying a microdescriptor download.
    pub fn retry_microdescs(&mut self, sched: RetryConfig) -> &mut Self {
        self.inner.retry_microdescs = sched;
        self
    }

    /// Set the number of microdescriptor downloads that we should be
    /// allowed to launch in parallel.
    ///
    /// The default value is 4.
    pub fn microdesc_parallelism(&mut self, parallelism: u8) -> &mut Self {
        self.inner.microdesc_parallelism = parallelism;
        self
    }

    /// Try to construct a download schedule configuration from this builder.
    pub fn build(&self) -> Result<DownloadScheduleConfig> {
        Ok(self.inner.clone())
    }
}

/// Builder for a [`DirMgrConfig`]
///
/// To create a directory configuration, create one of these,
/// configure it, then call its build function.
///
/// # Examples
///
/// ```
/// # use tor_dirmgr::*;
/// # fn x() -> anyhow::Result<()> {
/// let mut builder = DirMgrConfigBuilder::new();
/// builder.use_default_cache_path()?;
/// let config: DirMgrConfig = builder.build()?;
/// # Ok(()) }
/// # x().unwrap()
/// ```
#[derive(Debug, Clone, Default)]
pub struct DirMgrConfigBuilder {
    /// Path to use for current (sqlite) directory information.
    cache_path: Option<PathBuf>,

    /// Configuration information about the network.
    network: NetworkConfig,

    /// Configuration information about when to download stuff.
    schedule: DownloadScheduleConfig,

    /// A map of network parameters that we're overriding from their
    /// settings in the consensus.
    override_net_params: netstatus::NetParams<i32>,
}

/// Configuration type for network directory operations.
///
/// This type is immutable once constructed.
///
/// To create an object of this type, use DirMgrConfigBuilder.
#[derive(Debug, Clone)]
pub struct DirMgrConfig {
    /// Location to use for storing and reading current-format
    /// directory information.
    cache_path: PathBuf,

    /// Configuration information about the network.
    network: NetworkConfig,

    /// Configuration information about when we download things.
    schedule: DownloadScheduleConfig,

    /// A map of network parameters that we're overriding from their
    /// settings in the consensus.
    override_net_params: netstatus::NetParams<i32>,
}

impl DirMgrConfigBuilder {
    /// Construct a new DirMgrConfig.
    ///
    /// To use this, call at least one method to set a cache directory,
    /// then call load().
    pub fn new() -> Self {
        DirMgrConfigBuilder::default()
    }

    /// Set the network information (authorities and fallbacks) from `config`.
    ///
    /// (You shouldn't need to replace the defaults unless you are
    /// using a private Tor network, a testing-only Tor network, or a
    /// network that is otherwise nonstandard.)
    pub fn network_config(&mut self, config: NetworkConfig) -> &mut Self {
        self.network = config;
        self
    }

    /// Set the timing information that we use for deciding when to
    /// attempt and retry downloads.
    ///
    /// (The defaults should be reasonable for most use cases.)
    pub fn schedule_config(&mut self, schedule: DownloadScheduleConfig) -> &mut Self {
        self.schedule = schedule;
        self
    }

    /// Use `path` as the directory to use for current directory files.
    pub fn cache_path(&mut self, path: &Path) -> &mut Self {
        self.cache_path = Some(path.to_path_buf());
        self
    }

    /// Overrides the network consensus parameter named `param` with a
    /// new value.
    ///
    /// If the new value is out of range, it will be clamped to the
    /// acceptable range.
    ///
    /// If the parameter is not recognized by Arti, it will be
    /// ignored, and a warning will be produced when we try to apply
    /// it to the consensus.
    ///
    /// By default no parameters will be overridden.
    pub fn override_net_param(&mut self, param: String, value: i32) -> &mut Self {
        self.override_net_params.set(param, value);
        self
    }

    /// Try to use the default cache path.
    ///
    /// This will be ~/.cache/arti on unix, and in other suitable
    /// locations on other platforms.
    pub fn use_default_cache_path(&mut self) -> Result<&mut Self> {
        let pd = directories::ProjectDirs::from("org", "torproject", "Arti")
            .ok_or(Error::DirectoryNotPresent)?;

        self.cache_path = Some(pd.cache_dir().into());

        Ok(self)
    }

    /// Use this builder to produce a DirMgrConfig that can be used
    /// to load directories
    pub fn build(&self) -> Result<DirMgrConfig> {
        let cache_path = self
            .cache_path
            .as_ref()
            .ok_or(Error::BadNetworkConfig("No cache path configured"))?;

        if self.network.authority.is_empty() {
            return Err(Error::BadNetworkConfig("No authorities configured").into());
        }
        if self.network.fallback_cache.is_empty() {
            return Err(Error::BadNetworkConfig("No fallback caches configured").into());
        }

        Ok(DirMgrConfig {
            cache_path: cache_path.clone(),
            network: self.network.clone(),
            schedule: self.schedule.clone(),
            override_net_params: self.override_net_params.clone(),
        })
    }
}

impl DirMgrConfig {
    /// Return a new builder to construct a DirMgrConfig.
    pub fn builder() -> DirMgrConfigBuilder {
        DirMgrConfigBuilder::new()
    }

    /// Create a SqliteStore from this configuration.
    ///
    /// Note that each time this is called, a new store object will be
    /// created: you probably only want to call this once.
    ///
    /// The `readonly` argument is as for [`SqliteStore::from_path`]
    pub(crate) fn open_sqlite_store(&self, readonly: bool) -> Result<SqliteStore> {
        SqliteStore::from_path(&self.cache_path, readonly)
    }

    /// Return a slice of the configured authorities
    pub fn authorities(&self) -> &[Authority] {
        self.network.authorities()
    }

    /// Return the configured set of fallback directories
    pub fn fallbacks(&self) -> &[FallbackDir] {
        self.network.fallbacks()
    }

    /// Return set of configured networkstatus parameter overrides.
    pub fn override_net_params(&self) -> &netstatus::NetParams<i32> {
        &self.override_net_params
    }

    /// Return the schedule configuration we should use to decide when to
    /// attempt and retry downloads.
    pub fn schedule(&self) -> &DownloadScheduleConfig {
        &self.schedule
    }
}

impl DownloadScheduleConfig {
    /// Return configuration for retrying our entire bootstrap
    /// operation at startup.
    pub fn retry_bootstrap(&self) -> &RetryConfig {
        &self.retry_bootstrap
    }

    /// Return configuration for retrying a consensus download.
    pub fn retry_consensus(&self) -> &RetryConfig {
        &self.retry_consensus
    }

    /// Return configuration for retrying an authority certificate download
    pub fn retry_certs(&self) -> &RetryConfig {
        &self.retry_certs
    }

    /// Return configuration for retrying an authority certificate download
    pub fn retry_microdescs(&self) -> &RetryConfig {
        &self.retry_microdescs
    }

    /// Number of microdescriptor fetches to attempt in parallel
    pub fn microdesc_parallelism(&self) -> usize {
        self.microdesc_parallelism.max(1).into()
    }
}

/// Helpers for initializing the fallback list.
mod fallbacks {
    use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
    use tor_netdir::fallback::FallbackDir;
    /// Return a list of the default fallback directories shipped with
    /// arti.
    pub(crate) fn default_fallbacks() -> Vec<super::FallbackDir> {
        /// Build a fallback directory; panic if input is bad.
        fn fallback(rsa: &str, ed: &str, ports: &[&str]) -> FallbackDir {
            let rsa = hex::decode(rsa).expect("Bad hex in built-in fallback list");
            let rsa =
                RsaIdentity::from_bytes(&rsa).expect("Wrong length in built-in fallback list");
            let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
                .expect("Bad hex in built-in fallback list");
            let ed =
                Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
            let mut bld = FallbackDir::builder();
            bld.rsa_identity(rsa).ed_identity(ed);

            ports
                .iter()
                .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
                .for_each(|p| {
                    bld.orport(p);
                });

            bld.build()
                .expect("Unable to build default fallback directory!?")
        }
        include!("fallback_dirs.inc")
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn simplest_config() -> Result<()> {
        let tmp = tempdir().unwrap();

        let dir = DirMgrConfigBuilder::new().cache_path(tmp.path()).build()?;

        assert!(dir.authorities().len() >= 3);
        assert!(dir.fallbacks().len() >= 3);

        // TODO: verify other defaults.

        Ok(())
    }

    #[test]
    fn build_network() -> Result<()> {
        let dflt = NetworkConfig::default();

        // with nothing set, we get the default.
        let mut bld = NetworkConfig::builder();
        let cfg = bld.build()?;
        assert_eq!(cfg.authorities().len(), dflt.authority.len());
        assert_eq!(cfg.fallbacks().len(), dflt.fallback_cache.len());

        // with any authorities set, the fallback list becomes empty
        // unless you set it.
        bld.authority(
            Authority::builder()
                .name("Hello")
                .v3ident([b'?'; 20].into())
                .build()?,
        );
        bld.authority(
            Authority::builder()
                .name("world")
                .v3ident([b'!'; 20].into())
                .build()?,
        );
        let cfg = bld.build()?;
        assert_eq!(cfg.authorities().len(), 2);
        assert!(cfg.fallbacks().is_empty());

        bld.fallback(
            FallbackDir::builder()
                .rsa_identity([b'x'; 20].into())
                .ed_identity([b'y'; 32].into())
                .orport("127.0.0.1:99".parse().unwrap())
                .orport("[::]:99".parse().unwrap())
                .build()?,
        );
        let cfg = bld.build()?;
        assert_eq!(cfg.authorities().len(), 2);
        assert_eq!(cfg.fallbacks().len(), 1);

        Ok(())
    }

    #[test]
    fn build_schedule() -> Result<()> {
        use std::time::Duration;
        let mut bld = DownloadScheduleConfig::builder();

        let cfg = bld.build()?;
        assert_eq!(cfg.microdesc_parallelism(), 4);
        assert_eq!(cfg.retry_microdescs().n_attempts(), 3);
        assert_eq!(cfg.retry_bootstrap().n_attempts(), 128);

        bld.microdesc_parallelism(0)
            .retry_consensus(RetryConfig::new(7, Duration::new(86400, 0)))
            .retry_bootstrap(RetryConfig::new(4, Duration::new(3600, 0)))
            .retry_certs(RetryConfig::new(5, Duration::new(3600, 0)))
            .retry_microdescs(RetryConfig::new(6, Duration::new(3600, 0)));

        let cfg = bld.build()?;
        assert_eq!(cfg.microdesc_parallelism(), 1); // gets clamped to 1
        assert_eq!(cfg.retry_microdescs().n_attempts(), 6);
        assert_eq!(cfg.retry_bootstrap().n_attempts(), 4);
        assert_eq!(cfg.retry_consensus().n_attempts(), 7);
        assert_eq!(cfg.retry_certs().n_attempts(), 5);

        Ok(())
    }

    #[test]
    fn build_dirmgrcfg() -> Result<()> {
        let mut bld = DirMgrConfig::builder();
        let tmp = tempdir().unwrap();

        let cfg = bld
            .override_net_param("circwindow".into(), 999)
            .cache_path(tmp.path())
            .network_config(NetworkConfig::default())
            .schedule_config(DownloadScheduleConfig::default())
            .build()?;

        assert_eq!(cfg.override_net_params().get("circwindow").unwrap(), &999);

        Ok(())
    }
}
