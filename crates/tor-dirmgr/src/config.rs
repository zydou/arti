//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client`: any changes
//! here must be reflected in the version of `arti-client`.

use crate::retry::DownloadSchedule;
use crate::storage::DynStore;
use crate::{Authority, Result};
use tor_config::ConfigBuildError;
use tor_netdir::fallback::FallbackDir;
use tor_netdoc::doc::netstatus;

use derive_builder::Builder;
use std::path::PathBuf;

use serde::Deserialize;

/// Configuration information about the Tor network itself; used as
/// part of Arti's configuration.
///
/// This type is immutable once constructed. To make one, use
/// [`NetworkConfigBuilder`], or deserialize it from a string.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information, if
    /// we don't actually have a directory yet.
    ///
    /// (If we do have a cached directory, we use directory caches listed there
    /// instead.)
    ///
    /// This section can be changed in a running Arti client.  Doing so will
    /// affect future download attempts only.
    #[serde(default = "fallbacks::default_fallbacks")]
    #[builder(default = "fallbacks::default_fallbacks()")]
    fallback_caches: Vec<FallbackDir>,

    /// List of directory authorities which we expect to sign consensus
    /// documents.
    ///
    /// (If none are specified, we use a default list of authorities shipped
    /// with Arti.)
    ///
    /// This section cannot be changed in a running Arti client.
    #[serde(default = "crate::authority::default_authorities")]
    #[builder(default = "crate::authority::default_authorities()")]
    authorities: Vec<Authority>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            fallback_caches: fallbacks::default_fallbacks(),
            authorities: crate::authority::default_authorities(),
        }
    }
}

impl From<NetworkConfig> for NetworkConfigBuilder {
    fn from(cfg: NetworkConfig) -> NetworkConfigBuilder {
        let mut builder = NetworkConfigBuilder::default();
        builder
            .fallback_caches(cfg.fallback_caches)
            .authorities(cfg.authorities);
        builder
    }
}

impl NetworkConfig {
    /// Return a new builder to construct a NetworkConfig.
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::default()
    }
    /// Return the configured directory authorities
    pub(crate) fn authorities(&self) -> &[Authority] {
        &self.authorities[..]
    }
    /// Return the configured fallback directories
    pub(crate) fn fallbacks(&self) -> &[FallbackDir] {
        &self.fallback_caches[..]
    }
}

impl NetworkConfigBuilder {
    /// Check that this builder will give a reasonable network.
    fn validate(&self) -> std::result::Result<(), ConfigBuildError> {
        if self.authorities.is_some() && self.fallback_caches.is_none() {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["authorities".to_owned(), "fallbacks".to_owned()],
                problem: "Non-default authorities are use, but the fallback list is not overridden"
                    .to_owned(),
            });
        }

        Ok(())
    }
}

/// Configuration information for how exactly we download documents from the
/// Tor directory caches.
///
/// This type is immutable once constructed. To make one, use
/// [`DownloadScheduleConfigBuilder`], or deserialize it from a string.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct DownloadScheduleConfig {
    /// Top-level configuration for how to retry our initial bootstrap attempt.
    #[serde(default = "default_retry_bootstrap")]
    #[builder(default = "default_retry_bootstrap()")]
    retry_bootstrap: DownloadSchedule,

    /// Configuration for how to retry a consensus download.
    #[serde(default)]
    #[builder(default)]
    retry_consensus: DownloadSchedule,

    /// Configuration for how to retry an authority cert download.
    #[serde(default)]
    #[builder(default)]
    retry_certs: DownloadSchedule,

    /// Configuration for how to retry a microdescriptor download.
    #[serde(default = "default_microdesc_schedule")]
    #[builder(default = "default_microdesc_schedule()")]
    retry_microdescs: DownloadSchedule,
}

/// Default value for retry_bootstrap in DownloadScheduleConfig.
fn default_retry_bootstrap() -> DownloadSchedule {
    DownloadSchedule::new(128, std::time::Duration::new(1, 0), 1)
}

/// Default value for microdesc_bootstrap in DownloadScheduleConfig.
fn default_microdesc_schedule() -> DownloadSchedule {
    DownloadSchedule::new(3, std::time::Duration::new(1, 0), 4)
}

impl Default for DownloadScheduleConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default builder setting didn't work")
    }
}

impl DownloadScheduleConfig {
    /// Return a new builder to make a [`DownloadScheduleConfig`]
    pub fn builder() -> DownloadScheduleConfigBuilder {
        DownloadScheduleConfigBuilder::default()
    }
}

impl From<DownloadScheduleConfig> for DownloadScheduleConfigBuilder {
    fn from(cfg: DownloadScheduleConfig) -> DownloadScheduleConfigBuilder {
        let mut builder = DownloadScheduleConfigBuilder::default();
        builder
            .retry_bootstrap(cfg.retry_bootstrap)
            .retry_consensus(cfg.retry_consensus)
            .retry_certs(cfg.retry_certs)
            .retry_microdescs(cfg.retry_microdescs);
        builder
    }
}

/// Configuration type for network directory operations.
///
/// This type is immutable once constructed.
///
/// To create an object of this type, use [`DirMgrConfigBuilder`], or
/// deserialize it from a string. (Arti generally uses Toml for configuration,
/// but you can use other formats if you prefer.)
///
/// Many members of this type can be replaced with a new configuration on a
/// running Arti client. Those that cannot are documented.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct DirMgrConfig {
    /// Location to use for storing and reading current-format
    /// directory information.
    ///
    /// Cannot be changed on a running Arti client.
    #[builder(setter(into))]
    cache_path: PathBuf,

    /// Configuration information about the network.
    #[builder(default)]
    network_config: NetworkConfig,

    /// Configuration information about when we download things.
    ///
    /// This can be replaced on a running Arti client. Doing so affects _future_
    /// download attempts, but has no effect on attempts that are currently in
    /// progress or being retried.
    ///
    /// (The above is a limitation: we would like it to someday have an effect
    /// on in-progress attempts as well, at least at the top level.  Users
    /// should _not_ assume that the effect of changing this option will always
    /// be delayed.)
    #[builder(default)]
    schedule_config: DownloadScheduleConfig,

    /// A map of network parameters that we're overriding from their settings in
    /// the consensus.
    ///
    /// This can be replaced on a running Arti client.  Doing so will take
    /// effect the next time a consensus is downloaded.
    ///
    /// (The above is a limitation: we would like it to someday take effect
    /// immediately. Users should _not_ assume that the effect of changing this
    /// option will always be delayed.)
    #[builder(default)]
    override_net_params: netstatus::NetParams<i32>,
}

impl DirMgrConfigBuilder {
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
        self.override_net_params
            .get_or_insert_with(netstatus::NetParams::default)
            .set(param, value);
        self
    }
}

impl DirMgrConfig {
    /// Return a new builder to construct a DirMgrConfig.
    pub fn builder() -> DirMgrConfigBuilder {
        DirMgrConfigBuilder::default()
    }

    /// Create a store from this configuration.
    ///
    /// Note that each time this is called, a new store object will be
    /// created: you probably only want to call this once.
    pub(crate) fn open_store(&self, readonly: bool) -> Result<DynStore> {
        Ok(Box::new(crate::storage::SqliteStore::from_path(
            &self.cache_path,
            readonly,
        )?))
    }

    /// Return the configured cache path.
    pub(crate) fn cache_path(&self) -> &std::path::Path {
        self.cache_path.as_ref()
    }

    /// Return a slice of the configured authorities
    pub(crate) fn authorities(&self) -> &[Authority] {
        self.network_config.authorities()
    }

    /// Return the configured set of fallback directories
    pub(crate) fn fallbacks(&self) -> &[FallbackDir] {
        self.network_config.fallbacks()
    }

    /// Return set of configured networkstatus parameter overrides.
    pub(crate) fn override_net_params(&self) -> &netstatus::NetParams<i32> {
        &self.override_net_params
    }

    /// Return the schedule configuration we should use to decide when to
    /// attempt and retry downloads.
    pub(crate) fn schedule(&self) -> &DownloadScheduleConfig {
        &self.schedule_config
    }

    /// Construct a new configuration object where all replaceable fields in
    /// `self` are replaced with those from  `new_config`.
    ///
    /// Any fields which aren't allowed to change at runtime are copied from self.
    pub(crate) fn update_config(&self, new_config: &DirMgrConfig) -> DirMgrConfig {
        DirMgrConfig {
            cache_path: self.cache_path.clone(),
            network_config: NetworkConfig {
                fallback_caches: new_config.network_config.fallback_caches.clone(),
                authorities: self.network_config.authorities.clone(),
            },
            schedule_config: new_config.schedule_config.clone(),
            override_net_params: new_config.override_net_params.clone(),
        }
    }
}

impl DownloadScheduleConfig {
    /// Return configuration for retrying our entire bootstrap
    /// operation at startup.
    pub(crate) fn retry_bootstrap(&self) -> &DownloadSchedule {
        &self.retry_bootstrap
    }

    /// Return configuration for retrying a consensus download.
    pub(crate) fn retry_consensus(&self) -> &DownloadSchedule {
        &self.retry_consensus
    }

    /// Return configuration for retrying an authority certificate download
    pub(crate) fn retry_certs(&self) -> &DownloadSchedule {
        &self.retry_certs
    }

    /// Return configuration for retrying an authority certificate download
    pub(crate) fn retry_microdescs(&self) -> &DownloadSchedule {
        &self.retry_microdescs
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
            let rsa = RsaIdentity::from_hex(rsa).expect("Bad hex in built-in fallback list");
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
    #![allow(clippy::unnecessary_wraps)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn simplest_config() -> Result<()> {
        let tmp = tempdir().unwrap();

        let dir = DirMgrConfigBuilder::default()
            .cache_path(tmp.path().to_path_buf())
            .build()
            .unwrap();

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
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities().len(), dflt.authorities.len());
        assert_eq!(cfg.fallbacks().len(), dflt.fallback_caches.len());

        // with any authorities set, the fallback list _must_ be set
        // or the build fails.
        bld.authorities(vec![
            Authority::builder()
                .name("Hello")
                .v3ident([b'?'; 20].into())
                .build()
                .unwrap(),
            Authority::builder()
                .name("world")
                .v3ident([b'!'; 20].into())
                .build()
                .unwrap(),
        ]);
        assert!(bld.build().is_err());

        bld.fallback_caches(vec![FallbackDir::builder()
            .rsa_identity([b'x'; 20].into())
            .ed_identity([b'y'; 32].into())
            .orport("127.0.0.1:99".parse().unwrap())
            .orport("[::]:99".parse().unwrap())
            .build()
            .unwrap()]);
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities().len(), 2);
        assert_eq!(cfg.fallbacks().len(), 1);

        Ok(())
    }

    #[test]
    fn build_schedule() -> Result<()> {
        use std::time::Duration;
        let mut bld = DownloadScheduleConfig::builder();

        let cfg = bld.build().unwrap();
        assert_eq!(cfg.retry_microdescs().parallelism(), 4);
        assert_eq!(cfg.retry_microdescs().n_attempts(), 3);
        assert_eq!(cfg.retry_bootstrap().n_attempts(), 128);

        bld.retry_consensus(DownloadSchedule::new(7, Duration::new(86400, 0), 1))
            .retry_bootstrap(DownloadSchedule::new(4, Duration::new(3600, 0), 1))
            .retry_certs(DownloadSchedule::new(5, Duration::new(3600, 0), 1))
            .retry_microdescs(DownloadSchedule::new(6, Duration::new(3600, 0), 0));

        let cfg = bld.build().unwrap();
        assert_eq!(cfg.retry_microdescs().parallelism(), 1); // gets clamped
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
            .build()
            .unwrap();

        assert_eq!(cfg.override_net_params().get("circwindow").unwrap(), &999);

        Ok(())
    }
}
