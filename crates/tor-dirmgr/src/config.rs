//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client`: any changes
//! here must be reflected in the version of `arti-client`.

use crate::authority::{Authority, AuthorityBuilder, AuthorityList, AuthorityListBuilder};
use crate::retry::{DownloadSchedule, DownloadScheduleBuilder};
use crate::storage::DynStore;
use crate::Result;
use tor_config::{define_list_builder_accessors, ConfigBuildError};
use tor_guardmgr::fallback::FallbackDirBuilder;
use tor_guardmgr::fallback::FallbackListBuilder;
use tor_netdoc::doc::netstatus;

use derive_builder::Builder;
use serde::Deserialize;
use std::path::PathBuf;

/// Configuration information about the Tor network itself; used as
/// part of Arti's configuration.
///
/// This type is immutable once constructed. To make one, use
/// [`NetworkConfigBuilder`], or deserialize it from a string.
//
// TODO: We should move this type around, since the fallbacks part will no longer be used in
// dirmgr, but only in guardmgr.  Probably this type belongs in `arti-client`.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information, if
    /// we don't actually have a directory yet.
    ///
    /// (If we do have a cached directory, we use directory caches listed there
    /// instead.)
    ///
    /// This section can be changed in a running Arti client.  Doing so will
    /// affect future download attempts only.
    ///
    /// The default is to use a set of compiled-in fallback directories,
    /// whose addresses and public keys are shipped as part of the Arti source code.
    #[serde(default)]
    #[builder(sub_builder, setter(custom))]
    pub(crate) fallback_caches: tor_guardmgr::fallback::FallbackList,

    /// List of directory authorities which we expect to sign consensus
    /// documents.
    ///
    /// (If none are specified, we use a default list of authorities shipped
    /// with Arti.)
    ///
    /// This section cannot be changed in a running Arti client.
    ///
    /// The default is to use a set of compiled-in authorities,
    /// whose identities and public keys are shipped as part of the Arti source code.
    #[builder(sub_builder, setter(custom))]
    pub(crate) authorities: AuthorityList,
}

define_list_builder_accessors! {
    struct NetworkConfigBuilder {
        pub fallback_caches: [FallbackDirBuilder],
        pub authorities: [AuthorityBuilder],
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            fallback_caches: FallbackListBuilder::default()
                .build()
                .expect("build default fallbacks"),
            authorities: AuthorityListBuilder::default()
                .build()
                .expect("unable to construct built-in authorities!?"),
        }
    }
}

impl NetworkConfig {
    /// Return a new builder to construct a NetworkConfig.
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::default()
    }

    /// Return the list of fallback directory caches from this configuration.
    pub fn fallback_caches(&self) -> &tor_guardmgr::fallback::FallbackList {
        &self.fallback_caches
    }
}

impl NetworkConfigBuilder {
    /// Check that this builder will give a reasonable network.
    fn validate(&self) -> std::result::Result<(), ConfigBuildError> {
        if self.opt_authorities().is_some() && self.opt_fallback_caches().is_none() {
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
#[builder(derive(Deserialize))]
pub struct DownloadScheduleConfig {
    /// Top-level configuration for how to retry our initial bootstrap attempt.
    #[builder(
        sub_builder,
        field(build = "self.retry_bootstrap.build_retry_bootstrap()?")
    )]
    #[builder_field_attr(serde(default))]
    pub(crate) retry_bootstrap: DownloadSchedule,

    /// Configuration for how to retry a consensus download.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) retry_consensus: DownloadSchedule,

    /// Configuration for how to retry an authority cert download.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) retry_certs: DownloadSchedule,

    /// Configuration for how to retry a microdescriptor download.
    #[builder(
        sub_builder,
        field(build = "self.retry_microdescs.build_retry_microdescs()?")
    )]
    #[builder_field_attr(serde(default))]
    pub(crate) retry_microdescs: DownloadSchedule,
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

/// Configuration type for network directory operations.
///
/// If the directory manager gains new configurabilities, this structure will gain additional
/// supertraits, as an API break.
///
/// Prefer to use `TorClientConfig`, which will always be convertible to this struct
/// via `TryInto`.
//
// We do not use a builder here.  Instead, additions or changes here are API breaks.
//
// Rationale:
//
// The purpose of using a builder is to allow the code to continue to
// compile when new fields are added to the built struct.
//
// However, here, the DirMgrConfig is just a subset of the fields of a
// TorClientConfig, and it is important that all its fields are
// initialised by arti-client.
//
// If it grows a field, arti-client ought not to compile any more.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Default))]
#[allow(clippy::exhaustive_structs)]
pub struct DirMgrConfig {
    /// Location to use for storing and reading current-format
    /// directory information.
    ///
    /// Cannot be changed on a running Arti client.
    pub cache_path: PathBuf,

    /// Configuration information about the network.
    pub network: NetworkConfig,

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
    pub schedule: DownloadScheduleConfig,

    /// A map of network parameters that we're overriding from their settings in
    /// the consensus.
    ///
    /// This can be replaced on a running Arti client.  Doing so will take
    /// effect the next time a consensus is downloaded.
    ///
    /// (The above is a limitation: we would like it to someday take effect
    /// immediately. Users should _not_ assume that the effect of changing this
    /// option will always be delayed.)
    pub override_net_params: netstatus::NetParams<i32>,

    /// Extra fields for extension purposes.
    ///
    /// These are kept in a separate type so that the type can be marked as
    /// `non_exhaustive` and used for optional features.
    pub extensions: DirMgrExtensions,
}

impl DirMgrConfig {
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

    /// Return a slice of the configured authorities
    pub fn authorities(&self) -> &[Authority] {
        &self.network.authorities
    }

    /// Return the configured set of fallback directories
    pub fn fallbacks(&self) -> &tor_guardmgr::fallback::FallbackList {
        &self.network.fallback_caches
    }

    /// Construct a new configuration object where all replaceable fields in
    /// `self` are replaced with those from  `new_config`.
    ///
    /// Any fields which aren't allowed to change at runtime are copied from self.
    pub(crate) fn update_from_config(&self, new_config: &DirMgrConfig) -> DirMgrConfig {
        DirMgrConfig {
            cache_path: self.cache_path.clone(),
            network: NetworkConfig {
                fallback_caches: new_config.network.fallback_caches.clone(),
                authorities: self.network.authorities.clone(),
            },
            schedule: new_config.schedule.clone(),
            override_net_params: new_config.override_net_params.clone(),
            extensions: new_config.extensions.clone(),
        }
    }

    /// Construct a new configuration object where all replaceable fields in
    /// `self` are replaced with those from  `new_config`.
    ///
    /// Any fields which aren't allowed to change at runtime are copied from self.
    #[cfg(feature = "experimental-api")]
    pub fn update_config(&self, new_config: &DirMgrConfig) -> DirMgrConfig {
        self.update_from_config(new_config)
    }
}

/// Optional extensions for configuring
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DirMgrExtensions {
    /// A filter to be used when installing new directory objects.
    #[cfg(feature = "dirfilter")]
    pub filter: crate::filter::FilterConfig,
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

        let dir = DirMgrConfig {
            cache_path: tmp.path().into(),
            ..Default::default()
        };

        assert!(dir.authorities().len() >= 3);
        assert!(dir.fallbacks().len() >= 3);

        // TODO: verify other defaults.

        Ok(())
    }

    #[test]
    fn build_network() -> Result<()> {
        use tor_guardmgr::fallback::FallbackDir;

        let dflt = NetworkConfig::default();

        // with nothing set, we get the default.
        let mut bld = NetworkConfig::builder();
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities.len(), dflt.authorities.len());
        assert_eq!(cfg.fallback_caches.len(), dflt.fallback_caches.len());

        // with any authorities set, the fallback list _must_ be set
        // or the build fails.
        bld.set_authorities(vec![
            Authority::builder()
                .name("Hello")
                .v3ident([b'?'; 20].into())
                .clone(),
            Authority::builder()
                .name("world")
                .v3ident([b'!'; 20].into())
                .clone(),
        ]);
        assert!(bld.build().is_err());

        bld.set_fallback_caches(vec![FallbackDir::builder()
            .rsa_identity([b'x'; 20].into())
            .ed_identity([b'y'; 32].into())
            .orport("127.0.0.1:99".parse().unwrap())
            .orport("[::]:99".parse().unwrap())
            .clone()]);
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities.len(), 2);
        assert_eq!(cfg.fallback_caches.len(), 1);

        Ok(())
    }

    #[test]
    fn build_schedule() -> Result<()> {
        use std::time::Duration;
        let mut bld = DownloadScheduleConfig::builder();

        let cfg = bld.build().unwrap();
        assert_eq!(cfg.retry_microdescs.parallelism(), 4);
        assert_eq!(cfg.retry_microdescs.n_attempts(), 3);
        assert_eq!(cfg.retry_bootstrap.n_attempts(), 128);

        bld.retry_consensus().attempts(7);
        bld.retry_consensus().initial_delay(Duration::new(86400, 0));
        bld.retry_consensus().parallelism(1);
        bld.retry_bootstrap().attempts(4);
        bld.retry_bootstrap().initial_delay(Duration::new(3600, 0));
        bld.retry_bootstrap().parallelism(1);

        bld.retry_certs().attempts(5);
        bld.retry_certs().initial_delay(Duration::new(3600, 0));
        bld.retry_certs().parallelism(1);
        bld.retry_microdescs().attempts(6);
        bld.retry_microdescs().initial_delay(Duration::new(3600, 0));
        bld.retry_microdescs().parallelism(1);

        let cfg = bld.build().unwrap();
        assert_eq!(cfg.retry_microdescs.parallelism(), 1);
        assert_eq!(cfg.retry_microdescs.n_attempts(), 6);
        assert_eq!(cfg.retry_bootstrap.n_attempts(), 4);
        assert_eq!(cfg.retry_consensus.n_attempts(), 7);
        assert_eq!(cfg.retry_certs.n_attempts(), 5);

        Ok(())
    }

    #[test]
    fn build_dirmgrcfg() -> Result<()> {
        let mut bld = DirMgrConfig::default();
        let tmp = tempdir().unwrap();

        bld.override_net_params.set("circwindow".into(), 999);
        bld.cache_path = tmp.path().into();

        assert_eq!(bld.override_net_params.get("circwindow").unwrap(), &999);

        Ok(())
    }
}
