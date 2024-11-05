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
use tor_checkable::timed::TimerangeBound;
use tor_config::{define_list_builder_accessors, impl_standard_builder, ConfigBuildError};
use tor_guardmgr::fallback::FallbackDirBuilder;
use tor_netdoc::doc::netstatus::{self, Lifetime};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration information about the Tor network itself; used as
/// part of Arti's configuration.
///
/// This type is immutable once constructed. To make one, use
/// [`NetworkConfigBuilder`], or deserialize it from a string.
//
// TODO: We should move this type around, since the fallbacks part will no longer be used in
// dirmgr, but only in guardmgr.  Probably this type belongs in `arti-client`.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
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

impl_standard_builder! { NetworkConfig }

define_list_builder_accessors! {
    struct NetworkConfigBuilder {
        pub fallback_caches: [FallbackDirBuilder],
        pub authorities: [AuthorityBuilder],
    }
}

impl NetworkConfig {
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
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
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

impl_standard_builder! { DownloadScheduleConfig }

/// Configuration for how much much to extend the official tolerances of our
/// directory information.
///
/// Because of possible clock skew, and because we want to tolerate possible
/// failures of the directory authorities to reach a consensus, we want to
/// consider a directory to be valid for a while before and after its official
/// range of validity.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct DirTolerance {
    /// For how long before a directory document is valid should we accept it?
    ///
    /// Having a nonzero value here allows us to tolerate a little clock skew.
    ///
    /// Defaults to 1 day.
    #[builder(default = "Duration::from_secs(24 * 60 * 60)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) pre_valid_tolerance: Duration,

    /// For how long after a directory document is valid should we consider it
    /// usable?
    ///
    /// Having a nonzero value here allows us to tolerate a little clock skew,
    /// and makes us more robust to temporary failures for the directory
    /// authorities to reach consensus.
    ///
    /// Defaults to 3 days (per [prop212]).
    ///
    /// [prop212]:
    ///     https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/212-using-old-consensus.txt
    #[builder(default = "Duration::from_secs(3 * 24 * 60 * 60)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) post_valid_tolerance: Duration,
}

impl_standard_builder! { DirTolerance }

impl DirTolerance {
    /// Return a new [`TimerangeBound`] that extends the validity interval of
    /// `timebound` according to this configuration.
    pub(crate) fn extend_tolerance<B>(&self, timebound: TimerangeBound<B>) -> TimerangeBound<B> {
        timebound
            .extend_tolerance(self.post_valid_tolerance)
            .extend_pre_tolerance(self.pre_valid_tolerance)
    }

    /// Return a new consensus [`Lifetime`] that extends the validity intervals
    /// of `lifetime` according to this configuration.
    pub(crate) fn extend_lifetime(&self, lifetime: &Lifetime) -> Lifetime {
        Lifetime::new(
            lifetime.valid_after() - self.pre_valid_tolerance,
            lifetime.fresh_until(),
            lifetime.valid_until() + self.post_valid_tolerance,
        )
        .expect("Logic error when constructing lifetime")
    }
}

/// Configuration type for network directory operations.
///
/// If the directory manager gains new configurabilities, this structure will gain additional
/// supertraits, as an API break.
///
/// Prefer to use `TorClientConfig`, which can be converted to this struct via
/// the `dir_mgr_config` method.
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
// initialized by arti-client.
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
    pub cache_dir: PathBuf,

    /// Rules for whether to trust the permissions on the cache_path.
    pub cache_trust: fs_mistrust::Mistrust,

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

    /// How much skew do we tolerate in directory validity times?
    pub tolerance: DirTolerance,

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
        Ok(Box::new(
            crate::storage::SqliteStore::from_path_and_mistrust(
                &self.cache_dir,
                &self.cache_trust,
                readonly,
            )?,
        ))
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
        // NOTE: keep this in sync with the behaviour of `DirMgr::reconfigure`
        DirMgrConfig {
            cache_dir: self.cache_dir.clone(),
            cache_trust: self.cache_trust.clone(),
            network: NetworkConfig {
                fallback_caches: new_config.network.fallback_caches.clone(),
                authorities: self.network.authorities.clone(),
            },
            schedule: new_config.schedule.clone(),
            tolerance: new_config.tolerance.clone(),
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
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::unnecessary_wraps)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn simplest_config() -> Result<()> {
        let tmp = tempdir().unwrap();

        let dir = DirMgrConfig {
            cache_dir: tmp.path().into(),
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

        bld.set_fallback_caches(vec![{
            let mut bld = FallbackDir::builder();
            bld.rsa_identity([b'x'; 20].into())
                .ed_identity([b'y'; 32].into());
            bld.orports().push("127.0.0.1:99".parse().unwrap());
            bld.orports().push("[::]:99".parse().unwrap());
            bld
        }]);
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
        bld.cache_dir = tmp.path().into();

        assert_eq!(bld.override_net_params.get("circwindow").unwrap(), &999);

        Ok(())
    }
}
