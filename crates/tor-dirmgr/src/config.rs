//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client`: any changes
//! here must be reflected in the version of `arti-client`.

use crate::Result;
use crate::storage::DynStore;
use tor_dircommon::{
    authority::AuthorityContacts,
    config::{DirTolerance, DownloadScheduleConfig, NetworkConfig},
};
use tor_netdoc::doc::netstatus::{self};

use std::path::PathBuf;

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
    pub fn authorities(&self) -> &AuthorityContacts {
        self.network.authorities()
    }

    /// Return the configured set of fallback directories
    pub fn fallbacks(&self) -> &tor_dircommon::fallback::FallbackList {
        self.network.fallback_caches()
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
            network: new_config.network.clone(),
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
    #![allow(clippy::unchecked_time_subtraction)]
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

        assert!(dir.authorities().v3idents().len() >= 3);
        assert!(dir.fallbacks().len() >= 3);

        // TODO: verify other defaults.

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
